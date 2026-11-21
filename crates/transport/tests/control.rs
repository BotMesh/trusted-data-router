use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    os::unix::fs::PermissionsExt,
    process::Command,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use trusted_router_transport::{
    control::{enroll_node, Gateway, NodeCredential},
    grants::{self, Purpose, Verifier},
    relay::browser_router,
};

async fn listen(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    (
        url,
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }),
    )
}

#[tokio::test]
async fn control_uses_live_fleet_scope_and_binds_node_and_stateful_clients() {
    let tmp = tempfile::tempdir().unwrap();
    let private = tmp.path().join("key");
    let public = tmp.path().join("public");
    assert!(Command::new("openssl")
        .args(["genpkey", "-algorithm", "ED25519", "-out"])
        .arg(&private)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(&private)
        .args(["-pubout", "-out"])
        .arg(&public)
        .status()
        .unwrap()
        .success());
    let key = std::fs::read(private).unwrap();
    let pubkey = std::fs::read(public).unwrap();
    let fleet_token = tmp.path().join("registration-token");
    std::fs::write(&fleet_token, "registration-reader").unwrap();
    std::fs::set_permissions(&fleet_token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let execution = json!({"namespace":"film", "workload":"comfy", "allocation_id":"comfy-0", "lease_id":"first", "generation":1,"node_id":"edge-a"});
    let view = Arc::new(Mutex::new(
        json!({"name":"comfy", "namespace":"film", "disabled":false,
        "runtime_instances":[{"execution":execution,"ready":true,"services":["http", "control"]}]}),
    ));
    async fn app(
        State(view): State<Arc<Mutex<Value>>>,
        headers: HeaderMap,
    ) -> Result<Json<Value>, StatusCode> {
        match headers.get("authorization").and_then(|h| h.to_str().ok()) {
            Some("Bearer film-user" | "Bearer registration-reader" | "Bearer administrator") => {
                Ok(Json(view.lock().unwrap().clone()))
            }
            _ => Err(StatusCode::FORBIDDEN),
        }
    }
    let (fleet, fleet_task) = listen(
        Router::new()
            .route("/access", get(|headers: HeaderMap| async move { Json(json!({"permissions":if headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer administrator") {vec!["admin"]} else {vec!["read"]}})) }))
            .route("/routers/relay/authorize", axum::routing::post(|Json(request): Json<Value>| async move {
                Json(json!({"principal":request["principal"],"session":request["session"],"policy_version":7,"policy_sha256":"ef".repeat(32)}))
            }))
            .route("/apps/comfy", get(app))
            .with_state(view.clone()),
    )
    .await;
    let gateway = Gateway::new(
        &fleet,
        "https://relay.example/",
        "test".into(),
        &key,
        &pubkey,
        fleet_token,
    )
    .unwrap();
    let (base, task) = listen(gateway.clone().router()).await;
    let http = reqwest::Client::new();
    let service = json!({"namespace":"film","workload":"comfy","service":"http"});
    let managed = gateway.with_authorization("relay").unwrap();
    let identity = json!({"principal":"11".repeat(32),"session":"22".repeat(32)});
    let expires_at = grants::now() + 30;
    let scoped = serde_json::from_value(
        json!({"service":service,"identity":identity,"expires_at":expires_at}),
    )
    .unwrap();
    let connections = managed.connections("film-user", &scoped).await.unwrap();
    let scoped_grant = Verifier::new(&pubkey, "test".into())
        .unwrap()
        .verify(&connections[0].token, Purpose::Access)
        .unwrap();
    assert_eq!(scoped_grant.sub, identity["principal"]);
    assert_eq!(scoped_grant.access.unwrap().policy_version, 7);
    assert_eq!(scoped_grant.exp, expires_at);
    assert!(managed
        .connections(
            "film-user",
            &serde_json::from_value(json!({"service":service})).unwrap()
        )
        .await
        .is_err());
    let request = json!({"service":service});
    let control_request =
        json!({"service":{"namespace":"film","workload":"comfy","service":"control"}});
    let managed_control = serde_json::from_value(control_request.clone()).unwrap();
    assert!(managed
        .connections("film-user", &managed_control)
        .await
        .is_err());
    let operator = managed
        .connections("administrator", &managed_control)
        .await
        .unwrap();
    assert!(Verifier::new(&pubkey, "test".into())
        .unwrap()
        .verify(&operator[0].token, Purpose::Access)
        .unwrap()
        .access
        .is_some());
    for (token, expected) in [("film-user", 403), ("administrator", 200)] {
        assert_eq!(
            http.post(format!("{base}v1/runtime/connections"))
                .bearer_auth(token)
                .json(&control_request)
                .send()
                .await
                .unwrap()
                .status(),
            expected
        );
    }

    let binding = json!({"id":"ab".repeat(32),"method":"POST","path":"/v1/chat/completions","body_sha256":"cd".repeat(32)});
    let bound: Value = http
        .post(format!("{base}v1/runtime/connections"))
        .bearer_auth("film-user")
        .json(&json!({"service":service,"http_request":binding}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let verified = Verifier::new(&pubkey, "test".into())
        .unwrap()
        .verify(bound[0]["token"].as_str().unwrap(), Purpose::Access)
        .unwrap();
    assert_eq!(
        serde_json::to_value(verified.http_request.unwrap()).unwrap(),
        binding
    );
    let mut invalid = binding.clone();
    invalid["path"] = json!("/../admin");
    assert_eq!(
        http.post(format!("{base}v1/runtime/connections"))
            .bearer_auth("film-user")
            .json(&json!({"service":service,"http_request":invalid}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );

    let access = || {
        http.post(format!("{base}v1/runtime/connections"))
            .bearer_auth("film-user")
            .json(&request)
    };
    assert_eq!(
        http.post(format!("{base}v1/runtime/connections"))
            .bearer_auth("other-user")
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let connections: Value = access()
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(connections[0]["execution"], execution);
    let verifier = Verifier::new(&pubkey, "test".into()).unwrap();
    let token = connections[0]["token"].as_str().unwrap();
    assert_eq!(
        verifier
            .verify(token, Purpose::Access)
            .unwrap()
            .execution
            .node_id,
        "edge-a"
    );
    assert!(verifier.verify(token, Purpose::Register).is_err());
    let node = |name: &str, namespace: &str| {
        enroll_node(
            &key,
            &NodeCredential {
                iss: "test".into(),
                aud: "trusted-runtime-node/v1".into(),
                sub: name.into(),
                namespaces: vec![namespace.into()],
                nbf: grants::now(),
                exp: grants::now() + 3600,
            },
        )
        .unwrap()
    };
    let registration = json!({"execution":execution,"service":{"id":service,"protocol":"http1","endpoint_ref":"app"}});
    for credential in [
        node("edge-b", "film"),
        node("edge-a", "other"),
        token.into(),
    ] {
        assert_eq!(
            http.post(format!("{base}v1/runtime/registration"))
                .bearer_auth(credential)
                .json(&registration)
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
    }
    let response: Value = http
        .post(format!("{base}v1/runtime/registration"))
        .bearer_auth(node("edge-a", "film"))
        .json(&registration)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let register = verifier
        .verify(response["token"].as_str().unwrap(), Purpose::Register)
        .unwrap();
    assert_eq!(register.route_id(), connections[0]["route_id"]);
    let route = connections[0]["route_id"].clone();
    let renewal = json!({"service":service,"route_id":route});
    assert_eq!(
        http.post(format!("{base}v1/runtime/connections"))
            .bearer_auth("film-user")
            .json(&renewal)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    view.lock().unwrap()["runtime_instances"][0]["execution"]["lease_id"] = json!("replacement");
    assert_eq!(
        http.post(format!("{base}v1/runtime/connections"))
            .bearer_auth("film-user")
            .json(&renewal)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(
        http.post(format!("{base}v1/runtime/registration"))
            .bearer_auth(node("edge-a", "film"))
            .json(&registration)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    view.lock().unwrap()["disabled"] = json!(true);
    assert_eq!(access().send().await.unwrap().status(), 403);
    task.abort();
    fleet_task.abort();
}

#[tokio::test]
async fn browser_preflight_only_allows_configured_origins() {
    let (base, task) = listen(
        browser_router(
            Router::new().route("/example", get(|| async { "ok" })),
            &["https://studio.example".into()],
        )
        .unwrap(),
    )
    .await;
    let http = reqwest::Client::new();
    for origin in ["https://studio.example", "https://attacker.example"] {
        let response = http
            .request(reqwest::Method::OPTIONS, format!("{base}example"))
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "authorization,content-type,x-trusted-access",
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_some(),
            origin == "https://studio.example"
        );
        assert!(!response
            .headers()
            .contains_key("access-control-allow-credentials"));
    }
    assert!(browser_router(Router::new(), &["*".into()]).is_err());
    task.abort();
}
