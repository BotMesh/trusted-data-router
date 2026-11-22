use axum::{
    body::Body,
    routing::{get, post},
    Json, Router,
};
use futures::StreamExt;
use serde_json::{json, Value};
use std::{
    os::unix::fs::PermissionsExt,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use trusted_contracts::{ExecutionIdentity, PolicyRef, ServiceId};
use trusted_router_transport::{
    authorization::AccessBinding,
    edge,
    grants::{self, Grant, Purpose, Verifier, AUDIENCE},
    relay::Relay,
    sync::ControlClient,
};

async fn listen(router: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (
        addr,
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }),
    )
}
#[tokio::test]
async fn session_user_and_policy_changes_cancel_only_matching_streams_without_restarting_connector()
{
    tokio::time::timeout(Duration::from_secs(15), acceptance())
        .await
        .unwrap();
}
async fn acceptance() {
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
        .arg("pkey")
        .arg("-in")
        .arg(&private)
        .args(["-pubout", "-out"])
        .arg(&public)
        .status()
        .unwrap()
        .success());
    let key = std::fs::read(private).unwrap();
    let pubkey = std::fs::read(public).unwrap();
    let token = tmp.path().join("router.token");
    std::fs::write(&token, "secret").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ns = "ab".repeat(16);
    let digest = "ab".repeat(32);
    let response = Arc::new(Mutex::new(
        json!({"router_id":"relay","issuer":"gateway","epoch":"ab".repeat(16),"from_revision":0,"revision":0,"revoked_routes":[],"lease_seconds":30,
        "authorization":{"revision":1,"policies":[{"namespace":ns,"workload":"*","service":"http","version":1,"sha256":digest,"enabled":true}],"revoked_subjects":[]}}),
    ));
    let acks = Arc::new(Mutex::new(Vec::<Value>::new()));
    let (control, ctask) = listen(Router::new().route(
        "/routers/relay/sync",
        post({
            let response = response.clone();
            let acks = acks.clone();
            move |Json(request): Json<Value>| {
                let response = response.clone();
                let acks = acks.clone();
                async move {
                    acks.lock().unwrap().push(request);
                    Json(response.lock().unwrap().clone())
                }
            }
        }),
    ))
    .await;
    let client = ControlClient::new(&format!("http://{control}/"), "relay".into(), token).unwrap();
    let db = tmp.path().join("relay.db");
    let relay = Relay::new(Verifier::new(&pubkey, "gateway".into()).unwrap(), &db).unwrap();
    relay.bind_control(&client).unwrap();
    client.poll_once(&relay).await.unwrap();
    let (addr, rtask) = listen(relay.clone().router()).await;
    let (app, atask) = listen(Router::new().route(
        "/events",
        get(|| async {
            let stream = futures::stream::unfold(0, |n| async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Some((Ok::<_, std::io::Error>(format!("data: {n}\n\n")), n + 1))
            });
            axum::response::Response::builder()
                .header("content-type", "text/event-stream")
                .body(Body::from_stream(stream))
                .unwrap()
        }),
    ))
    .await;
    let registration = Grant {
        iss: "gateway".into(),
        aud: AUDIENCE.into(),
        sub: "node".into(),
        nbf: grants::now(),
        exp: grants::now() + 120,
        purpose: Purpose::Register,
        http_request: None,
        access: None,
        execution: ExecutionIdentity {
            namespace: ns.clone(),
            workload: "app".into(),
            allocation_id: "one".into(),
            lease_id: "lease".into(),
            generation: 1,
            node_id: "node".into(),
        },
        service: ServiceId {
            namespace: ns.clone(),
            workload: "app".into(),
            service: "http".into(),
        },
        policy: PolicyRef {
            issuer: "gateway".into(),
            policy_id: "registration".into(),
            version: 1,
            sha256: digest.clone(),
        },
    };
    let route = registration.route_id();
    let stop = CancellationToken::new();
    let connector = tokio::spawn({
        let url = format!("ws://{addr}/v1/connect/{route}");
        let token = grants::sign(&key, &registration).unwrap();
        let stop = stop.clone();
        async move { edge::connect(&url, &token, app, stop).await }
    });
    let mut first = registration.clone();
    first.purpose = Purpose::Access;
    first.sub = "11".repeat(32);
    first.access = Some(AccessBinding {
        principal: first.sub.clone(),
        session: "aa".repeat(32),
        policy_version: 1,
        policy_sha256: digest.clone(),
    });
    // Namespace defaults cover newly scheduled workloads, but an exact deny
    // wins even when the wildcard version/hash would otherwise match.
    let mut rules: trusted_router_transport::authorization::AuthorizationState =
        serde_json::from_value(response.lock().unwrap()["authorization"].clone()).unwrap();
    assert!(rules.allows(&first));
    let mut exact = rules.policies[0].clone();
    exact.workload = "app".into();
    exact.enabled = false;
    rules.policies.push(exact);
    assert!(!rules.allows(&first));
    let mut foreign = first.clone();
    foreign.execution.namespace = "cd".repeat(16);
    assert!(!rules.allows(&foreign));
    let mut probe = registration.clone();
    probe.purpose = Purpose::Probe;
    probe.exp = probe.nbf + 30;
    let probe_token = grants::sign(&key, &probe).unwrap();
    let probe_http = reqwest::Client::new();
    // Probe may inspect an identity-managed route, but cannot carry app bytes.
    for path in [
        format!("/v1/http/{route}/events"),
        format!("/v1/tunnel/{route}"),
    ] {
        assert!(probe_http
            .get(format!("http://{addr}{path}"))
            .header("x-trusted-access", &probe_token)
            .bearer_auth(&probe_token)
            .send()
            .await
            .unwrap()
            .status()
            .is_client_error());
    }
    let mut second = first.clone();
    second.access.as_mut().unwrap().session = "bb".repeat(32);
    let mut other = first.clone();
    other.sub = "22".repeat(32);
    other.access.as_mut().unwrap().principal = other.sub.clone();
    let http = reqwest::Client::new();
    let signed = |grant: &Grant| grants::sign(&key, grant).unwrap();
    let ready = |grant: &Grant| {
        http.get(format!("http://{addr}/v1/ready/{route}"))
            .bearer_auth(signed(grant))
    };
    for _ in 0..100 {
        if ready(&first).send().await.unwrap().status() == 204 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(ready(&first).send().await.unwrap().status(), 204);
    assert_eq!(ready(&probe).send().await.unwrap().status(), 204);
    let events = |grant: &Grant| {
        http.get(format!("http://{addr}/v1/http/{route}/events"))
            .header("x-trusted-access", signed(grant))
    };
    let mut a = events(&first).send().await.unwrap().bytes_stream();
    let mut b = events(&second).send().await.unwrap().bytes_stream();
    let mut c = events(&other).send().await.unwrap().bytes_stream();
    assert!(a.next().await.unwrap().is_ok());
    assert!(b.next().await.unwrap().is_ok());
    assert!(c.next().await.unwrap().is_ok());
    response.lock().unwrap()["authorization"]["revision"] = json!(2);
    response.lock().unwrap()["authorization"]["revoked_subjects"] = json!([{"namespace":ns,"principal":first.sub,"session":first.access.as_ref().unwrap().session}]);
    client.poll_once(&relay).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(Ok(_)) = a.next().await {}
    })
    .await
    .unwrap();
    assert!(b.next().await.unwrap().is_ok());
    assert!(c.next().await.unwrap().is_ok());
    assert_eq!(ready(&first).send().await.unwrap().status(), 403);
    response.lock().unwrap()["authorization"]["revision"] = json!(3);
    response.lock().unwrap()["authorization"]["revoked_subjects"]
        .as_array_mut()
        .unwrap()
        .push(json!({"namespace":ns,"principal":first.sub,"session":null}));
    client.poll_once(&relay).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(Ok(_)) = b.next().await {}
    })
    .await
    .unwrap();
    assert!(c.next().await.unwrap().is_ok());
    response.lock().unwrap()["authorization"]["revision"] = json!(4);
    response.lock().unwrap()["authorization"]["policies"][0]["version"] = json!(2);
    response.lock().unwrap()["authorization"]["policies"][0]["sha256"] = json!("cd".repeat(32));
    client.poll_once(&relay).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(Ok(_)) = c.next().await {}
    })
    .await
    .unwrap();
    assert_eq!(ready(&other).send().await.unwrap().status(), 403);
    other.access.as_mut().unwrap().policy_version = 2;
    other.access.as_mut().unwrap().policy_sha256 = "cd".repeat(32);
    assert_eq!(ready(&other).send().await.unwrap().status(), 204);
    assert!(
        !connector.is_finished(),
        "access-policy changes must retain the runtime connector"
    );
    let good = response.lock().unwrap().clone();
    response.lock().unwrap()["authorization"]["revision"] = json!(5);
    response.lock().unwrap()["authorization"]["revoked_subjects"] = json!([]);
    assert!(client.poll_once(&relay).await.is_err());
    *response.lock().unwrap() = good.clone();
    response.lock().unwrap()["authorization"] = Value::Null;
    assert!(client.poll_once(&relay).await.is_err());
    *response.lock().unwrap() = good;
    client.poll_once(&relay).await.unwrap();
    assert_eq!(
        acks.lock().unwrap().last().unwrap()["applied_authorization_revision"],
        4
    );
    let mut legacy = registration.clone();
    legacy.purpose = Purpose::Access;
    assert_eq!(ready(&legacy).send().await.unwrap().status(), 403);
    let recovered = Relay::new(Verifier::new(&pubkey, "gateway".into()).unwrap(), &db).unwrap();
    recovered.bind_control(&client).unwrap();
    client.poll_once(&recovered).await.unwrap();
    assert_eq!(
        acks.lock().unwrap().last().unwrap()["applied_authorization_revision"],
        4
    );
    stop.cancel();
    connector.abort();
    rtask.abort();
    atask.abort();
    ctask.abort();
}
