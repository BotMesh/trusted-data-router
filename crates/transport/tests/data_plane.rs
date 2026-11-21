use axum::{
    body::Body,
    extract::ws::{Message, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use std::{process::Command, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use trusted_contracts::{ExecutionIdentity, PolicyRef, ServiceId};
use trusted_router_transport::{
    edge,
    grants::{self, Grant, Purpose, Verifier, AUDIENCE},
    relay::Relay,
};

async fn application() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    async fn echo(headers: HeaderMap) -> Response {
        assert!(!headers.contains_key("x-trusted-access"));
        (
            StatusCode::OK,
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("hello")
                .to_owned(),
        )
            .into_response()
    }
    async fn events() -> Response {
        let stream = futures::stream::unfold(0, |i| async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            Some((Ok::<_, std::io::Error>(format!("data: {i}\n\n")), i + 1))
        });
        Response::builder()
            .header("content-type", "text/event-stream")
            .body(Body::from_stream(stream))
            .unwrap()
    }
    async fn ws(upgrade: WebSocketUpgrade) -> Response {
        upgrade.on_upgrade(|mut socket| async move {
            while let Some(Ok(message)) = socket.recv().await {
                if let Message::Text(text) = message {
                    if socket.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
            }
        })
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/echo", get(echo))
                .route("/events", get(events))
                .route("/ws", get(ws)),
        )
        .await
        .unwrap();
    });
    (address, task)
}

#[tokio::test]
async fn outbound_http_sse_websocket_auth_expiry_revocation_and_recovery() {
    tokio::time::timeout(Duration::from_secs(35), acceptance())
        .await
        .unwrap();
}

#[tokio::test]
async fn registration_renewal_preserves_streams_without_extending_access_or_reviving_routes() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let temp = tempfile::tempdir().unwrap();
    let private = temp.path().join("key");
    let public = temp.path().join("pub");
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
    let relay = Relay::new(
        Verifier::new(&std::fs::read(public).unwrap(), "renewal-test".into()).unwrap(),
        &temp.path().join("routes.db"),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let relay_task = tokio::spawn(relay.serve(listener));
    let (app, app_task) = application().await;
    let start = grants::now();
    let register = Grant {
        iss: "renewal-test".into(),
        aud: AUDIENCE.into(),
        sub: "node".into(),
        nbf: start,
        exp: start + 5,
        purpose: Purpose::Register,
        http_request: None,
        access: None,
        execution: ExecutionIdentity {
            namespace: "test".into(),
            workload: "web".into(),
            allocation_id: "a".into(),
            lease_id: "l".into(),
            generation: 1,
            node_id: "node".into(),
        },
        service: ServiceId {
            namespace: "test".into(),
            workload: "web".into(),
            service: "http".into(),
        },
        policy: PolicyRef {
            issuer: "renewal-test".into(),
            policy_id: "policy".into(),
            version: 1,
            sha256: "ab".repeat(32),
        },
    };
    let route = register.route_id();
    let stop = CancellationToken::new();
    let worker_stop = stop.clone();
    let token = grants::sign(&key, &register).unwrap();
    let worker = tokio::spawn(async move {
        edge::connect(
            &format!("ws://{address}/v1/connect/{route}"),
            &token,
            app,
            worker_stop,
        )
        .await
    });
    let route = register.route_id();
    let http = reqwest::Client::new();
    let mut access = register.clone();
    access.purpose = Purpose::Access;
    access.sub = "user".into();
    access.exp = start + 30;
    let token = grants::sign(&key, &access).unwrap();
    for _ in 0..100 {
        if http
            .get(format!("http://{address}/v1/ready/{route}"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut stream = http
        .get(format!("http://{address}/v1/http/{route}/events"))
        .header("x-trusted-access", &token)
        .send()
        .await
        .unwrap()
        .bytes_stream();
    assert!(stream.next().await.unwrap().is_ok());
    let mut ws_request = format!("ws://{address}/v1/http/{route}/ws")
        .into_client_request()
        .unwrap();
    ws_request
        .headers_mut()
        .insert("x-trusted-access", token.parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_request).await.unwrap();
    let renew_url = format!("http://{address}/v1/connect/{route}/renew");
    let mut next = register.clone();
    next.exp = start + 20;
    for invalid in [
        access.clone(),
        {
            let mut g = next.clone();
            g.sub = "other-node".into();
            g
        },
        {
            let mut g = next.clone();
            g.policy.version += 1;
            g
        },
        {
            let mut g = next.clone();
            g.execution.namespace = "other-tenant".into();
            g.service.namespace = "other-tenant".into();
            g
        },
    ] {
        assert!(http
            .post(&renew_url)
            .bearer_auth(grants::sign(&key, &invalid).unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .is_client_error());
    }
    assert_eq!(
        http.post(&renew_url)
            .bearer_auth(grants::sign(&key, &next).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    // Replaying an earlier valid grant cannot shorten the renewed lease.
    assert_eq!(
        http.post(&renew_url)
            .bearer_auth(grants::sign(&key, &register).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let mut short = access.clone();
    short.exp = start + 3;
    let mut short_stream = http
        .get(format!("http://{address}/v1/http/{route}/events"))
        .header("x-trusted-access", grants::sign(&key, &short).unwrap())
        .send()
        .await
        .unwrap()
        .bytes_stream();
    let consume =
        tokio::spawn(async move { while matches!(short_stream.next().await, Some(Ok(_))) {} });
    tokio::time::timeout(Duration::from_secs(5), consume)
        .await
        .unwrap()
        .unwrap();
    while grants::now() <= start + 5 {
        assert!(tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .is_ok());
    }
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        "after-renewal".into(),
    ))
    .await
    .unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap().into_text().unwrap(),
        "after-renewal"
    );
    let mut revoke = access;
    revoke.purpose = Purpose::Revoke;
    assert!(http
        .delete(format!("http://{address}/v1/revoke/{route}"))
        .bearer_auth(grants::sign(&key, &revoke).unwrap())
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    assert!(http
        .post(&renew_url)
        .bearer_auth(grants::sign(&key, &next).unwrap())
        .send()
        .await
        .unwrap()
        .status()
        .is_client_error());
    stop.cancel();
    worker.await.unwrap().unwrap();
    relay_task.abort();
    app_task.abort();
}

#[tokio::test]
async fn fleet_sync_revokes_live_streams_and_fails_closed_on_restart_and_outage() {
    tokio::time::timeout(Duration::from_secs(15), managed_acceptance())
        .await
        .unwrap();
}

async fn managed_acceptance() {
    use serde_json::{json, Value};
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };
    use trusted_router_transport::sync::ControlClient;
    let temp = tempfile::tempdir().unwrap();
    let key_path = temp.path().join("key");
    let public_path = temp.path().join("public");
    assert!(Command::new("openssl")
        .args(["genpkey", "-algorithm", "ED25519", "-out"])
        .arg(&key_path)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("openssl")
        .arg("pkey")
        .arg("-in")
        .arg(&key_path)
        .args(["-pubout", "-out"])
        .arg(&public_path)
        .status()
        .unwrap()
        .success());
    let key = std::fs::read(&key_path).unwrap();
    let public = std::fs::read(&public_path).unwrap();
    let token_file = temp.path().join("router.token");
    std::fs::write(&token_file, "router-only").unwrap();
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let epoch = "ab".repeat(16);
    let response = Arc::new(Mutex::new(
        json!({"router_id":"relay-a","issuer":"test-gateway","epoch":epoch,
        "from_revision":0,"revision":0,"revoked_routes":[],"lease_seconds":30}),
    ));
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let control = Router::new().route(
        "/routers/relay-a/sync",
        axum::routing::post({
            let response = response.clone();
            let requests = requests.clone();
            move |headers: HeaderMap, axum::Json(request): axum::Json<Value>| {
                let response = response.clone();
                let requests = requests.clone();
                async move {
                    assert_eq!(headers["authorization"], "Bearer router-only");
                    requests.lock().unwrap().push(request);
                    axum::Json(response.lock().unwrap().clone())
                }
            }
        }),
    );
    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_url = format!("http://{}/", control_listener.local_addr().unwrap());
    let control_task = tokio::spawn(async {
        axum::serve(control_listener, control).await.unwrap();
    });
    let client = ControlClient::new(&control_url, "relay-a".into(), token_file.clone()).unwrap();
    assert!(
        ControlClient::new("http://example.com", "relay-a".into(), token_file.clone()).is_err()
    );
    assert!(ControlClient::new(&control_url, "../other".into(), token_file.clone()).is_err());
    let verifier = Verifier::new(&public, "test-gateway".into()).unwrap();
    let database = temp.path().join("relay.db");
    let relay = Relay::new(verifier.clone(), &database).unwrap();
    relay.bind_control(&client).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(relay.clone().serve(listener));
    let (app, app_task) = application().await;
    let grant = Grant {
        iss: "test-gateway".into(),
        aud: AUDIENCE.into(),
        sub: "owner".into(),
        nbf: grants::now(),
        exp: grants::now() + 120,
        purpose: Purpose::Register,
        http_request: None,
        access: None,
        execution: ExecutionIdentity {
            namespace: "film".into(),
            workload: "app".into(),
            allocation_id: "one".into(),
            lease_id: "first".into(),
            generation: 1,
            node_id: "nat-node".into(),
        },
        service: ServiceId {
            namespace: "film".into(),
            workload: "app".into(),
            service: "http".into(),
        },
        policy: PolicyRef {
            issuer: "gateway".into(),
            policy_id: "network".into(),
            version: 1,
            sha256: "ab".repeat(32),
        },
    };
    let http = reqwest::Client::new();
    let signed = |g: &Grant, purpose| {
        grants::sign(
            &key,
            &Grant {
                purpose,
                ..g.clone()
            },
        )
        .unwrap()
    };
    let ready = |g: &Grant| {
        http.get(format!("http://{addr}/v1/ready/{}", g.route_id()))
            .bearer_auth(signed(g, Purpose::Access))
    };
    assert_eq!(ready(&grant).send().await.unwrap().status(), 503);
    client.poll_once(&relay).await.unwrap();
    assert_eq!(
        requests.lock().unwrap()[0],
        json!({"epoch":null,"after_revision":0,"applied_revision":null})
    );
    let stop = CancellationToken::new();
    let start = |g: &Grant| {
        let url = format!("ws://{addr}/v1/connect/{}", g.route_id());
        let token = signed(g, Purpose::Register);
        let stop = stop.clone();
        tokio::spawn(async move { edge::connect(&url, &token, app, stop).await })
    };
    let connector = start(&grant);
    for _ in 0..100 {
        if ready(&grant).send().await.unwrap().status() == 204 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(ready(&grant).send().await.unwrap().status(), 204);
    let mut stream = http
        .get(format!("http://{addr}/v1/http/{}/events", grant.route_id()))
        .header("x-trusted-access", signed(&grant, Purpose::Access))
        .send()
        .await
        .unwrap()
        .bytes_stream();
    assert!(stream.next().await.unwrap().is_ok());
    response.lock().unwrap()["revision"] = json!(1);
    response.lock().unwrap()["revoked_routes"] = json!([grant.route_id()]);
    client.poll_once(&relay).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(Ok(_)) = stream.next().await {}
    })
    .await
    .unwrap();
    assert_ne!(ready(&grant).send().await.unwrap().status(), 204);
    response.lock().unwrap()["from_revision"] = json!(1);
    response.lock().unwrap()["revoked_routes"] = json!([]);
    client.poll_once(&relay).await.unwrap();
    assert_eq!(
        requests.lock().unwrap().last().unwrap()["applied_revision"],
        1
    );
    // Reopening SQLite starts unavailable, preserves all tombstones and refuses
    // authority changes, even if deployment accidentally omits control config.
    let recovered = Relay::new(verifier, &database).unwrap();
    assert!(recovered.requires_control().unwrap());
    recovered.bind_control(&client).unwrap();
    let other = ControlClient::new(&control_url, "relay-b".into(), token_file).unwrap();
    assert!(recovered.bind_control(&other).is_err());
    client.poll_once(&recovered).await.unwrap();
    assert_eq!(
        requests.lock().unwrap().last().unwrap()["after_revision"],
        1
    );
    let recovery_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let recovery_addr = recovery_listener.local_addr().unwrap();
    // Use the embeddable Router API as well: it must enforce the same controls.
    let recovery_task = tokio::spawn(async move {
        axum::serve(recovery_listener, recovered.router())
            .await
            .unwrap();
    });
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            edge::connect(
                &format!("ws://{recovery_addr}/v1/connect/{}", grant.route_id()),
                &signed(&grant, Purpose::Register),
                app,
                CancellationToken::new()
            )
        )
        .await
        .unwrap()
        .is_err(),
        "the persisted tombstone must reject registration after recovery"
    );
    recovery_task.abort();
    // Invalid authority, rollback, gaps and malformed routes never advance the cursor.
    let good = response.lock().unwrap().clone();
    for (field, value) in [
        ("epoch", json!("cd".repeat(16))),
        ("revision", json!(0)),
        ("from_revision", json!(2)),
        ("issuer", json!("other")),
        ("router_id", json!("other")),
        ("lease_seconds", json!(31)),
    ] {
        response.lock().unwrap()[field] = value;
        assert!(client.poll_once(&relay).await.is_err());
        *response.lock().unwrap() = good.clone();
    }
    // A different exact execution can connect, but loses its active SSE and
    // new access when Fleet is unreachable beyond the control lease.
    response.lock().unwrap()["lease_seconds"] = json!(1);
    client.poll_once(&relay).await.unwrap();
    let mut next = grant.clone();
    next.execution.generation = 2;
    next.execution.lease_id = "second".into();
    let next_connector = start(&next);
    for _ in 0..100 {
        if ready(&next).send().await.unwrap().status() == 204 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(ready(&next).send().await.unwrap().status(), 204);
    let mut stream = http
        .get(format!("http://{addr}/v1/http/{}/events", next.route_id()))
        .header("x-trusted-access", signed(&next, Purpose::Access))
        .send()
        .await
        .unwrap()
        .bytes_stream();
    assert!(stream.next().await.unwrap().is_ok());
    control_task.abort();
    assert!(client.poll_once(&relay).await.is_err());
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(Ok(_)) = stream.next().await {}
    })
    .await
    .unwrap();
    assert_eq!(ready(&next).send().await.unwrap().status(), 503);
    stop.cancel();
    connector.abort();
    next_connector.abort();
    task.abort();
    app_task.abort();
}

async fn acceptance() {
    let temp = tempfile::tempdir().unwrap();
    let key_path = temp.path().join("private.pem");
    let pub_path = temp.path().join("public.pem");
    assert!(Command::new("openssl")
        .args(["genpkey", "-algorithm", "ED25519", "-out"])
        .arg(&key_path)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(&key_path)
        .args(["-pubout", "-out"])
        .arg(&pub_path)
        .status()
        .unwrap()
        .success());
    let key = std::fs::read(key_path).unwrap();
    let public = std::fs::read(pub_path).unwrap();
    let grant = Grant {
        iss: "test-gateway".into(),
        aud: AUDIENCE.into(),
        sub: "owner".into(),
        nbf: grants::now(),
        exp: grants::now() + 120,
        purpose: Purpose::Register,
        http_request: None,
        access: None,
        execution: ExecutionIdentity {
            namespace: "film".into(),
            workload: "qwen".into(),
            allocation_id: "qwen-0".into(),
            lease_id: "lease-1".into(),
            generation: 1,
            node_id: "nat-edge".into(),
        },
        service: ServiceId {
            namespace: "film".into(),
            workload: "qwen".into(),
            service: "http".into(),
        },
        policy: PolicyRef {
            issuer: "gateway".into(),
            policy_id: "network".into(),
            version: 1,
            sha256: "ab".repeat(32),
        },
    };
    let token = |purpose| {
        grants::sign(
            &key,
            &Grant {
                purpose,
                ..grant.clone()
            },
        )
        .unwrap()
    };
    let register = token(Purpose::Register);
    let access = token(Purpose::Access);
    let revoke = token(Purpose::Revoke);
    let route = grant.route_id();
    let verifier = Verifier::new(&public, grant.iss.clone()).unwrap();
    assert!(verifier.verify(&register, Purpose::Access).is_err());
    let mut bound = grant.clone();
    bound.purpose = Purpose::Access;
    bound.http_request = Some(trusted_router_transport::grants::HttpRequestBinding {
        id: "ab".repeat(32),
        method: "POST".into(),
        path: "/echo".into(),
        body_sha256: "cd".repeat(32),
    });
    let bound_access = grants::sign(&key, &bound).unwrap();
    assert_eq!(
        verifier
            .verify(&bound_access, Purpose::Access)
            .unwrap()
            .http_request,
        bound.http_request
    );
    bound.purpose = Purpose::Register;
    assert!(grants::sign(&key, &bound).is_err());
    let db = temp.path().join("routes.db");
    let relay = Relay::new(verifier.clone(), &db).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let relay_task = tokio::spawn(relay.serve(listener));
    let (app, app_task) = application().await;
    let http = reqwest::Client::new();
    let ready_url = format!("http://{address}/v1/ready/{route}");
    assert_eq!(http.get(&ready_url).send().await.unwrap().status(), 401);
    assert_eq!(
        http.get(&ready_url)
            .bearer_auth(&bound_access)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    let stop = CancellationToken::new();
    let connector_url = format!("ws://{address}/v1/connect/{route}");
    let connector = tokio::spawn({
        let url = connector_url.clone();
        let token = register.clone();
        let stop = stop.clone();
        async move { edge::connect(&url, &token, app, stop).await }
    });
    let http = reqwest::Client::new();
    let base = format!("http://{address}/v1/http/{route}");
    for _ in 0..100 {
        if http
            .get(format!("{base}/echo"))
            .header("x-trusted-access", &access)
            .send()
            .await
            .unwrap()
            .status()
            == 200
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        http.get(&ready_url)
            .bearer_auth(&bound_access)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        http.get(&ready_url)
            .bearer_auth(&register)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    for (method, path) in [
        (reqwest::Method::GET, "/echo"),
        (reqwest::Method::POST, "/different"),
        (reqwest::Method::POST, "/echo?extra=1"),
    ] {
        assert_eq!(
            http.request(method, format!("{base}{path}"))
                .header("x-trusted-access", &bound_access)
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
    }
    assert_eq!(
        http.get(format!("http://{address}/v1/tunnel/{route}"))
            .bearer_auth(&bound_access)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let response = http
        .get(format!("{base}/echo"))
        .header("x-trusted-access", &access)
        .header("authorization", "Bearer native-app-key")
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "Bearer native-app-key");
    assert_eq!(
        http.get(format!("{base}/echo"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        http.get(format!("{base}/echo"))
            .header("x-trusted-access", &register)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let mut other = grant.clone();
    other.execution.lease_id = "other".into();
    other.purpose = Purpose::Access;
    assert_eq!(
        http.get(format!("{base}/echo"))
            .header("x-trusted-access", grants::sign(&key, &other).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert!(
        edge::connect(&connector_url, &register, app, CancellationToken::new())
            .await
            .is_err()
    );
    // Real SSE: observe multiple chunks before the response ever completes.
    let mut events = http
        .get(format!("{base}/events"))
        .header("x-trusted-access", &access)
        .send()
        .await
        .unwrap()
        .bytes_stream();
    assert!(events
        .next()
        .await
        .unwrap()
        .unwrap()
        .starts_with(b"data: 0"));
    assert!(events
        .next()
        .await
        .unwrap()
        .unwrap()
        .starts_with(b"data: 1"));
    // Plain clients use a local forwarder; no application changes/credentials leak.
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_address = local.local_addr().unwrap();
    let forward_stop = CancellationToken::new();
    let forward = tokio::spawn(edge::forward(
        local,
        format!("ws://{address}/v1/tunnel/{route}"),
        access.clone(),
        forward_stop.clone(),
    ));
    assert_eq!(
        http.get(format!("http://{local_address}/echo"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "hello"
    );
    let (mut websocket, _) = tokio_tungstenite::connect_async(format!("ws://{local_address}/ws"))
        .await
        .unwrap();
    websocket
        .send(tokio_tungstenite::tungstenite::Message::Text("chat".into()))
        .await
        .unwrap();
    assert_eq!(
        websocket
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap(),
        "chat"
    );
    // Direct HTTP proxy also upgrades without buffering or rewriting WS frames.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://{address}/v1/http/{route}/ws")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("x-trusted-access", access.parse().unwrap());
    let (mut direct_ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    direct_ws
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "direct".into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        direct_ws
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap(),
        "direct"
    );
    // Access expiry tears down an already established stream independently of registration.
    let short = grants::sign(
        &key,
        &Grant {
            purpose: Purpose::Access,
            exp: grants::now() + 2,
            ..grant.clone()
        },
    )
    .unwrap();
    let mut short_stream = http
        .get(format!("{base}/events"))
        .header("x-trusted-access", short)
        .send()
        .await
        .unwrap()
        .bytes_stream();
    assert!(short_stream.next().await.unwrap().is_ok());
    tokio::time::timeout(Duration::from_secs(4), async {
        while let Some(Ok(_)) = short_stream.next().await {}
    })
    .await
    .unwrap();
    // A disconnect closes the old streams. Same execution can reconnect; no request is retried.
    stop.cancel();
    connector.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(_)) = events.next().await {}
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stop2 = CancellationToken::new();
    assert_eq!(
        http.get(&ready_url)
            .bearer_auth(&bound_access)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    let connector2 = tokio::spawn({
        let url = connector_url.clone();
        let token = register.clone();
        let stop = stop2.clone();
        async move { edge::connect(&url, &token, app, stop).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        http.get(format!("{base}/echo"))
            .header("x-trusted-access", &access)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let mut revoked_stream = http
        .get(format!("{base}/events"))
        .header("x-trusted-access", &access)
        .send()
        .await
        .unwrap()
        .bytes_stream();
    assert!(revoked_stream.next().await.unwrap().is_ok());
    assert_eq!(
        http.delete(format!("http://{address}/v1/revoke/{route}"))
            .bearer_auth(revoke)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(_)) = revoked_stream.next().await {}
    })
    .await
    .unwrap();
    connector2.await.unwrap().unwrap();
    assert!(
        edge::connect(&connector_url, &register, app, CancellationToken::new())
            .await
            .is_err()
    );
    // Revocation survives relay replacement and does not depend on in-memory sockets.
    relay_task.abort();
    let _ = relay_task.await;
    let restarted = Relay::new(verifier, &db).unwrap();
    let listener = TcpListener::bind(address).await.unwrap();
    let restarted_task = tokio::spawn(restarted.serve(listener));
    assert!(
        edge::connect(&connector_url, &register, app, CancellationToken::new())
            .await
            .is_err()
    );
    // Replacement can use a new generation, but the retired lease stays fenced.
    let mut replacement = grant.clone();
    replacement.execution.generation = 2;
    replacement.execution.lease_id = "lease-2".into();
    let replacement_register = grants::sign(&key, &replacement).unwrap();
    let replacement_url = format!("ws://{address}/v1/connect/{}", replacement.route_id());
    let replacement_stop = CancellationToken::new();
    let replacement_task = tokio::spawn({
        let url = replacement_url.clone();
        let token = replacement_register.clone();
        let stop = replacement_stop.clone();
        async move { edge::connect(&url, &token, app, stop).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut conflicting = replacement.clone();
    conflicting.execution.lease_id = "another-lease-at-generation-2".into();
    assert!(edge::connect(
        &format!("ws://{address}/v1/connect/{}", conflicting.route_id()),
        &grants::sign(&key, &conflicting).unwrap(),
        app,
        CancellationToken::new()
    )
    .await
    .is_err());
    replacement_stop.cancel();
    replacement_task.await.unwrap().unwrap();
    let mut stale = replacement.clone();
    stale.execution.generation = 1;
    stale.execution.lease_id = "different-old-lease".into();
    assert!(edge::connect(
        &format!("ws://{address}/v1/connect/{}", stale.route_id()),
        &grants::sign(&key, &stale).unwrap(),
        app,
        CancellationToken::new()
    )
    .await
    .is_err());
    forward_stop.cancel();
    forward.await.unwrap().unwrap();
    restarted_task.abort();
    app_task.abort();
}
