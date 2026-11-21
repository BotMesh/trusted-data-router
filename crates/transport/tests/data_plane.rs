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
