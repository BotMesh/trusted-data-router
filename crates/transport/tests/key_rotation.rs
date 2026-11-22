use axum::{body::Body, routing::get, Json, Router};
use futures::StreamExt;
use serde_json::json;
use std::{io::Write, path::Path, process::Command, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use trusted_router_transport::{
    control::Gateway,
    edge,
    grants::{self, Grant, Purpose, Verifier},
    relay::Relay,
};

fn keys(path: &Path, name: &str) -> (Vec<u8>, Vec<u8>) {
    let private = path.join(name);
    let public = path.join(format!("{name}.pub"));
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
    (
        std::fs::read(private).unwrap(),
        std::fs::read(public).unwrap(),
    )
}
fn replace(path: &Path, bytes: &[u8]) {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap()).unwrap();
    file.write_all(bytes).unwrap();
    file.as_file().sync_all().unwrap();
    file.persist(path).unwrap();
}
fn grant() -> Grant {
    serde_json::from_value(json!({
        "iss":"rotate", "aud":grants::AUDIENCE, "sub":"node", "nbf":grants::now(), "exp":grants::now()+60,
        "purpose":"register", "execution":{"namespace":"tenant", "workload":"web", "allocation_id":"web-0", "lease_id":"one", "generation":1,"node_id":"node"},
        "service":{"namespace":"tenant", "workload":"web", "service":"http"},
        "policy":{"issuer":"rotate","policy_id":"p","version":1,"sha256":"ab".repeat(32)}
    })).unwrap()
}

#[tokio::test]
async fn atomic_key_overlap_rotates_live_relay_without_reconnecting_or_extending_streams() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let dir = tempfile::tempdir().unwrap();
        let (old_private, old_public) = keys(dir.path(), "old");
        let (new_private, new_public) = keys(dir.path(), "new");
        let bundle = dir.path().join("trust.pem");
        replace(&bundle, &old_public);
        let verifier = Verifier::from_file(bundle.clone(), "rotate".into()).unwrap();
        let register = grant();
        let route = register.route_id();
        let old_registration = grants::sign(&old_private, &register).unwrap();
        let new_registration = grants::sign(&new_private, &register).unwrap();
        assert!(verifier
            .verify(&new_registration, Purpose::Register)
            .is_err());
        let relay = Relay::new(verifier.clone(), &dir.path().join("routes.db")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay_task = tokio::spawn(relay.serve(listener));
        let app_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app_address = app_listener.local_addr().unwrap();
        let app_task = tokio::spawn(async move {
            axum::serve(
                app_listener,
                Router::new().route(
                    "/events",
                    get(|| async {
                        let body = futures::stream::unfold(0, |n| async move {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            Some((Ok::<_, std::io::Error>(format!("data: {n}\n\n")), n + 1))
                        });
                        axum::response::Response::builder()
                            .header("content-type", "text/event-stream")
                            .body(Body::from_stream(body))
                            .unwrap()
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let stop = CancellationToken::new();
        let worker_stop = stop.clone();
        let connect_route = route.clone();
        let worker = tokio::spawn(async move {
            edge::connect(
                &format!("ws://{address}/v1/connect/{connect_route}"),
                &old_registration,
                app_address,
                worker_stop,
            )
            .await
        });
        let mut access = register.clone();
        access.purpose = Purpose::Access;
        access.sub = "user".into();
        let old_access = grants::sign(&old_private, &access).unwrap();
        let new_access = grants::sign(&new_private, &access).unwrap();
        let http = reqwest::Client::new();
        for _ in 0..100 {
            if http
                .get(format!("http://{address}/v1/ready/{route}"))
                .bearer_auth(&old_access)
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
            .header("x-trusted-access", &old_access)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes_stream();
        assert!(stream.next().await.unwrap().is_ok());
        let overlap = [old_public.as_slice(), new_public.as_slice()].concat();
        replace(&bundle, &overlap);
        assert!(verifier
            .verify(&new_registration, Purpose::Register)
            .is_ok());
        for token in [&old_access, &new_access] {
            assert!(http
                .get(format!("http://{address}/v1/ready/{route}"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status()
                .is_success());
        }
        assert!(http
            .post(format!("http://{address}/v1/connect/{route}/renew"))
            .bearer_auth(new_registration)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        replace(&bundle, &new_public);
        assert!(http
            .get(format!("http://{address}/v1/ready/{route}"))
            .bearer_auth(&old_access)
            .send()
            .await
            .unwrap()
            .status()
            .is_client_error());
        assert!(http
            .get(format!("http://{address}/v1/ready/{route}"))
            .bearer_auth(&new_access)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        // Key retirement governs new admission; already admitted streams retain
        // their original deadline and remain subject to Fleet revocation.
        assert!(stream.next().await.unwrap().is_ok());
        assert!(!worker.is_finished());
        replace(
            &bundle,
            &[
                new_public.as_slice(),
                b"-----BEGIN PUBLIC KEY-----\ntruncated",
            ]
            .concat(),
        );
        assert!(verifier.verify(&new_access, Purpose::Access).is_err());
        replace(&bundle, &new_public);
        assert!(verifier.verify(&new_access, Purpose::Access).is_ok());
        std::fs::remove_file(&bundle).unwrap();
        assert!(verifier.verify(&new_access, Purpose::Access).is_err());
        stop.cancel();
        worker.await.unwrap().unwrap();
        relay_task.abort();
        app_task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn embedded_gateway_reloads_signer_and_rejects_unstaged_or_invalid_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (old_private, old_public) = keys(dir.path(), "old");
    let (new_private, new_public) = keys(dir.path(), "new");
    let private_path = dir.path().join("signing.pem");
    let public_path = dir.path().join("trusted.pem");
    replace(&private_path, &old_private);
    replace(&public_path, &old_public);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let execution = serde_json::to_value(grant().execution).unwrap();
    let fleet = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/apps/web",
                get(move || {
                    let execution = execution.clone();
                    async move {
                        Json(json!({"namespace":"tenant", "name":"web", "disabled":false,
                "runtime_instances":[{"execution":execution,"ready":true,"services":["http"]}]}))
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let gateway = Gateway::new(
        &base,
        "https://relay.example/",
        "rotate".into(),
        &old_private,
        &old_public,
        dir.path().join("unused"),
    )
    .unwrap()
    .with_key_files(private_path.clone(), public_path.clone())
    .unwrap();
    let request = serde_json::from_value(json!({"service":grant().service})).unwrap();
    let old_verifier = Verifier::new(&old_public, "rotate".into()).unwrap();
    let new_verifier = Verifier::new(&new_public, "rotate".into()).unwrap();
    let old = gateway
        .connections("app-reader", &request)
        .await
        .unwrap()
        .remove(0);
    old_verifier.verify(&old.token, Purpose::Access).unwrap();
    replace(&private_path, &new_private); // invalid rollout ordering must fail closed
    assert!(gateway.connections("app-reader", &request).await.is_err());
    replace(
        &public_path,
        &[old_public.as_slice(), new_public.as_slice()].concat(),
    );
    let new = gateway
        .connections("app-reader", &request)
        .await
        .unwrap()
        .remove(0);
    new_verifier.verify(&new.token, Purpose::Access).unwrap();
    assert!(old_verifier.verify(&new.token, Purpose::Access).is_err());
    assert_eq!(old.route_id, new.route_id);
    replace(&private_path, b"corrupt");
    assert!(gateway.connections("app-reader", &request).await.is_err());
    replace(&private_path, &new_private);
    replace(
        &public_path,
        &[new_public.as_slice(), new_public.as_slice()].concat(),
    );
    assert!(gateway.connections("app-reader", &request).await.is_err());
    replace(&public_path, &new_public);
    let mut wrong_issuer = grant();
    wrong_issuer.iss = "different".into();
    assert!(new_verifier
        .verify(
            &grants::sign(&new_private, &wrong_issuer).unwrap(),
            Purpose::Register
        )
        .is_err());
    assert!(Verifier::new(&[new_public.as_slice(); 9].concat(), "rotate".into()).is_err());
    fleet.abort();
}
