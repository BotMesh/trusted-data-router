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

#[test]
fn revocation_compaction_cannot_weaken_scope_or_reset_history() {
    use trusted_router_transport::authorization::{AuthorizationState, SubjectRevocation};
    let session = SubjectRevocation {
        namespace: "ab".repeat(16),
        principal: "12".repeat(32),
        session: Some("34".repeat(32)),
        application_only: Some(true),
        expires_at: None,
    };
    let old = AuthorizationState {
        revision: 1,
        policies: vec![],
        revoked_subjects: vec![session.clone()],
        retired_policy_version: None,
    };
    let mut user = session.clone();
    user.session = None;
    let mut compacted = AuthorizationState {
        revision: 2,
        revoked_subjects: vec![user.clone()],
        ..old.clone()
    };
    compacted.validate(Some(&old)).unwrap();
    // Legacy all-service scope (absent/false) is wider than application-only.
    for application_only in [None, Some(false)] {
        compacted.revoked_subjects[0].application_only = application_only;
        compacted.validate(Some(&old)).unwrap();
        let mut narrowed = compacted.clone();
        narrowed.revision += 1;
        narrowed.revoked_subjects[0].application_only = Some(true);
        assert!(narrowed.validate(Some(&compacted)).is_err());
    }
    compacted.revoked_subjects = vec![user];
    let mut changed = compacted.clone();
    changed.revision = old.revision;
    assert!(changed.validate(Some(&old)).is_err());
    changed = old.clone();
    changed.revision = 3;
    assert!(changed.validate(Some(&compacted)).is_err()); // user -> one session
    changed.revoked_subjects[0].session = Some("56".repeat(32));
    assert!(changed.validate(Some(&old)).is_err()); // replacing a different session
    for field in ["namespace", "principal"] {
        let mut replacement = serde_json::to_value(&session).unwrap();
        replacement[field] = json!(if field == "namespace" {
            "cd".repeat(16)
        } else {
            "56".repeat(32)
        });
        changed = old.clone();
        changed.revision = 3;
        changed.revoked_subjects = vec![serde_json::from_value(replacement).unwrap()];
        assert!(changed.validate(Some(&old)).is_err());
    }
    changed.revoked_subjects.clear();
    assert!(changed.validate(Some(&compacted)).is_err());
}
#[test]
fn expiring_delegate_denials_leave_only_after_this_relays_clock_passes_them() {
    use trusted_router_transport::authorization::{
        AuthorizationState, SubjectRevocation, MAX_EXPIRING_REVOCATIONS, MAX_PERMANENT_RECORDS,
    };
    let now = 1_000_000;
    let denial = |session: usize, expires_at: Option<u64>| SubjectRevocation {
        namespace: "ab".repeat(16),
        principal: "12".repeat(32),
        session: Some(format!("{session:064x}")),
        application_only: Some(true),
        expires_at,
    };
    let state = |revision, revoked_subjects| AuthorizationState {
        revision,
        policies: vec![],
        revoked_subjects,
        retired_policy_version: None,
    };
    let old = state(1, vec![denial(1, Some(now + 10)), denial(2, None)]);
    old.validate_at(None, now).unwrap();
    // Not before its time on this relay, and a permanent denial never.
    let dropped = state(2, vec![denial(2, None)]);
    assert!(dropped.validate_at(Some(&old), now + 9).is_err());
    dropped.validate_at(Some(&old), now + 10).unwrap();
    assert!(state(2, vec![denial(1, Some(now + 10))])
        .validate_at(Some(&old), now + 1_000)
        .is_err());
    // Replacement must deny at least as long; expiry never replaces permanence.
    let extended = state(2, vec![denial(1, Some(now + 20)), denial(2, None)]);
    extended.validate_at(Some(&old), now).unwrap();
    let shortened = state(2, vec![denial(1, Some(now + 5)), denial(2, None)]);
    assert!(shortened.validate_at(Some(&old), now).is_err());
    let mut principal = denial(1, Some(now + 20));
    principal.session = None;
    state(2, vec![principal.clone(), denial(2, None)])
        .validate_at(Some(&old), now)
        .unwrap();
    assert!(state(2, vec![principal])
        .validate_at(Some(&old), now)
        .is_err());
    // Only a namespace delegate's denial may expire.
    for application_only in [None, Some(false)] {
        let mut operator = denial(3, Some(now + 10));
        operator.application_only = application_only;
        assert!(state(1, vec![operator]).validate_at(None, now).is_err());
    }
    assert!(state(1, vec![denial(3, Some(0))])
        .validate_at(None, now)
        .is_err());
    // Expiring denials have their own budget beside the permanent one.
    let many: Vec<_> = (0..MAX_EXPIRING_REVOCATIONS)
        .map(|i| denial(i, Some(now + 10)))
        .chain((0..=MAX_PERMANENT_RECORDS).map(|i| {
            let mut permanent = denial(i, None);
            permanent.principal = "34".repeat(32);
            permanent
        }))
        .collect();
    let (fits, extra_permanent) = (&many[..many.len() - 1], many.last().unwrap());
    state(1, fits.to_vec()).validate_at(None, now).unwrap();
    for extra in [
        denial(MAX_EXPIRING_REVOCATIONS, Some(now + 10)),
        extra_permanent.clone(),
    ] {
        let mut over = fits.to_vec();
        over.push(extra);
        assert!(state(1, over).validate_at(None, now).is_err());
    }
}
#[test]
fn a_policy_leaves_only_when_enabled_and_covered_by_a_floor_that_never_decreases() {
    use trusted_router_transport::authorization::{AccessPolicy, AuthorizationState};
    let policy = |workload: &str, version, enabled| AccessPolicy {
        namespace: "ab".repeat(16),
        workload: workload.into(),
        service: "control".into(),
        version,
        sha256: "cd".repeat(32),
        enabled,
    };
    let state = |revision, policies, retired_policy_version| AuthorizationState {
        revision,
        policies,
        revoked_subjects: vec![],
        retired_policy_version,
    };
    let rejects =
        |new: &AuthorizationState, old: &AuthorizationState| new.validate(Some(old)).is_err();
    let old = state(
        1,
        vec![policy("agent", 3, true), policy("other", 1, true)],
        None,
    );
    let kept = vec![policy("other", 1, true)];
    // A removal needs a floor at or above the removed version.
    assert!(rejects(&state(2, kept.clone(), None), &old));
    assert!(rejects(&state(2, kept.clone(), Some(2)), &old));
    let retired = state(2, kept.clone(), Some(3));
    retired.validate(Some(&old)).unwrap();
    // A floor above a policy that stays leaves that policy valid.
    state(2, old.policies.clone(), Some(9))
        .validate(Some(&old))
        .unwrap();
    // Without a floor a snapshot serializes as it always did.
    assert!(serde_json::to_value(&old)
        .unwrap()
        .get("retired_policy_version")
        .is_none());
    assert_eq!(
        serde_json::to_value(&retired).unwrap()["retired_policy_version"],
        3
    );
    // The floor never decreases.
    assert!(rejects(&state(3, kept.clone(), Some(2)), &retired));
    assert!(rejects(&state(3, kept.clone(), None), &retired));
    // A policy this relay has not seen must be above the floor it holds, whatever its name.
    for (workload, version, accepted) in [
        ("agent", 3, false),
        ("agent", 4, true),
        ("new", 3, false),
        ("new", 4, true),
    ] {
        let mut policies = kept.clone();
        policies.push(policy(workload, version, true));
        assert_eq!(
            state(3, policies, Some(3)).validate(Some(&retired)).is_ok(),
            accepted,
            "{workload} v{version}"
        );
    }
    // A relay that missed the retirement sees the policy created again as a higher version.
    let recreated = state(
        3,
        vec![policy("agent", 4, true), policy("other", 1, true)],
        Some(3),
    );
    recreated.validate(Some(&old)).unwrap();
    // A disabled policy blocks its namespace's default, so no floor removes it. A relay
    // that missed its enabling rejects the removal until the policy is back, higher.
    let denied = state(1, vec![policy("agent", 3, false)], None);
    assert!(rejects(&state(3, vec![], Some(4)), &denied));
    state(4, vec![policy("agent", 5, true)], Some(4))
        .validate(Some(&denied))
        .unwrap();
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
    // Application sessions and operator control have separate revocation scopes.
    let mut control = first.clone();
    control.service.service = "control".into();
    let mut control_rules = rules.clone();
    control_rules.policies[0].service = "control".into();
    assert!(
        !control_rules.allows(&control),
        "control never inherits a wildcard"
    );
    control_rules.policies[0].workload = "app".into();
    control_rules.policies.push(rules.policies[0].clone());
    assert!(control_rules.allows(&control));
    control_rules.revoked_subjects.push(
        serde_json::from_value(json!({
            "namespace":ns,"principal":first.sub,"session":null,"application_only":true
        }))
        .unwrap(),
    );
    assert!(!control_rules.allows(&first));
    assert!(control_rules.allows(&control));
    control_rules.revoked_subjects[0].application_only = None;
    assert!(
        !control_rules.allows(&control),
        "operator revocation covers control"
    );
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
    response.lock().unwrap()["authorization"]["revoked_subjects"] =
        json!([{"namespace":ns,"principal":first.sub,"session":null}]);
    client.poll_once(&relay).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(Ok(_)) = b.next().await {}
    })
    .await
    .unwrap();
    assert!(c.next().await.unwrap().is_ok());
    assert_eq!(ready(&first).send().await.unwrap().status(), 403);
    assert_eq!(ready(&second).send().await.unwrap().status(), 403);
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
