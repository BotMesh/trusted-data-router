//! Helper failure must stop its sessions and be followed by a fresh helper,
//! without ever replacing a live one. Fake helpers model process failure only.
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command, time::Duration};
use trusted_router_transport::{chisel::Broker, grants::Verifier, relay::Relay};

fn relay(dir: &Path) -> std::sync::Arc<Relay> {
    let private = dir.join("key");
    let public = dir.join("key.pub");
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
    let verifier = Verifier::new(&std::fs::read(public).unwrap(), "supervision".into()).unwrap();
    Relay::new(verifier, &dir.join("routes.db")).unwrap()
}

fn helper(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!("#!/bin/sh\nread line\necho '{{\"ok\":true}}'\n{body}\n"),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[tokio::test]
async fn failed_helper_is_restarted() {
    let dir = tempfile::tempdir().unwrap();
    let relay = relay(dir.path());
    let starts = dir.path().join("starts");
    let crashing = helper(
        dir.path(),
        "crashing",
        &format!("echo start >> '{}'\nsleep 0.2\nexit 1", starts.display()),
    );
    let supervisor = relay.clone().supervise_chisel(crashing).await.unwrap();
    let task = tokio::spawn(supervisor);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let count = std::fs::read_to_string(&starts)
                .map(|s| s.lines().count())
                .unwrap_or(0);
            if count >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("each failed helper must be replaced");
    task.abort();
}

#[tokio::test]
async fn initial_helper_failure_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let relay = relay(dir.path());
    let refusing = dir.path().join("refusing");
    std::fs::write(&refusing, "#!/bin/sh\nread line\necho '{\"ok\":false}'\n").unwrap();
    std::fs::set_permissions(&refusing, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(relay.supervise_chisel(refusing).await.is_err());
}

#[tokio::test]
async fn live_helper_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let relay = relay(dir.path());
    let alive = helper(dir.path(), "alive", "sleep 30");
    let first = Broker::start(&alive).await.unwrap();
    let second = Broker::start(&alive).await.unwrap();
    relay.enable_chisel(first.clone()).unwrap();
    assert!(relay.enable_chisel(second.clone()).is_err());
    first.stopped().cancel();
    relay.enable_chisel(second).unwrap();
}
