//! Deployment CLI. The gateway owns keys/grants; transport commands read a
//! private, atomically replaceable grant file so credentials never enter argv.
use std::{env, path::Path, time::Duration};
use tokio::{net::TcpListener, signal};
use tokio_util::sync::CancellationToken;
use trusted_router_transport::{
    control::{enroll_node, Gateway, NodeCredential},
    edge,
    grants::{self, Grant, Verifier},
    relay::Relay,
    sync::ControlClient,
};

fn file(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 || meta.len() > 16384 {
        return Err("expected a bounded private regular file".into());
    }
    Ok(std::fs::read(path)?)
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("trusted-data-router: operation failed");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("relay") if args.len() == 5 => {
            // relay LISTEN DATABASE PUBLIC_KEY_PEM ISSUER
            let verifier = Verifier::from_file(Path::new(&args[3]).to_path_buf(), args[4].clone())?;
            let database = Path::new(&args[2]);
            let parent = database.parent().ok_or("missing private state directory")?;
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(parent)?.permissions().mode() & 0o077 != 0 {
                return Err("state directory must be private".into());
            }
            let origins: Vec<String> = env::var("TRUSTED_ROUTER_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_owned())
                .collect();
            let relay = Relay::new(verifier, database)?;
            let client = ControlClient::from_env()?;
            if client.is_none() && relay.requires_control()? {
                return Err("persisted managed relay requires Fleet control configuration".into());
            }
            let listener = TcpListener::bind(&args[1]).await?;
            if let Some(client) = client {
                relay.bind_control(&client)?;
                tokio::select! {
                    result = relay.clone().serve_with_origins(listener, &origins) => result?,
                    _ = client.run(relay) => return Err("control synchronization stopped".into()),
                }
            } else {
                relay.serve_with_origins(listener, &origins).await?;
            }
        }
        Some("gateway") if args.len() == 2 => {
            // Standalone control service, or embed Gateway::router in a backend.
            let listener = TcpListener::bind(&args[1]).await?;
            if !listener.local_addr()?.ip().is_loopback() {
                return Err("use a TLS proxy".into());
            }
            let gateway = Gateway::from_env()?.ok_or("missing gateway configuration")?;
            axum::serve(listener, gateway.router()).await?;
        }
        Some("connect" | "forward") if args.len() == 4 => {
            // connect|forward URL TARGET_OR_LISTEN GRANT_FILE
            let stop = CancellationToken::new();
            let shutdown = stop.clone();
            tokio::spawn(async move {
                let mut term =
                    signal::unix::signal(signal::unix::SignalKind::terminate()).expect("signal");
                tokio::select! { _ = signal::ctrl_c() => {}, _ = term.recv() => {} }
                shutdown.cancel();
            });
            if args[0] == "forward" {
                edge::forward(
                    TcpListener::bind(&args[2]).await?,
                    args[1].clone(),
                    String::from_utf8(file(&args[3])?)?.trim().into(),
                    stop,
                )
                .await?;
            } else {
                let mut backoff = 1;
                loop {
                    let token = String::from_utf8(file(&args[3])?)?;
                    let start = std::time::Instant::now();
                    let attempt =
                        edge::connect(&args[1], token.trim(), args[2].parse()?, stop.clone());
                    tokio::select! { _ = stop.cancelled() => break, _ = attempt => {} }
                    if start.elapsed() > Duration::from_secs(30) {
                        backoff = 1;
                    }
                    tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(Duration::from_secs(backoff)) => {} }
                    backoff = (backoff * 2).min(30);
                }
            }
        }
        Some("sign" | "enroll-node") if args.len() == 2 => {
            // sign PRIVATE_KEY_PEM; bounded Grant JSON on stdin, JWT on stdout.
            use std::io::Read;
            let mut input = Vec::new();
            std::io::stdin().take(16385).read_to_end(&mut input)?;
            if input.len() > 16384 {
                return Err("grant too large".into());
            }
            let key = file(&args[1])?;
            let token = if args[0] == "sign" {
                grants::sign(&key, &serde_json::from_slice::<Grant>(&input)?)?
            } else {
                enroll_node(&key, &serde_json::from_slice::<NodeCredential>(&input)?)?
            };
            println!("{token}");
        }
        _ => return Err("usage: relay|gateway|connect|forward|sign|enroll-node".into()),
    }
    Ok(())
}
