//! Real upstream processes, not a mock tunnel. CI builds the pinned Go adapter.
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use trusted_router_transport::chisel::{Broker, Client, ClientConfig};

async fn unused() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn application(label: u8) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = connections.join_next(), if !connections.is_empty() => {},
                connection = listener.accept() => {
                    let (mut stream, _) = connection.unwrap();
                    connections.spawn(async move {
                        if stream.write_all(&[label]).await.is_err() { return; }
                        let mut buffer = [0; 8192];
                        loop {
                            match stream.read(&mut buffer).await {
                                Ok(0) => { let _ = stream.write_all(b"EOF").await; break; },
                                Ok(n) => { if stream.write_all(&buffer[..n]).await.is_err() { break; } },
                                Err(_) => break,
                            }
                        }
                    });
                }
            }
        }
    });
    (address, task)
}

async fn connection(address: SocketAddr, label: u8) -> TcpStream {
    // Upstream Ready means SSH configured; its listener may bind shortly after.
    let mut stream = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(stream) = TcpStream::connect(address).await {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), label);
    stream
}

#[tokio::test]
#[ignore = "requires TRUSTED_ROUTER_TUNNEL_BINARY built from tunnel/chisel"]
async fn upstream_process_half_close_isolation_and_cleanup() {
    tokio::time::timeout(Duration::from_secs(50), acceptance())
        .await
        .unwrap();
}

async fn acceptance() {
    let binary = PathBuf::from(
        std::env::var_os("TRUSTED_ROUTER_TUNNEL_BINARY").expect("build the pinned helper first"),
    );
    let server = Broker::start(&binary).await.unwrap();
    let stopped = server.stopped();
    let (app_a, task_a) = application(b'A').await;
    let (app_b, task_b) = application(b'B').await;
    let (route_a, route_b) = (unused().await, unused().await);
    let lease_a = server.authorize(route_a, true).await.unwrap();
    let lease_b = server.authorize(route_b, true).await.unwrap();
    // Even knowing A's public fingerprint cannot authenticate B's credential
    // through A's isolated native SSH server.
    assert!(Client::start(
        &binary,
        ClientConfig {
            server: &format!("http://{}", lease_a.address),
            token: "fixture",
            auth: lease_b.auth(),
            fingerprint: &lease_a.fingerprint,
            listen: route_b,
            target: app_b,
            reverse: true,
            ca: None,
        }
    )
    .await
    .is_err());
    // A second tenant cannot reuse the first lease to bind another address.
    assert!(Client::start(
        &binary,
        ClientConfig {
            server: &format!("http://{}", lease_a.address),
            token: "fixture",
            auth: lease_a.auth(),
            fingerprint: &lease_a.fingerprint,
            listen: route_b,
            target: app_a,
            reverse: true,
            ca: None,
        }
    )
    .await
    .is_err());
    assert!(Client::start(
        &binary,
        ClientConfig {
            server: &format!("http://{}", lease_a.address),
            token: "fixture",
            auth: lease_a.auth(),
            fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            listen: route_a,
            target: app_a,
            reverse: true,
            ca: None,
        }
    )
    .await
    .is_err());
    let client_a = Client::start(
        &binary,
        ClientConfig {
            server: &format!("http://{}", lease_a.address),
            token: "fixture",
            auth: lease_a.auth(),
            fingerprint: &lease_a.fingerprint,
            listen: route_a,
            target: app_a,
            reverse: true,
            ca: None,
        },
    )
    .await
    .unwrap();
    let client_b = Client::start(
        &binary,
        ClientConfig {
            server: &format!("http://{}", lease_b.address),
            token: "fixture",
            auth: lease_b.auth(),
            fingerprint: &lease_b.fingerprint,
            listen: route_b,
            target: app_b,
            reverse: true,
            ca: None,
        },
    )
    .await
    .unwrap();
    // The client-facing hop can also use upstream Chisel, preserving TCP EOF.
    let access = server.authorize(route_a, false).await.unwrap();
    let local = unused().await;
    let forward = Client::start(
        &binary,
        ClientConfig {
            server: &format!("http://{}", access.address),
            token: "fixture",
            auth: access.auth(),
            fingerprint: &access.fingerprint,
            listen: local,
            target: route_a,
            reverse: false,
            ca: None,
        },
    )
    .await
    .unwrap();
    let mut stream = connection(local, b'A').await;
    let payload: Vec<u8> = (0..524288).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = stream.split();
    let ((), received) = tokio::join!(
        async {
            write.write_all(&payload).await.unwrap();
            write.shutdown().await.unwrap();
        },
        async {
            let mut bytes = Vec::new();
            read.read_to_end(&mut bytes).await.unwrap();
            bytes
        }
    );
    assert_eq!(&received[..payload.len()], payload);
    assert_eq!(&received[payload.len()..], b"EOF");
    let mut a = connection(local, b'A').await;
    let mut b = connection(route_b, b'B').await;
    client_a.close().await.unwrap();
    drop(lease_a);
    // Closing one outer SSH transport drains its active streams only.
    let mut remainder = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), a.read_to_end(&mut remainder))
        .await
        .unwrap()
        .unwrap();
    b.write_all(b"still-alive").await.unwrap();
    let mut reply = [0; 11];
    b.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"still-alive");
    drop(forward); // Drop is also a forceful process/lifecycle boundary.
    drop(access);
    // Control failure must kill the shared helper and every remaining stream.
    stopped.cancel();
    let mut remainder = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), b.read_to_end(&mut remainder))
        .await
        .unwrap()
        .unwrap();
    assert!(client_b.wait().await.is_err());
    drop(lease_b);
    drop(server);
    tokio::time::timeout(Duration::from_secs(3), stopped.cancelled())
        .await
        .unwrap();
    task_a.abort();
    task_b.abort();
}

#[tokio::test]
#[ignore = "requires TRUSTED_ROUTER_TUNNEL_BINARY built from tunnel/chisel"]
async fn lease_drop_storm_neither_stops_the_broker_nor_retains_authority() {
    let binary = PathBuf::from(
        std::env::var_os("TRUSTED_ROUTER_TUNNEL_BINARY").expect("build the pinned helper first"),
    );
    let server = Broker::start(&binary).await.unwrap();
    let mut leases = Vec::new();
    for _ in 0..600 {
        leases.push(server.authorize(unused().await, false).await.unwrap());
    }
    let addresses: Vec<_> = leases.iter().map(|l| l.address).collect();
    // Many sessions expiring together, e.g. abandoned enrollments, must not
    // take every tenant's helper down with them.
    drop(leases);
    let survivor = tokio::time::timeout(
        Duration::from_secs(20),
        server.authorize(unused().await, false),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!server.stopped().is_cancelled());
    // Every dropped lease's private SSH server is closed by then: removals
    // are drained before any later authorization.
    for address in addresses {
        assert!(TcpStream::connect(address).await.is_err());
    }
    drop(survivor);
}
