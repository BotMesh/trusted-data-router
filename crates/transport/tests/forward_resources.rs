//! Resource limits apply only to a dedicated subprocess, never the test runner.
#![cfg(target_os = "linux")]

use futures::{SinkExt, StreamExt};
use std::{fs::File, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};
use tokio_util::sync::CancellationToken;
use trusted_router_transport::edge;

#[test]
fn forward_survives_file_descriptor_exhaustion() {
    const CHILD: &str = "TRUSTED_ROUTER_FD_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "forward_survives_file_descriptor_exhaustion",
                "--nocapture"
            ])
            .env(CHILD, "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(10), exercise())
                .await
                .unwrap();
        });
}

async fn echo(stream: &mut TcpStream, bytes: &[u8]) {
    stream.write_all(bytes).await.unwrap();
    let mut response = vec![0; bytes.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, bytes);
}

async fn exercise() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/echo", upstream.local_addr().unwrap());
    let server = tokio::spawn(async move {
        while let Ok((socket, _)) = upstream.accept().await {
            tokio::spawn(async move {
                let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
                while let Some(Ok(message)) = socket.next().await {
                    if message.is_binary() && socket.send(message).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let forward = tokio::spawn(edge::forward(
        listener,
        url,
        "test-grant".into(),
        stop.clone(),
    ));
    let mut established = TcpStream::connect(address).await.unwrap();
    echo(&mut established, b"before").await;
    // Reserve the client's fd before exhausting the process. Connecting this
    // socket queues an accept that cannot allocate a new server-side fd.
    let pending = TcpSocket::new_v4().unwrap();
    let mut original = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut original), 0);
        let reduced = libc::rlimit {
            rlim_cur: original.rlim_cur.min(128),
            ..original
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &reduced), 0);
    }
    let mut files = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(file) => files.push(file),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                break;
            }
        }
    }
    let mut pending = pending.connect(address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !forward.is_finished(),
        "one accept error stopped the forwarder"
    );
    echo(&mut established, b"during-exhaustion").await;
    drop(files);
    unsafe {
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &original), 0);
    }
    echo(&mut pending, b"after-recovery").await;
    echo(&mut established, b"still-the-same-stream").await;
    stop.cancel();
    forward.await.unwrap().unwrap();
    server.abort();
}
