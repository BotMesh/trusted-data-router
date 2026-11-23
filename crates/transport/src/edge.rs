//! Outbound connector and optional local client forwarder. Neither needs a node
//! inbound port. Reconnect restores connectivity only, never replays requests.
use crate::{
    relay::loopback,
    transport::{websocket_config, WsIo},
    Error, Result,
};
use futures::future::poll_fn;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_util::{
    compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
    sync::CancellationToken,
};

/// Register one upstream Chisel session. The caller owns reconnect and grant
/// renewal; a failed attempt never falls back to a different transport.
pub async fn connect_chisel(
    binary: &std::path::Path,
    url: &str,
    token: &str,
    target: SocketAddr,
    stop: CancellationToken,
) -> Result<()> {
    let run = async {
        let client = start_chisel(binary, url, token, target, true).await?;
        let _ = client.wait().await;
        Ok(())
    };
    tokio::select! { result = run => result, _ = stop.cancelled() => Ok(()) }
}

/// Keep the caller's listener stable across upstream lease renewal. Chisel
/// handles the private TCP-to-SSH/WSS hop; these are ordinary local TCP copies.
pub async fn forward_chisel(
    binary: &std::path::Path,
    mut listener: TcpListener,
    url: String,
    token: String,
    stop: CancellationToken,
) -> Result<()> {
    use std::sync::Arc;
    struct Connected {
        address: SocketAddr,
        cancel: CancellationToken,
    }
    loopback(listener.local_addr().map_err(|_| Error::Unavailable)?)?;
    let (sender, receiver) = tokio::sync::watch::channel(None::<Arc<Connected>>);
    let supervise = async {
        let mut backoff = 1;
        loop {
            let started = std::time::Instant::now();
            let reservation = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|_| Error::Unavailable)?;
            let address = reservation.local_addr().map_err(|_| Error::Unavailable)?;
            drop(reservation);
            if let Ok(client) = start_chisel(binary, &url, &token, address, false).await {
                let connected = Arc::new(Connected {
                    address,
                    cancel: CancellationToken::new(),
                });
                let fence = connected.cancel.clone().drop_guard();
                sender.send_replace(Some(connected.clone()));
                let _ = client.wait().await;
                connected.cancel.cancel();
                sender.send_replace(None);
                drop(fence);
            }
            if started.elapsed() > Duration::from_secs(30) {
                backoff = 1;
            }
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    };
    tokio::pin!(supervise);
    let slots = Arc::new(Semaphore::new(256));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            result = &mut supervise => return result,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            (mut local, _) = axum::serve::Listener::accept(&mut listener) => {
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue; };
                let mut receiver = receiver.clone();
                tasks.spawn(async move {
                    let _slot = slot;
                    let ready = async {
                        loop {
                            let current = receiver.borrow_and_update().clone();
                            if let Some(current) = current { if !current.cancel.is_cancelled() { break Ok::<_, Error>(current); } }
                            receiver.changed().await.map_err(|_| Error::Unavailable)?;
                        }
                    };
                    let Ok(Ok(current)) = tokio::time::timeout(Duration::from_secs(15), ready).await else { return; };
                    let connect = async {
                        // Upstream's SSH Ready can precede its local bind. No
                        // application bytes are sent during connection retries.
                        loop {
                            match TcpStream::connect(current.address).await {
                                Ok(stream) => break stream,
                                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                            }
                        }
                    };
                    let mut upstream = tokio::select! {
                        biased;
                        _ = current.cancel.cancelled() => return,
                        stream = tokio::time::timeout(Duration::from_secs(15), connect) => match stream { Ok(s) => s, Err(_) => return },
                    };
                    tokio::select! {
                        biased;
                        _ = current.cancel.cancelled() => {},
                        _ = tokio::io::copy_bidirectional(&mut local, &mut upstream) => {},
                    }
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn start_chisel(
    binary: &std::path::Path,
    url: &str,
    token: &str,
    target: SocketAddr,
    reverse: bool,
) -> Result<crate::chisel::Client> {
    let target = loopback(target)?;
    let mut endpoint = reqwest::Url::parse(url).map_err(|_| Error::InvalidContract)?;
    if endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || !(endpoint.scheme() == "wss"
            || endpoint.scheme() == "ws"
                && matches!(endpoint.host_str(), Some("127.0.0.1" | "[::1]")))
    {
        return Err(Error::InvalidContract);
    }
    let scheme = if endpoint.scheme() == "wss" {
        "https"
    } else {
        "http"
    };
    endpoint
        .set_scheme(scheme)
        .map_err(|_| Error::InvalidContract)?;
    endpoint.set_path(&format!("{}/chisel", endpoint.path().trim_end_matches('/')));
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| Error::Unavailable)?;
    {
        let mut response = http
            .post(endpoint.clone())
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if bytes.len() + chunk.len() > 16384 {
                return Err(Error::InvalidContract);
            }
            bytes.extend_from_slice(&chunk);
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Offer {
            lease: String,
            auth: String,
            fingerprint: String,
            listen: SocketAddr,
        }
        let offer: Offer = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidContract)?;
        if offer.lease.len() != 64
            || !offer.lease.bytes().all(|b| b.is_ascii_hexdigit())
            || !offer.auth.starts_with(&format!("{}:", offer.lease))
        {
            return Err(Error::InvalidContract);
        }
        endpoint.set_path(&format!("{}/{}", endpoint.path(), offer.lease));
        let client = crate::chisel::Client::start(
            binary,
            crate::chisel::ClientConfig {
                server: endpoint.as_str(),
                token,
                auth: &offer.auth,
                fingerprint: &offer.fingerprint,
                listen: if reverse { offer.listen } else { target },
                target: if reverse { target } else { offer.listen },
                reverse,
                ca: None,
            },
        )
        .await?;
        if reverse {
            endpoint.set_path(&format!("{}/ready", endpoint.path()));
            let response = http
                .post(endpoint)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|_| Error::Unavailable)?;
            if response.status() != reqwest::StatusCode::NO_CONTENT {
                return Err(Error::Unavailable);
            }
        }
        Ok(client)
    }
}

async fn dial(
    url: &str,
    token: &str,
) -> Result<WsIo<tokio_tungstenite::MaybeTlsStream<TcpStream>>> {
    let mut req = url
        .into_client_request()
        .map_err(|_| Error::InvalidContract)?;
    let uri = req.uri();
    if uri.scheme_str() != Some("wss")
        && !(uri.scheme_str() == Some("ws") && matches!(uri.host(), Some("127.0.0.1" | "[::1]")))
    {
        return Err(Error::InvalidContract);
    }
    if token.len() > 8192 || token.is_empty() {
        return Err(Error::InvalidContract);
    }
    let mut header: axum::http::HeaderValue = format!("Bearer {token}")
        .parse()
        .map_err(|_| Error::InvalidContract)?;
    header.set_sensitive(true);
    req.headers_mut().insert("authorization", header);
    let (socket, _) = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_tungstenite::connect_async_with_config(req, Some(websocket_config()), true),
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|_| Error::Unavailable)?;
    Ok(WsIo::new(socket))
}

/// One transport session; caller supervises reconnect using the same allocation.
/// The target is selected by the trusted runtime adapter, never by a user token.
pub async fn connect(
    url: &str,
    token: &str,
    target: SocketAddr,
    stop: CancellationToken,
) -> Result<()> {
    let target = loopback(target)?;
    let io = dial(url, token).await?;
    let mut mux =
        yamux::Connection::new(io.compat(), yamux::Config::default(), yamux::Mode::Client);
    let mut tasks = tokio::task::JoinSet::new();
    let slots = std::sync::Arc::new(Semaphore::new(256));
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            stream = poll_fn(|cx| mux.poll_next_inbound(cx)) => {
                let Some(Ok(stream)) = stream else { break; };
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue; };
                tasks.spawn(async move {
                    let _slot = slot;
                    if let Ok(Ok(mut tcp)) = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(target)).await {
                        let _ = tokio::io::copy_bidirectional(&mut stream.compat(), &mut tcp).await;
                    }
                });
            }
        }
    }
    // JoinSet drop aborts every stream, including streams opened before expiry.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Makes an unmodified HTTP/SSE/WebSocket client work through authenticated WSS.
/// Application Authorization headers and paths remain unchanged inside it.
pub async fn forward(
    mut listener: TcpListener,
    url: String,
    token: String,
    stop: CancellationToken,
) -> Result<()> {
    loopback(listener.local_addr().map_err(|_| Error::Unavailable)?)?;
    let mut tasks = tokio::task::JoinSet::new();
    let slots = std::sync::Arc::new(Semaphore::new(256));
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            // Reuse axum's accept-error handling: retry connection errors and
            // back off on resource exhaustion without dropping active streams.
            (mut tcp, _) = axum::serve::Listener::accept(&mut listener) => {
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue; };
                let (url, token) = (url.clone(), token.clone());
                tasks.spawn(async move {
                    let _slot = slot;
                    if let Ok(mut ws) = dial(&url, &token).await { let _ = tokio::io::copy_bidirectional(&mut tcp, &mut ws).await; }
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
