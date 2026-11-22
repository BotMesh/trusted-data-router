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
    listener: TcpListener,
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
            socket = listener.accept() => {
                let (mut tcp, _) = socket.map_err(|_| Error::Unavailable)?;
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
