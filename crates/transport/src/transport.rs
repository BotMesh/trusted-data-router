//! Byte-stream adapter only. Tungstenite owns WebSocket framing and controls;
//! Yamux owns multiplexing, windows and backpressure; rustls owns client TLS.
use bytes::{Buf, Bytes};
use futures::{Sink, Stream};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{ready, Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

pub struct WsIo<S> {
    socket: WebSocketStream<S>,
    remaining: Bytes,
    heartbeat: Option<Heartbeat>,
}
// Yamux RTT probes do not wake idle sockets. Use standard WebSocket controls to
// keep NAT/proxy mappings alive and detect blackholes without application bytes.
const PING_INTERVAL: Duration = Duration::from_secs(15);
const PONG_TIMEOUT: Duration = Duration::from_secs(15);
struct Heartbeat {
    timer: Pin<Box<Sleep>>,
    sequence: u64,
    awaiting: Option<Bytes>,
    queued: bool,
}
impl<S> WsIo<S> {
    pub fn new(socket: WebSocketStream<S>) -> Self {
        Self {
            socket,
            remaining: Bytes::new(),
            heartbeat: None,
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> WsIo<S> {
    fn poll_heartbeat(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        // Lazy initialization preserves construction outside a Tokio runtime.
        let heartbeat = self.heartbeat.get_or_insert_with(|| Heartbeat {
            timer: Box::pin(tokio::time::sleep(PING_INTERVAL)),
            sequence: 0,
            awaiting: None,
            queued: false,
        });
        if heartbeat.timer.as_mut().poll(cx).is_ready() {
            if heartbeat.awaiting.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "websocket pong timeout",
                ));
            }
            heartbeat.sequence = heartbeat.sequence.wrapping_add(1);
            heartbeat.awaiting = Some(Bytes::copy_from_slice(&heartbeat.sequence.to_be_bytes()));
            heartbeat.queued = true;
            heartbeat
                .timer
                .as_mut()
                .reset(Instant::now() + PONG_TIMEOUT);
            // Register the timeout even when this poll can immediately read data.
            let _ = heartbeat.timer.as_mut().poll(cx);
        }
        if heartbeat.queued {
            if let Poll::Ready(result) = Pin::new(&mut self.socket).poll_ready(cx) {
                result.map_err(io::Error::other)?;
                Pin::new(&mut self.socket)
                    .start_send(Message::Ping(
                        heartbeat.awaiting.clone().expect("queued ping"),
                    ))
                    .map_err(io::Error::other)?;
                heartbeat.queued = false;
            }
        }
        if heartbeat.awaiting.is_some() {
            if let Poll::Ready(result) = Pin::new(&mut self.socket).poll_flush(cx) {
                result.map_err(io::Error::other)?;
            }
        }
        // A blocked write must not block reading: peers need receive progress
        // to relieve backpressure. The timer remains armed in either direction.
        Ok(())
    }

    fn pong(&mut self, payload: &Bytes) {
        if let Some(heartbeat) = &mut self.heartbeat {
            if !heartbeat.queued && heartbeat.awaiting.as_ref() == Some(payload) {
                heartbeat.awaiting = None;
                heartbeat
                    .timer
                    .as_mut()
                    .reset(Instant::now() + PING_INTERVAL);
            }
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            this.poll_heartbeat(cx)?;
            if !this.remaining.is_empty() {
                let n = this.remaining.len().min(buf.remaining());
                buf.put_slice(&this.remaining[..n]);
                this.remaining.advance(n);
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => this.remaining = data,
                Some(Ok(Message::Pong(payload))) => this.pong(&payload),
                Some(Ok(Message::Ping(_))) => continue,
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::other("binary websocket required")))
                }
                Some(Err(_)) => return Poll::Ready(Err(io::Error::other("websocket closed"))),
            }
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.poll_heartbeat(cx)?;
        let socket = &mut this.socket;
        ready!(Pin::new(&mut *socket).poll_ready(cx)).map_err(io::Error::other)?;
        // Bounded frames, independent of the size of an application write.
        let n = buf.len().min(32 * 1024);
        Pin::new(socket)
            .start_send(Message::Binary(Bytes::copy_from_slice(&buf[..n])))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.poll_heartbeat(cx)?;
        Pin::new(&mut this.socket)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

pub fn websocket_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(256 * 1024)
        .max_message_size(Some(256 * 1024))
        .max_frame_size(Some(256 * 1024))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_tungstenite::tungstenite::protocol::Role;

    async fn pair() -> (WsIo<DuplexStream>, WebSocketStream<DuplexStream>) {
        let (client, server) = tokio::io::duplex(64);
        let (client, server) = tokio::join!(
            WebSocketStream::from_raw_socket(client, Role::Client, Some(websocket_config())),
            WebSocketStream::from_raw_socket(server, Role::Server, Some(websocket_config())),
        );
        (WsIo::new(client), server)
    }

    #[tokio::test(start_paused = true)]
    async fn idle_ping_pong_preserves_stream_and_never_becomes_application_bytes() {
        let (mut io, mut peer) = pair().await;
        let reader = tokio::spawn(async move {
            let mut data = [0; 4];
            io.read_exact(&mut data).await.unwrap();
            data
        });
        let mut previous = Bytes::new();
        for _ in 0..3 {
            let Message::Ping(payload) = peer.next().await.unwrap().unwrap() else {
                panic!("idle peer must receive a standard WebSocket ping");
            };
            assert_ne!(payload, previous);
            previous = payload;
            peer.flush().await.unwrap(); // Tungstenite supplies the matching pong.
        }
        peer.send(Message::Binary(Bytes::from_static(b"data")))
            .await
            .unwrap();
        assert_eq!(reader.await.unwrap(), *b"data");
    }

    #[tokio::test(start_paused = true)]
    async fn missing_or_wrong_pong_cannot_keep_a_blackholed_transport_alive() {
        for wrong_pong in [false, true] {
            let (mut io, mut peer) = pair().await;
            let reader = tokio::spawn(async move { io.read_u8().await });
            assert!(matches!(
                peer.next().await.unwrap().unwrap(),
                Message::Ping(_)
            ));
            if wrong_pong {
                // A custom Pong replaces Tungstenite's queued automatic reply.
                peer.send(Message::Pong(Bytes::from_static(b"wrong")))
                    .await
                    .unwrap();
            }
            let start = Instant::now();
            let error = reader.await.unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(Instant::now() - start, PONG_TIMEOUT);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_writer_does_not_disable_the_heartbeat_deadline() {
        let (mut io, _peer) = pair().await;
        let start = Instant::now();
        let error = io.write_all(&vec![42; 1024 * 1024]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(Instant::now() - start, PING_INTERVAL + PONG_TIMEOUT);
    }
}
