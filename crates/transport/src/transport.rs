//! Byte-stream adapter only. Tungstenite owns WebSocket framing and controls;
//! Yamux owns multiplexing, windows and backpressure; rustls owns client TLS.
use bytes::{Buf, Bytes};
use futures::{Sink, Stream};
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

pub struct WsIo<S> {
    socket: WebSocketStream<S>,
    remaining: Bytes,
}
impl<S> WsIo<S> {
    pub fn new(socket: WebSocketStream<S>) -> Self {
        Self {
            socket,
            remaining: Bytes::new(),
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
            if !this.remaining.is_empty() {
                let n = this.remaining.len().min(buf.remaining());
                buf.put_slice(&this.remaining[..n]);
                this.remaining.advance(n);
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => this.remaining = data,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
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
        let socket = &mut self.get_mut().socket;
        ready!(Pin::new(&mut *socket).poll_ready(cx)).map_err(io::Error::other)?;
        // Bounded frames, independent of the size of an application write.
        let n = buf.len().min(32 * 1024);
        Pin::new(socket)
            .start_send(Message::Binary(Bytes::copy_from_slice(&buf[..n])))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
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
