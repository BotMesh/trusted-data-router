//! Process boundary around upstream Chisel, not a tunnel implementation.
//! The helper receives private JSON on stdin. A dropped client kills its child;
//! losing the server's control channel fails closed instead of reusing stale RPCs.
use crate::{relay::loopback, Error, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{net::SocketAddr, path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

struct Process {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    ok: bool,
    fingerprint: Option<String>,
    address: Option<SocketAddr>,
}

impl Process {
    async fn start(binary: &Path, config: Value) -> Result<(Self, Reply)> {
        if !binary.is_absolute() {
            return Err(Error::InvalidContract);
        }
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Error::Unavailable)?;
        let input = child.stdin.take().ok_or(Error::Unavailable)?;
        let output = BufReader::new(child.stdout.take().ok_or(Error::Unavailable)?);
        let mut process = Self {
            child,
            input,
            output,
        };
        let reply = process.request(config).await?;
        Ok((process, reply))
    }

    async fn request(&mut self, request: Value) -> Result<Reply> {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut line = serde_json::to_vec(&request).map_err(|_| Error::InvalidContract)?;
            if line.len() >= 32767 {
                return Err(Error::InvalidContract);
            }
            line.push(b'\n');
            self.input
                .write_all(&line)
                .await
                .map_err(|_| Error::Unavailable)?;
            let mut response = Vec::new();
            loop {
                let byte = self
                    .output
                    .read_u8()
                    .await
                    .map_err(|_| Error::Unavailable)?;
                if byte == b'\n' {
                    break;
                }
                if response.len() == 4096 {
                    return Err(Error::Unavailable);
                }
                response.push(byte);
            }
            serde_json::from_slice(&response).map_err(|_| Error::Unavailable)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}

struct Request {
    body: Value,
    reply: Option<oneshot::Sender<Result<Reply>>>,
}

/// One helper process hosting isolated upstream SSH domains for each lease.
pub struct Broker {
    requests: mpsc::Sender<Request>,
    stopped: CancellationToken,
}

impl Broker {
    pub async fn start(binary: &Path) -> Result<Arc<Self>> {
        let (mut process, reply) = Process::start(
            binary,
            json!({
                "mode": "broker",
            }),
        )
        .await?;
        if !reply.ok {
            return Err(Error::Unavailable);
        }
        let (requests, mut receive) = mpsc::channel::<Request>(128);
        let stopped = CancellationToken::new();
        let stop = stopped.clone();
        tokio::spawn(async move {
            loop {
                let request = tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = process.child.wait() => break,
                    request = receive.recv() => match request { Some(r) => r, None => break },
                };
                // Finish each exchange even if its caller disconnects. An
                // interrupted exchange must kill the helper, not desync replies.
                let response = tokio::select! {
                    _ = stop.cancelled() => break,
                    response = process.request(request.body) => response,
                };
                let failed = response.is_err();
                if let Some(reply) = request.reply {
                    let result = response.and_then(|r| {
                        if r.ok {
                            Ok(r)
                        } else {
                            Err(Error::InvalidContract)
                        }
                    });
                    let _ = reply.send(result);
                } else if !response.is_ok_and(|r| r.ok) {
                    break;
                }
                if failed {
                    break;
                }
            }
            stop.cancel();
            let _ = process.child.kill().await;
        });
        Ok(Arc::new(Self { requests, stopped }))
    }

    pub fn stopped(&self) -> CancellationToken {
        self.stopped.clone()
    }

    /// Install exactly one literal address, never caller-provided regexes.
    /// The owner must close the corresponding WebSocket before dropping this
    /// lease: upstream DeleteUser alone does not drain an established tunnel.
    pub async fn authorize(self: &Arc<Self>, address: SocketAddr, reverse: bool) -> Result<Lease> {
        loopback(address)?;
        let mut random = [0; 64];
        getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
        let user = hex::encode(&random[..32]);
        let password = hex::encode(&random[32..]);
        let mut lease = Lease {
            server: self.clone(),
            user: user.clone(),
            auth: format!("{user}:{password}"),
            address: "127.0.0.1:0".parse().unwrap(),
            fingerprint: String::new(),
        };
        let (reply, result) = oneshot::channel();
        self.requests.send(Request {
            body: json!({"op": "add", "user": user, "password": password, "address": address.to_string(), "reverse": reverse}),
            reply: Some(reply),
        }).await.map_err(|_| Error::Unavailable)?;
        let reply = result.await.map_err(|_| Error::Unavailable)??;
        lease.address = loopback(reply.address.ok_or(Error::Unavailable)?)?;
        lease.fingerprint = reply
            .fingerprint
            .filter(|s| s.len() == 44)
            .ok_or(Error::Unavailable)?;
        if lease.address.port() == 0 {
            return Err(Error::Unavailable);
        }
        Ok(lease)
    }
}

/// Deliberately has no Debug implementation: SSH credentials are secrets.
pub struct Lease {
    server: Arc<Broker>,
    user: String,
    auth: String,
    pub address: SocketAddr,
    pub fingerprint: String,
}
impl Lease {
    pub fn id(&self) -> &str {
        &self.user
    }
    pub fn auth(&self) -> &str {
        &self.auth
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self
            .server
            .requests
            .try_send(Request {
                body: json!({"op": "remove", "user": self.user}),
                reply: None,
            })
            .is_err()
        {
            // Dropping a lease may never silently retain authority under load.
            self.server.stopped.cancel();
        }
    }
}

/// Upstream client with a single declared mapping and no internal retries.
/// Use HTTPS externally; HTTP is allowed only for numeric loopback tests.
pub struct Client {
    process: Process,
}
pub struct ClientConfig<'a> {
    pub server: &'a str,
    pub token: &'a str,
    pub auth: &'a str,
    pub fingerprint: &'a str,
    pub listen: SocketAddr,
    pub target: SocketAddr,
    pub reverse: bool,
    pub ca: Option<&'a Path>,
}
impl Client {
    pub async fn start(binary: &Path, config: ClientConfig<'_>) -> Result<Self> {
        let (process, reply) = Process::start(
            binary,
            json!({
                "mode": "client", "server": config.server, "token": config.token,
                "auth": config.auth, "fingerprint": config.fingerprint,
                "listen": config.listen.to_string(), "target": config.target.to_string(),
                "reverse": config.reverse, "ca": config.ca.and_then(Path::to_str).unwrap_or(""),
            }),
        )
        .await?;
        if !reply.ok {
            return Err(Error::Unavailable);
        }
        Ok(Self { process })
    }
    pub async fn wait(mut self) -> Result<()> {
        let status = self
            .process
            .child
            .wait()
            .await
            .map_err(|_| Error::Unavailable)?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }
    pub async fn close(mut self) -> Result<()> {
        self.process
            .child
            .kill()
            .await
            .map_err(|_| Error::Unavailable)
    }
}
