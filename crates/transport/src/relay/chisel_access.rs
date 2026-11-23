//! A scoped upstream client tunnel feeds a private listener. Every accepted
//! stream still traverses the Router's existing session and access fences.
use super::*;

pub(super) struct ClientSession {
    grant: Grant,
    lease: crate::chisel::Lease,
    access: Arc<AccessGuard>,
    node: Arc<Session>,
    claimed: AtomicBool,
    attached: Notify,
}

struct Registration {
    owner: std::sync::Weak<Relay>,
    client: Arc<ClientSession>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.client.access.cancel.cancel();
        if let Some(relay) = self.owner.upgrade() {
            if let Ok(mut clients) = relay.chisel_access.lock() {
                clients.remove(self.client.lease.id());
            }
        }
    }
}

pub(super) async fn enroll(State(relay): State<Arc<Relay>>, req: Request) -> HttpResult {
    let grant = relay.authenticate(&req, Purpose::Access)?;
    if grant.http_request.is_some() {
        return Err(StatusCode::FORBIDDEN);
    }
    let node = relay.session(&grant)?;
    let access = relay.track_access(&grant, &node)?;
    let broker = relay.chisel_broker()?;
    let stopped = broker.stopped();
    let mut listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let target = listener
        .local_addr()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let lease = broker
        .authorize(target, false)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "lease": lease.id(), "auth": lease.auth(), "fingerprint": lease.fingerprint, "listen": target,
    })).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let client = Arc::new(ClientSession {
        grant,
        lease,
        access,
        node,
        claimed: AtomicBool::new(false),
        attached: Notify::new(),
    });
    {
        let mut clients = relay
            .chisel_access
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if clients.len() >= 4096 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        clients.insert(client.lease.id().to_owned(), client.clone());
    }
    let registered = Registration {
        owner: Arc::downgrade(&relay),
        client: client.clone(),
    };
    tokio::spawn(async move {
        let run = async {
            let wait = async {
                loop {
                    let attached = client.attached.notified();
                    if client.claimed.load(Ordering::Acquire) {
                        break;
                    }
                    attached.await;
                }
            };
            if tokio::time::timeout(Duration::from_secs(20), wait)
                .await
                .is_err()
            {
                return;
            }
            let mut streams = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = streams.join_next(), if !streams.is_empty() => {},
                    (mut downstream, _) = axum::serve::Listener::accept(&mut listener) => {
                        let Ok(slot) = client.node.slots.clone().try_acquire_owned() else { continue; };
                        let node = client.node.clone();
                        streams.spawn(async move {
                            let _slot = slot;
                            if let Ok(mut upstream) = open(&node).await {
                                let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                            }
                        });
                    }
                }
            }
        };
        tokio::select! {
            biased;
            _ = client.access.cancel.cancelled() => {}, _ = expires(client.grant.exp) => {},
            _ = stopped.cancelled() => {}, _ = run => {},
        }
        drop(registered);
    });
    Response::builder()
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub(super) async fn attach(State(relay): State<Arc<Relay>>, mut req: Request) -> HttpResult {
    let grant = relay.authenticate(&req, Purpose::Access)?;
    relay.session(&grant)?; // recheck current Fleet and application authorization
    let id = req
        .uri()
        .path()
        .split('/')
        .nth(5)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let client = relay
        .chisel_access
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .get(id)
        .cloned()
        .ok_or(StatusCode::FORBIDDEN)?;
    if client.grant != grant || client.access.cancel.is_cancelled() {
        return Err(StatusCode::FORBIDDEN);
    }
    if req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        != Some("chisel-v3")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (response, upgraded) = upgrade(&mut req)?;
    if client.claimed.swap(true, Ordering::AcqRel) {
        return Err(StatusCode::CONFLICT);
    }
    client.attached.notify_one();
    chisel::proxy(
        req.headers().clone(),
        response,
        upgraded,
        client.lease.address,
        client.access.cancel.clone(),
        client,
    )
    .await
}
