//! Authenticated lifecycle around opaque, unmodified upstream WebSockets.
use super::*;
use serde::Serialize;
use tokio::net::TcpStream;

pub(super) struct Connection {
    lease: crate::chisel::Lease,
    pub reverse_address: SocketAddr,
    reservation: Mutex<Option<TcpListener>>,
    claimed: AtomicBool,
    pub ready: AtomicBool,
    confirmed: Notify,
}

#[derive(Serialize)]
struct Offer<'a> {
    lease: &'a str,
    auth: &'a str,
    fingerprint: &'a str,
    listen: SocketAddr,
}

pub(super) async fn enroll(State(relay): State<Arc<Relay>>, req: Request) -> HttpResult {
    let grant = relay.authenticate(&req, Purpose::Register)?;
    let broker = relay
        .chisel
        .get()
        .ok_or(StatusCode::NOT_IMPLEMENTED)?
        .clone();
    let stopped = broker.stopped();
    if stopped.is_cancelled() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let reservation = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let address = reservation
        .local_addr()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let lease = broker
        .authorize(address, true)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let body = serde_json::to_vec(&Offer {
        lease: lease.id(),
        auth: lease.auth(),
        fingerprint: &lease.fingerprint,
        listen: address,
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let session = Arc::new(Session {
        expires_at: AtomicU64::new(grant.exp),
        renewed: Notify::new(),
        grant,
        serial: relay.serial.fetch_add(1, Ordering::Relaxed),
        backend: Backend::Chisel(Box::new(Connection {
            lease,
            reverse_address: address,
            reservation: Mutex::new(Some(reservation)),
            claimed: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            confirmed: Notify::new(),
        })),
        cancel: CancellationToken::new(),
        slots: Arc::new(Semaphore::new(256)),
    });
    let pending = session.clone();
    let owner = Arc::downgrade(&relay);
    let registered = relay
        .persist(move |db, directory| register_session(db, directory, pending, owner))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)??;
    tokio::spawn(async move {
        let Backend::Chisel(connection) = &session.backend else {
            unreachable!()
        };
        let handshake = async {
            loop {
                let confirmed = connection.confirmed.notified();
                if connection.ready.load(Ordering::Acquire) {
                    break;
                }
                confirmed.await;
            }
        };
        let lifetime = async {
            if tokio::time::timeout(Duration::from_secs(20), handshake)
                .await
                .is_err()
            {
                return;
            }
            std::future::pending::<()>().await;
        };
        tokio::select! {
            _ = lifetime => {}, _ = session.expired() => {},
            _ = session.cancel.cancelled() => {}, _ = stopped.cancelled() => {},
        }
        // The upgrade task keeps its Session alive until its opaque socket is
        // dropped. Only then can Lease::drop remove the private upstream server.
        drop(registered);
    });
    Response::builder()
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn registration(relay: &Relay, req: &Request) -> std::result::Result<Arc<Session>, StatusCode> {
    let grant = relay.authenticate(req, Purpose::Register)?;
    let mut directory = relay
        .directory
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    directory.check_control()?;
    let session = directory
        .sessions
        .get(&grant.route_id())
        .ok_or(StatusCode::CONFLICT)?;
    let old = &session.grant;
    if session.cancel.is_cancelled()
        || session.expires_at.load(Ordering::Acquire) <= grants::now()
        || old.iss != grant.iss
        || old.sub != grant.sub
        || old.execution != grant.execution
        || old.service != grant.service
        || old.policy != grant.policy
        || old.access != grant.access
        || old.http_request != grant.http_request
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let Backend::Chisel(connection) = &session.backend else {
        return Err(StatusCode::CONFLICT);
    };
    if req.uri().path().split('/').nth(5) != Some(connection.lease.id()) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(session.clone())
}

pub(super) async fn confirm(State(relay): State<Arc<Relay>>, req: Request) -> HttpResult {
    let session = registration(&relay, &req)?;
    let Backend::Chisel(connection) = &session.backend else {
        unreachable!()
    };
    if !connection.claimed.load(Ordering::Acquire) {
        return Err(StatusCode::CONFLICT);
    }
    connection.ready.store(true, Ordering::Release);
    connection.confirmed.notify_one();
    Ok(Response::builder().status(204).body(Body::empty()).unwrap())
}

pub(super) async fn attach(State(relay): State<Arc<Relay>>, mut req: Request) -> HttpResult {
    let session = registration(&relay, &req)?;
    let Backend::Chisel(connection) = &session.backend else {
        unreachable!()
    };
    if req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        != Some("chisel-v3")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (response, upgraded) = upgrade(&mut req)?;
    if connection.claimed.swap(true, Ordering::AcqRel) {
        return Err(StatusCode::CONFLICT);
    }
    connection
        .reservation
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .take();
    let address = connection.lease.address;
    proxy(
        req.headers().clone(),
        response,
        upgraded,
        address,
        session.cancel.clone(),
        session,
    )
    .await
}

pub(super) async fn proxy<T: Send + 'static>(
    headers: HeaderMap,
    mut response: Response,
    upgraded: hyper::upgrade::OnUpgrade,
    address: SocketAddr,
    cancel: CancellationToken,
    owner: T,
) -> HttpResult {
    let cancel_on_exit = cancel.clone().drop_guard();
    let offered = headers.get("sec-websocket-protocol").cloned();
    let upstream = tokio::time::timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect(address)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let (mut sender, transport) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(transport.with_upgrades());
        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        for name in [
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-protocol",
        ] {
            if let Some(value) = headers.get(name) {
                request.headers_mut().insert(name, value.clone());
            }
        }
        request
            .headers_mut()
            .insert("host", "localhost".parse().unwrap());
        let mut response = sender
            .send_request(request)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(StatusCode::BAD_GATEWAY);
        }
        // Upstream Chisel only answers 101 to its exact protocol offer, but its
        // upgrader never echoes the selection. Complete RFC 6455 negotiation
        // at this edge with the offer the attach path already required, and
        // reject any contradicting upstream selection.
        if response
            .headers()
            .get("sec-websocket-protocol")
            .is_some_and(|selected| Some(selected) != offered.as_ref())
        {
            return Err(StatusCode::BAD_GATEWAY);
        }
        hyper::upgrade::on(&mut response)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)
    })
    .await
    .map_err(|_| StatusCode::GATEWAY_TIMEOUT)??;
    if let Some(offered) = offered {
        response
            .headers_mut()
            .insert("sec-websocket-protocol", offered);
    }
    tokio::spawn(async move {
        let _cancel_on_exit = cancel_on_exit;
        let _owner = owner;
        let copy = async {
            let client = upgraded.await.map_err(|_| ())?;
            let _ = tokio::io::copy_bidirectional(
                &mut TokioIo::new(client),
                &mut TokioIo::new(upstream),
            )
            .await;
            Ok::<_, ()>(())
        };
        tokio::select! { _ = copy => {}, _ = cancel.cancelled() => {} }
    });
    Ok(response)
}
