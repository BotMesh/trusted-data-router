//! Independently deployed relay. Its listener is loopback-only behind a TLS
//! reverse proxy. The backend and Fleet are never in the application byte path.
use crate::{
    grants::{self, Grant, Purpose, Verifier},
    transport::{websocket_config, WsIo},
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{any, delete, get},
    Router,
};
use futures::future::poll_fn;
use hyper_util::rt::TokioIo;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, Semaphore},
};
use tokio_tungstenite::{
    tungstenite::{handshake::derive_accept_key, protocol::Role},
    WebSocketStream,
};
use tokio_util::{
    compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
    sync::CancellationToken,
};

type HttpResult = std::result::Result<Response, StatusCode>;
type Open = oneshot::Sender<yamux::Stream>;

pub(crate) struct Session {
    grant: Grant,
    serial: u64,
    open: mpsc::Sender<Open>,
    pub(crate) cancel: CancellationToken,
    slots: Arc<Semaphore>,
}
pub(crate) struct Directory {
    pub(crate) db: Connection,
    pub(crate) sessions: HashMap<String, Arc<Session>>,
    pub(crate) control: Option<crate::sync::ManagedControl>,
    pub(crate) streams: HashMap<u64, AccessStream>,
}
pub(crate) struct AccessStream {
    pub(crate) grant: Grant,
    pub(crate) cancel: CancellationToken,
}
struct AccessGuard {
    id: u64,
    relay: std::sync::Weak<Relay>,
    cancel: CancellationToken,
}
impl Drop for AccessGuard {
    fn drop(&mut self) {
        if let Some(relay) = self.relay.upgrade() {
            if let Ok(mut directory) = relay.directory.lock() {
                directory.streams.remove(&self.id);
            }
        }
    }
}
pub struct Relay {
    pub(crate) verifier: Verifier,
    pub(crate) directory: Mutex<Directory>,
    serial: AtomicU64,
    watchdog_started: AtomicBool,
}

impl Relay {
    pub fn new(verifier: Verifier, database: &Path) -> crate::Result<Arc<Self>> {
        let db = Connection::open(database).map_err(|_| crate::Error::Unavailable)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS control(singleton INTEGER PRIMARY KEY CHECK(singleton=1), state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS revoked(route TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS generations(slot TEXT PRIMARY KEY, generation INTEGER NOT NULL, route TEXT NOT NULL, policy TEXT NOT NULL);")
            .map_err(|_| crate::Error::Unavailable)?;
        let control: Option<String> = db
            .query_row("SELECT state FROM control WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|_| crate::Error::Unavailable)?;
        let control = control
            .map(|s| serde_json::from_str::<crate::sync::ManagedControl>(&s))
            .transpose()
            .map_err(|_| crate::Error::InvalidContract)?;
        Ok(Arc::new(Self {
            verifier,
            directory: Mutex::new(Directory {
                db,
                control,
                sessions: HashMap::new(),
                streams: HashMap::new(),
            }),
            serial: AtomicU64::new(1),
            watchdog_started: AtomicBool::new(false),
        }))
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/v1/connect/{route}", get(connect))
            .route("/v1/tunnel/{route}", get(tunnel))
            .route("/v1/ready/{route}", get(ready))
            .route("/v1/http/{route}/", any(http_proxy))
            .route("/v1/http/{route}/{*rest}", any(http_proxy))
            .route("/v1/revoke/{route}", delete(revoke))
            .layer(axum::middleware::from_fn_with_state(
                self.clone(),
                watch_control,
            ))
            .with_state(self)
    }
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        self.serve_with_origins(listener, &[]).await
    }
    pub async fn serve_with_origins(
        self: Arc<Self>,
        listener: TcpListener,
        origins: &[String],
    ) -> std::io::Result<()> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err(std::io::Error::other(
                "TLS proxy must reach a loopback listener",
            ));
        }
        axum::serve(listener, browser_router(self.router(), origins)?).await
    }
    fn authenticate(
        &self,
        req: &Request,
        purpose: Purpose,
    ) -> std::result::Result<Grant, StatusCode> {
        let header = if req.uri().path().starts_with("/v1/http/") {
            "x-trusted-access"
        } else {
            "authorization"
        };
        let value = req
            .headers()
            .get(header)
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let token = if header == "authorization" {
            value
                .strip_prefix("Bearer ")
                .ok_or(StatusCode::UNAUTHORIZED)?
        } else {
            value
        };
        let grant = self
            .verifier
            .verify(token, purpose)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let route = req.uri().path().split('/').nth(3).unwrap_or("");
        if grant.route_id() != route {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(grant)
    }
    fn session(&self, grant: &Grant) -> std::result::Result<Arc<Session>, StatusCode> {
        let mut directory = self
            .directory
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        directory.check_control()?;
        directory.check_access(grant)?;
        let session = directory
            .sessions
            .get(&grant.route_id())
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        if session.cancel.is_cancelled()
            || session.grant.exp <= grants::now()
            || session.grant.policy != grant.policy
        {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(session.clone())
    }
    fn track_access(
        self: &Arc<Self>,
        grant: &Grant,
        session: &Session,
    ) -> std::result::Result<Arc<AccessGuard>, StatusCode> {
        let mut directory = self
            .directory
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        directory.check_control()?;
        directory.check_access(grant)?;
        if session.cancel.is_cancelled() {
            return Err(StatusCode::FORBIDDEN);
        }
        let id = self.serial.fetch_add(1, Ordering::Relaxed);
        let cancel = session.cancel.child_token();
        directory.streams.insert(
            id,
            AccessStream {
                grant: grant.clone(),
                cancel: cancel.clone(),
            },
        );
        Ok(Arc::new(AccessGuard {
            id,
            relay: Arc::downgrade(self),
            cancel,
        }))
    }
}

// Initialize on the first request, so embedded Router users receive the same
// enforcement as serve(), and router construction needs no Tokio context.
async fn watch_control(
    State(relay): State<Arc<Relay>>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    if !relay.watchdog_started.swap(true, Ordering::AcqRel) {
        let weak = Arc::downgrade(&relay);
        tokio::spawn(async move {
            loop {
                let Some(relay) = weak.upgrade() else {
                    break;
                };
                relay.expire_control();
                drop(relay);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }
    next.run(req).await
}

/// Browser traffic carries its scoped grant in a header. Never enable wildcard
/// origins or cookies on the relay; application ownership is checked centrally.
pub fn browser_router(router: Router, origins: &[String]) -> std::io::Result<Router> {
    use axum::http::{header, HeaderValue, Method};
    use tower_http::cors::CorsLayer;
    if origins.is_empty() {
        return Ok(router);
    }
    let mut allowed = Vec::new();
    for origin in origins {
        let url = reqwest::Url::parse(origin).map_err(std::io::Error::other)?;
        if url.origin().ascii_serialization() != *origin
            || url.scheme() != "https"
                && !(url.scheme() == "http"
                    && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
        {
            return Err(std::io::Error::other("invalid browser origin"));
        }
        allowed.push(HeaderValue::from_str(origin).map_err(std::io::Error::other)?);
    }
    Ok(router.layer(
        CorsLayer::new()
            .allow_origin(allowed)
            .allow_methods([
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
                header::HeaderName::from_static("x-trusted-access"),
            ])
            .max_age(Duration::from_secs(300)),
    ))
}

fn upgrade(
    req: &mut Request,
) -> std::result::Result<(Response, hyper::upgrade::OnUpgrade), StatusCode> {
    if req.method() != "GET"
        || !has_token(req.headers(), "connection", "upgrade")
        || !has_token(req.headers(), "upgrade", "websocket")
        || req
            .headers()
            .get("sec-websocket-version")
            .and_then(|v| v.to_str().ok())
            != Some("13")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = req
        .headers()
        .get("sec-websocket-key")
        .ok_or(StatusCode::BAD_REQUEST)?;
    let response = Response::builder()
        .status(101)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-accept", derive_accept_key(key.as_bytes()))
        .body(Body::empty())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok((response, hyper::upgrade::on(req)))
}
fn has_token(headers: &HeaderMap, name: &str, token: &str) -> bool {
    headers.get_all(name).iter().any(|v| {
        v.to_str()
            .is_ok_and(|s| s.split(',').any(|s| s.trim().eq_ignore_ascii_case(token)))
    })
}

async fn connect(State(relay): State<Arc<Relay>>, mut req: Request) -> HttpResult {
    let grant = relay.authenticate(&req, Purpose::Register)?;
    let (response, upgraded) = upgrade(&mut req)?;
    let route = grant.route_id();
    let (tx, mut rx) = mpsc::channel::<Open>(64);
    let cancel = CancellationToken::new();
    let session = Arc::new(Session {
        grant,
        serial: relay.serial.fetch_add(1, Ordering::Relaxed),
        open: tx,
        cancel: cancel.clone(),
        slots: Arc::new(Semaphore::new(256)),
    });
    {
        let mut directory = relay
            .directory
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        directory.check_control()?;
        let revoked: bool = directory
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked WHERE route=?1)",
                [&route],
                |row| row.get(0),
            )
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if revoked {
            return Err(StatusCode::FORBIDDEN);
        }
        if directory.sessions.contains_key(&route) {
            return Err(StatusCode::CONFLICT);
        }
        if directory.sessions.len() >= 1024 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        // Node-local allocation generations are fenced within their authority.
        // Cross-node replacement still requires the gateway to revoke the old
        // exact execution; no node is permitted to invent a global generation.
        let e = &session.grant.execution;
        let slot = serde_json::to_string(&(
            &session.grant.iss,
            &session.grant.service,
            &e.allocation_id,
            &e.node_id,
        ))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        let policy =
            serde_json::to_string(&session.grant.policy).map_err(|_| StatusCode::BAD_REQUEST)?;
        let generation = i64::try_from(e.generation).map_err(|_| StatusCode::BAD_REQUEST)?;
        let previous: Option<(i64, String, String)> = directory
            .db
            .query_row(
                "SELECT generation,route,policy FROM generations WHERE slot=?1",
                [&slot],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if previous.as_ref().is_some_and(|(g, r, p)| {
            *g > generation || *g == generation && (r != &route || p != &policy)
        }) {
            return Err(StatusCode::CONFLICT);
        }
        let transaction = directory
            .db
            .transaction()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        transaction.execute("INSERT INTO generations(slot,generation,route,policy) VALUES(?1,?2,?3,?4)
            ON CONFLICT(slot) DO UPDATE SET generation=excluded.generation,route=excluded.route,policy=excluded.policy",
            params![slot,generation,route,policy]).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if let Some((_, old, _)) = &previous {
            if old != &route {
                transaction
                    .execute("INSERT OR IGNORE INTO revoked(route) VALUES(?1)", [old])
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            }
        }
        transaction
            .commit()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if let Some((_, old, _)) = previous {
            if old != route {
                if let Some(old) = directory.sessions.remove(&old) {
                    old.cancel.cancel();
                }
            }
        }
        directory.sessions.insert(route.clone(), session.clone());
    }
    tokio::spawn(async move {
        let run = async {
            let io = TokioIo::new(upgraded.await.map_err(|_| ())?);
            let ws =
                WebSocketStream::from_raw_socket(io, Role::Server, Some(websocket_config())).await;
            let mut mux = yamux::Connection::new(
                WsIo::new(ws).compat(),
                yamux::Config::default(),
                yamux::Mode::Server,
            );
            loop {
                tokio::select! {
                    _ = poll_fn(|cx| mux.poll_next_inbound(cx)) => break, // edge must only accept streams
                    request = rx.recv() => {
                        let Some(reply) = request else { break; };
                        let stream = poll_fn(|cx| {
                            if mux.poll_next_inbound(cx).is_ready() { return std::task::Poll::Ready(Err(())); }
                            mux.poll_new_outbound(cx).map_err(|_| ())
                        }).await?;
                        let _ = reply.send(stream);
                    }
                }
            }
            Ok::<(), ()>(())
        };
        tokio::select! { _ = run => {}, _ = cancel.cancelled() => {}, _ = expires(session.grant.exp) => {} }
        cancel.cancel();
        if let Ok(mut directory) = relay.directory.lock() {
            if directory
                .sessions
                .get(&route)
                .is_some_and(|s| s.serial == session.serial)
            {
                directory.sessions.remove(&route);
            }
        }
    });
    Ok(response)
}

async fn open(session: &Session) -> std::result::Result<yamux::Stream, StatusCode> {
    let (tx, rx) = oneshot::channel();
    session
        .open
        .try_send(tx)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    tokio::time::timeout(Duration::from_secs(15), rx)
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
pub(crate) async fn expires(exp: u64) {
    tokio::time::sleep(Duration::from_secs(exp.saturating_sub(grants::now()))).await;
}

/// Observe the exact route without sending application bytes or consuming an
/// HTTP invocation. Availability is advisory; mutations still must not replay.
async fn ready(State(relay): State<Arc<Relay>>, req: Request) -> HttpResult {
    let grant = relay.authenticate(&req, Purpose::Access)?;
    let session = relay.session(&grant)?;
    if session.open.is_closed() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn tunnel(State(relay): State<Arc<Relay>>, mut req: Request) -> HttpResult {
    let grant = relay.authenticate(&req, Purpose::Access)?;
    if grant.http_request.is_some() {
        return Err(StatusCode::FORBIDDEN);
    }
    let session = relay.session(&grant)?;
    let access = relay.track_access(&grant, &session)?;
    let slot = session
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let (response, upgraded) = upgrade(&mut req)?;
    let mut upstream = open(&session).await?.compat();
    tokio::spawn(async move {
        let _slot = slot;
        let copy = async {
            let io = TokioIo::new(upgraded.await.map_err(|_| ())?);
            let ws =
                WebSocketStream::from_raw_socket(io, Role::Server, Some(websocket_config())).await;
            let _ = tokio::io::copy_bidirectional(&mut WsIo::new(ws), &mut upstream).await;
            Ok::<(), ()>(())
        };
        tokio::select! { _ = copy => {}, _ = access.cancel.cancelled() => {}, _ = expires(grant.exp) => {} }
    });
    Ok(response)
}

async fn revoke(State(relay): State<Arc<Relay>>, req: Request) -> HttpResult {
    let grant = relay.authenticate(&req, Purpose::Revoke)?;
    let route = grant.route_id();
    let mut directory = relay
        .directory
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    directory
        .db
        .execute(
            "INSERT OR IGNORE INTO revoked(route) VALUES(?1)",
            params![route],
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if let Some(session) = directory.sessions.remove(&route) {
        session.cancel.cancel();
    }
    Ok(Response::builder().status(204).body(Body::empty()).unwrap())
}

fn strip_hop(headers: &mut HeaderMap, websocket: bool) {
    let dynamic: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(',').map(|x| x.trim().to_owned()))
        .collect();
    for key in dynamic {
        if !websocket || !key.eq_ignore_ascii_case("upgrade") {
            headers.remove(key);
        }
    }
    for key in [
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "x-trusted-access",
    ] {
        headers.remove(key);
    }
    if websocket {
        headers.insert("connection", "upgrade".parse().unwrap());
    } else {
        headers.remove("connection");
        headers.remove("upgrade");
    }
}

async fn http_proxy(State(relay): State<Arc<Relay>>, mut req: Request) -> HttpResult {
    let grant = relay.authenticate(&req, Purpose::Access)?;
    let capability = req
        .headers()
        .get("x-trusted-access")
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let session = relay.session(&grant)?;
    let access = relay.track_access(&grant, &session)?;
    let slot = Arc::new(
        session
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?,
    );
    let stream = open(&session).await?;
    let websocket = has_token(req.headers(), "upgrade", "websocket");
    let client_upgrade = if websocket {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };
    let prefix = format!("/v1/http/{}/", grant.route_id());
    let path = req
        .uri()
        .path_and_query()
        .ok_or(StatusCode::BAD_REQUEST)?
        .as_str();
    let path = format!(
        "/{}",
        path.strip_prefix(&prefix).ok_or(StatusCode::BAD_REQUEST)?
    );
    if let Some(binding) = &grant.http_request {
        if websocket || binding.path != path || binding.method != req.method().as_str() {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    *req.uri_mut() = path.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    strip_hop(req.headers_mut(), websocket);
    // A local shim ingress verifies the exact signed execution before injecting
    // native app credentials. Never trust the client's copy of this header.
    req.headers_mut().insert("x-trusted-route", capability);
    req.headers_mut()
        .insert("host", "localhost".parse().unwrap());
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream.compat()))
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let cancellation = access.cancel.clone();
    let connection_access = access.clone();
    let connection_slot = slot.clone();
    tokio::spawn(async move {
        let _slot = connection_slot;
        let _access = connection_access;
        tokio::select! { _ = connection.with_upgrades() => {}, _ = cancellation.cancelled() => {}, _ = expires(grant.exp) => {} }
    });
    let mut response = tokio::time::timeout(Duration::from_secs(30), sender.send_request(req))
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return Err(StatusCode::BAD_GATEWAY);
        };
        let server_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            let _slot = slot;
            let copy = async {
                let (client, server) = tokio::try_join!(client_upgrade, server_upgrade)?;
                let _ = tokio::io::copy_bidirectional(
                    &mut TokioIo::new(client),
                    &mut TokioIo::new(server),
                )
                .await;
                Ok::<(), hyper::Error>(())
            };
            tokio::select! { _ = copy => {}, _ = access.cancel.cancelled() => {}, _ = expires(grant.exp) => {} }
        });
    }
    let upgraded = websocket && response.status() == StatusCode::SWITCHING_PROTOCOLS;
    strip_hop(response.headers_mut(), upgraded);
    Ok(response.map(Body::new))
}

pub fn loopback(address: SocketAddr) -> crate::Result<SocketAddr> {
    if address.ip().is_loopback() {
        Ok(address)
    } else {
        Err(crate::Error::InvalidContract)
    }
}
