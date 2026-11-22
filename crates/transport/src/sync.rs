//! Fleet control synchronization over outbound HTTPS. Wire records mirror
//! fleet-proto model/v1 RouterSync{Request,Response}; no scheduler dependency is
//! linked into the data plane. Application bytes never enter this client.
use crate::{control::private_file, relay::Relay, Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

pub const MAX_REVOCATIONS: usize = 4096;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRequest {
    pub epoch: Option<String>,
    pub after_revision: u64,
    pub applied_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_authorization_revision: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncResponse {
    pub router_id: String,
    pub issuer: String,
    pub epoch: String,
    pub from_revision: u64,
    pub revision: u64,
    pub revoked_routes: Vec<String>,
    pub lease_seconds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<crate::authorization::AuthorizationState>,
}

pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub(crate) fn valid_route(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedControl {
    authority: String,
    router_id: String,
    issuer: String,
    epoch: Option<String>,
    revision: u64,
    #[serde(default)]
    authorization: Option<crate::authorization::AuthorizationState>,
    // Monotonic and intentionally not persisted. A restart must contact Fleet.
    #[serde(skip)]
    deadline: Option<Instant>,
}
impl crate::relay::Directory {
    pub(crate) fn check_access(
        &self,
        grant: &crate::grants::Grant,
    ) -> std::result::Result<(), axum::http::StatusCode> {
        let authorized = match self.control.as_ref().and_then(|c| c.authorization.as_ref()) {
            Some(auth) => auth.allows(grant),
            None => grant.access.is_none(),
        };
        if authorized {
            Ok(())
        } else {
            Err(axum::http::StatusCode::FORBIDDEN)
        }
    }

    pub(crate) fn check_control(&mut self) -> std::result::Result<(), axum::http::StatusCode> {
        if self
            .control
            .as_ref()
            .is_some_and(|c| c.deadline.is_none_or(|d| d <= Instant::now()))
        {
            for (_, session) in self.sessions.drain() {
                session.cancel.cancel();
            }
            return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        }
        Ok(())
    }
}
impl Relay {
    pub fn requires_control(&self) -> Result<bool> {
        Ok(self
            .directory
            .lock()
            .map_err(|_| Error::Unavailable)?
            .control
            .is_some())
    }
    pub fn bind_control(&self, client: &ControlClient) -> Result<()> {
        let mut directory = self.directory.lock().map_err(|_| Error::Unavailable)?;
        if let Some(state) = &directory.control {
            if state.authority != client.authority
                || state.router_id != client.router_id
                || state.issuer != self.verifier.issuer
            {
                return Err(Error::InvalidContract);
            }
            return Ok(());
        }
        let state = ManagedControl {
            authority: client.authority.clone(),
            router_id: client.router_id.clone(),
            issuer: self.verifier.issuer.clone(),
            epoch: None,
            revision: 0,
            authorization: None,
            deadline: None,
        };
        directory
            .db
            .execute(
                "INSERT INTO control(singleton,state) VALUES(1,?1)",
                [serde_json::to_string(&state).map_err(|_| Error::InvalidContract)?],
            )
            .map_err(|_| Error::Unavailable)?;
        directory.control = Some(state);
        let _ = directory.check_control();
        Ok(())
    }
    pub(crate) fn expire_control(&self) {
        if let Ok(mut directory) = self.directory.lock() {
            let _ = directory.check_control();
        }
    }
    pub(crate) fn suspend_control(&self) {
        if let Ok(mut directory) = self.directory.lock() {
            if let Some(state) = &mut directory.control {
                state.deadline = None;
            }
            let _ = directory.check_control();
        }
    }
    fn sync_request(&self, client: &ControlClient) -> Result<SyncRequest> {
        let directory = self.directory.lock().map_err(|_| Error::Unavailable)?;
        let state = directory.control.as_ref().ok_or(Error::InvalidContract)?;
        if state.authority != client.authority || state.router_id != client.router_id {
            return Err(Error::InvalidContract);
        }
        Ok(SyncRequest {
            epoch: state.epoch.clone(),
            after_revision: state.revision,
            applied_revision: state.epoch.as_ref().map(|_| state.revision),
            applied_authorization_revision: state.authorization.as_ref().map(|a| a.revision),
        })
    }
    fn apply_control(
        &self,
        client: &ControlClient,
        request: &SyncRequest,
        update: &SyncResponse,
        started: Instant,
    ) -> Result<()> {
        let mut directory = self.directory.lock().map_err(|_| Error::Unavailable)?;
        // Never preserve an old connection across an expired control lease,
        // even if this response races the watchdog's next tick.
        let _ = directory.check_control();
        let state = directory.control.as_ref().ok_or(Error::InvalidContract)?;
        if state.authority != client.authority
            || state.router_id != update.router_id
            || state.issuer != update.issuer
            || state.epoch != request.epoch
            || state.revision != request.after_revision
            || state.epoch.as_ref().is_some_and(|e| e != &update.epoch)
            || update.epoch.len() != 32
            || !update.epoch.bytes().all(|b| b.is_ascii_hexdigit())
            || update.from_revision != state.revision
            || update.revision < state.revision
            || update.revision > MAX_REVOCATIONS as u64
            || update.revision - update.from_revision != update.revoked_routes.len() as u64
            || !update.revoked_routes.iter().all(|r| valid_route(r))
            || update
                .revoked_routes
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != update.revoked_routes.len()
            || !(1..=30).contains(&update.lease_seconds)
        {
            return Err(Error::InvalidContract);
        }
        match &update.authorization {
            Some(auth) => auth.validate(state.authorization.as_ref())?,
            None if state.authorization.is_some() => return Err(Error::InvalidContract),
            None => {}
        }
        let deadline = started + Duration::from_secs(update.lease_seconds.into());
        if deadline <= Instant::now() {
            return Err(Error::StaleExecution);
        }
        let next = ManagedControl {
            epoch: Some(update.epoch.clone()),
            revision: update.revision,
            authorization: update.authorization.clone(),
            deadline: Some(deadline),
            ..state.clone()
        };
        let transaction = directory.db.transaction().map_err(|_| Error::Unavailable)?;
        for route in &update.revoked_routes {
            transaction
                .execute("INSERT OR IGNORE INTO revoked(route) VALUES(?1)", [route])
                .map_err(|_| Error::Unavailable)?;
        }
        transaction
            .execute(
                "UPDATE control SET state=?1 WHERE singleton=1",
                [serde_json::to_string(&next).map_err(|_| Error::InvalidContract)?],
            )
            .map_err(|_| Error::Unavailable)?;
        transaction.commit().map_err(|_| Error::Unavailable)?;
        for route in &update.revoked_routes {
            if let Some(session) = directory.sessions.remove(route) {
                session.cancel.cancel();
            }
        }
        if let Some(auth) = &next.authorization {
            for stream in directory.streams.values() {
                if !auth.allows(&stream.grant) {
                    stream.cancel.cancel();
                }
            }
        }
        directory.control = Some(next);
        Ok(())
    }
}

pub struct ControlClient {
    pub(crate) authority: String,
    pub(crate) router_id: String,
    token_file: PathBuf,
    endpoint: reqwest::Url,
    http: reqwest::Client,
}
impl ControlClient {
    pub fn new(fleet: &str, router_id: String, token_file: PathBuf) -> Result<Self> {
        let mut url = reqwest::Url::parse(fleet).map_err(|_| Error::InvalidContract)?;
        let local = url.host_str().is_some_and(|h| {
            h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        });
        if !(url.scheme() == "https" || url.scheme() == "http" && local)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !valid_id(&router_id)
        {
            return Err(Error::InvalidContract);
        }
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }
        let endpoint = url
            .join(&format!("routers/{router_id}/sync"))
            .map_err(|_| Error::InvalidContract)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            authority: url.to_string(),
            router_id,
            token_file,
            endpoint,
            http,
        })
    }
    pub fn from_env() -> Result<Option<Self>> {
        let names = [
            "TRUSTED_ROUTER_FLEET_URL",
            "TRUSTED_ROUTER_ID",
            "TRUSTED_ROUTER_TOKEN_FILE",
        ];
        let values: Vec<_> = names.iter().map(std::env::var_os).collect();
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        let values: Vec<String> = values
            .into_iter()
            .map(|v| {
                v.and_then(|s| s.into_string().ok())
                    .filter(|s| !s.is_empty())
                    .ok_or(Error::InvalidContract)
            })
            .collect::<Result<_>>()?;
        let mut client = Self::new(&values[0], values[1].clone(), PathBuf::from(&values[2]))?;
        if let Some(ca) = crate::control::ca_from_env("TRUSTED_ROUTER_FLEET_CA_FILE")? {
            client.http = crate::control::http_client(Some(&ca))?;
        }
        Ok(Some(client))
    }
    /// A request acknowledges only the prior transaction, never the response
    /// about to be received. A crash before acknowledgment simply replays it.
    pub async fn poll_once(&self, relay: &Relay) -> Result<()> {
        let request = relay.sync_request(self)?;
        let token = String::from_utf8(private_file(&self.token_file)?)
            .map_err(|_| Error::InvalidContract)?;
        if token.trim().is_empty() {
            return Err(Error::InvalidContract);
        }
        let started = Instant::now();
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .bearer_auth(token.trim())
            // Older Fleet versions ignore this header and keep accepting the
            // unchanged JSON request. New Fleet gates default policies on it.
            .header(
                "x-fleet-router-capabilities",
                "workload-defaults-v1,scoped-revocations-v1",
            )
            .json(&request)
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        if matches!(response.status().as_u16(), 401 | 403 | 404 | 409) {
            relay.suspend_control();
            return Err(Error::Unavailable);
        }
        if !response.status().is_success() {
            return Err(Error::Unavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if body.len() + chunk.len() > 1024 * 1024 {
                return Err(Error::InvalidContract);
            }
            body.extend_from_slice(&chunk);
        }
        let update: SyncResponse =
            serde_json::from_slice(&body).map_err(|_| Error::InvalidContract)?;
        relay.apply_control(self, &request, &update, started)
    }
    pub async fn run(self, relay: Arc<Relay>) {
        loop {
            // Errors never renew a lease. The relay watchdog independently
            // terminates streams, even when this task is blocked or crashes.
            let _ = self.poll_once(&relay).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}
