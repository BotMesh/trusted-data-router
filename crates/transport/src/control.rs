//! Embeddable control gateway. Fleet authorizes application visibility and
//! supplies live execution identities; this module never forwards app bytes.
use crate::{
    grants::{self, Grant, Purpose},
    Error, Result,
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use trusted_contracts::{ExecutionIdentity, PolicyRef, ServiceId};
use trusted_data_router::ServiceSpec;

const NODE_AUDIENCE: &str = "trusted-runtime-node/v1";
const NODE_LIFETIME: u64 = 30 * 86400;
const GRANT_LIFETIME: u64 = 900;

/// An operator enrolls a node after verifying its Fleet identity. This is a
/// bootstrap credential, not a TEE attestation. Keep it outside the workload.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCredential {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub namespaces: Vec<String>,
    pub nbf: u64,
    pub exp: u64,
}
fn label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}
impl NodeCredential {
    fn validate(&self) -> Result<()> {
        if self.aud != NODE_AUDIENCE
            || !label(&self.iss)
            || !label(&self.sub)
            || self.namespaces.is_empty()
            || self.namespaces.len() > 64
            || self.namespaces.iter().any(|s| !label(s))
            || self.nbf > grants::now()
            || self.exp <= grants::now()
            || self.exp.saturating_sub(self.nbf) > NODE_LIFETIME
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
pub fn enroll_node(private_key: &[u8], credential: &NodeCredential) -> Result<String> {
    credential.validate()?;
    jsonwebtoken::encode(
        &Header::new(Algorithm::EdDSA),
        credential,
        &EncodingKey::from_ed_pem(private_key).map_err(|_| Error::InvalidContract)?,
    )
    .map_err(|_| Error::InvalidContract)
}

pub fn private_file(path: &Path) -> Result<Vec<u8>> {
    crate::keys::read_file(path, true)
}

fn root(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| Error::InvalidContract)?;
    if url.scheme() != "https"
        && !(url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]")))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::InvalidContract);
    }
    Ok(url)
}

#[derive(Clone)]
pub struct Gateway {
    fleet: reqwest::Url,
    relay: reqwest::Url,
    issuer: String,
    signing_key: Vec<u8>,
    signing_key_file: Option<PathBuf>,
    node_keys: crate::keys::VerificationKeys,
    registration_token_file: PathBuf,
    namespace_tokens: std::collections::HashMap<String, PathBuf>,
    client: reqwest::Client,
    authorization_router: Option<String>,
}
#[derive(Deserialize)]
struct AppView {
    name: String,
    namespace: String,
    disabled: bool,
    #[serde(default)]
    runtime_instances: Vec<Instance>,
}
#[derive(Deserialize)]
struct Instance {
    execution: ExecutionIdentity,
    ready: bool,
    services: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRequest {
    pub service: ServiceId,
    /// Present when renewing credentials for an existing, stateful session.
    pub execution: Option<ExecutionIdentity>,
    /// Stable opaque address saved by clients; never resolves to a replacement.
    pub route_id: Option<String>,
    #[serde(default)]
    pub http_request: Option<grants::HttpRequestBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<crate::authorization::AccessIdentity>,
    /// A backend can shorten a grant to the remaining authenticated session life.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub execution: ExecutionIdentity,
    pub service: ServiceId,
    pub route_id: String,
    pub base_url: String,
    pub token: String,
    pub expires_at: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    execution: ExecutionIdentity,
    service: ServiceSpec,
}

impl Gateway {
    pub fn new(
        fleet_url: &str,
        relay_url: &str,
        issuer: String,
        private_key: &[u8],
        public_key: &[u8],
        registration_token_file: PathBuf,
    ) -> Result<Arc<Self>> {
        if !label(&issuer) {
            return Err(Error::InvalidContract);
        }
        let node_keys = crate::keys::VerificationKeys::new(public_key)?;
        // Reject mismatched key pairs at startup, rather than issuing unusable grants.
        let probe = NodeCredential {
            iss: issuer.clone(),
            aud: NODE_AUDIENCE.into(),
            sub: "key-check".into(),
            namespaces: vec!["key-check".into()],
            nbf: grants::now(),
            exp: grants::now() + 60,
        };
        let token = enroll_node(private_key, &probe)?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[NODE_AUDIENCE]);
        node_keys
            .decode::<NodeCredential>(&token, &validation)
            .map_err(|_| Error::InvalidContract)?;
        Ok(Arc::new(Self {
            fleet: root(fleet_url)?,
            relay: root(relay_url)?,
            issuer,
            signing_key: private_key.into(),
            signing_key_file: None,
            node_keys,
            registration_token_file,
            namespace_tokens: Default::default(),
            authorization_router: None,
            client: http_client(None)?,
        }))
    }

    /// Keep the existing paths live so an operator can stage overlapping public
    /// keys and switch the signer without restarting embedded gateways.
    pub fn with_key_files(
        mut self: Arc<Self>,
        private: PathBuf,
        public: PathBuf,
    ) -> Result<Arc<Self>> {
        let gateway = Arc::make_mut(&mut self);
        gateway.node_keys = crate::keys::VerificationKeys::file(public)?;
        gateway.signing_key_file = Some(private);
        gateway.checked_signing_key()?;
        gateway.signing_key.clear();
        Ok(self)
    }

    fn checked_signing_key(&self) -> Result<Vec<u8>> {
        let key = match &self.signing_key_file {
            Some(path) => private_file(path)?,
            None => self.signing_key.clone(),
        };
        let probe = NodeCredential {
            iss: self.issuer.clone(),
            aud: NODE_AUDIENCE.into(),
            sub: "key-check".into(),
            namespaces: vec!["key-check".into()],
            nbf: grants::now(),
            exp: grants::now() + 60,
        };
        let token = enroll_node(&key, &probe)?;
        self.node(&token)?;
        Ok(key)
    }

    /// Optional central-backend integration, using its existing environment.
    /// Absence disables the routes; an incomplete configuration fails startup.
    pub fn from_env() -> Result<Option<Arc<Self>>> {
        let Ok(fleet) = std::env::var("TRUSTED_GATEWAY_FLEET_URL") else {
            return Ok(None);
        };
        let value = |name| std::env::var(name).map_err(|_| Error::InvalidContract);
        let key_path = PathBuf::from(value("TRUSTED_GATEWAY_SIGNING_KEY_FILE")?);
        let public_path = PathBuf::from(value("TRUSTED_GATEWAY_PUBLIC_KEY_FILE")?);
        let key = private_file(&key_path)?;
        let public = crate::keys::read_file(&public_path, false)?;
        let mut gateway = Self::new(
            &fleet,
            &value("TRUSTED_GATEWAY_RELAY_URL")?,
            value("TRUSTED_GATEWAY_ISSUER")?,
            &key,
            &public,
            value("TRUSTED_GATEWAY_FLEET_TOKEN_FILE")?.into(),
        )?
        .with_key_files(key_path, public_path)?;
        if let Some(ca) = ca_from_env("TRUSTED_GATEWAY_CA_FILE")? {
            Arc::make_mut(&mut gateway).client = http_client(Some(&ca))?;
        }
        if let Some(mapping) = std::env::var_os("TRUSTED_GATEWAY_NAMESPACE_TOKEN_FILES") {
            let mapping = mapping.into_string().map_err(|_| Error::InvalidContract)?;
            gateway = gateway.with_registration_tokens(
                serde_json::from_str(&mapping).map_err(|_| Error::InvalidContract)?,
            )?;
        }
        match std::env::var("TRUSTED_GATEWAY_ROUTER_ID") {
            Ok(id) => gateway.with_authorization(&id).map(Some),
            Err(std::env::VarError::NotPresent) => Ok(Some(gateway)),
            Err(_) => Err(Error::InvalidContract),
        }
    }

    /// Namespace readers for multi-tenant node registration. No root Fleet
    /// credential is needed on the business gateway.
    pub fn with_registration_tokens(
        mut self: Arc<Self>,
        mapping: std::collections::HashMap<String, PathBuf>,
    ) -> Result<Arc<Self>> {
        if mapping.len() > 1024
            || mapping
                .iter()
                .any(|(namespace, path)| !label(namespace) || !path.is_absolute())
        {
            return Err(Error::InvalidContract);
        }
        Arc::make_mut(&mut self).namespace_tokens = mapping;
        Ok(self)
    }

    pub fn with_authorization(mut self: Arc<Self>, router_id: &str) -> Result<Arc<Self>> {
        if !crate::sync::valid_id(router_id) {
            return Err(Error::InvalidContract);
        }
        Arc::make_mut(&mut self).authorization_router = Some(router_id.into());
        Ok(self)
    }
    pub fn manages_identities(&self) -> bool {
        self.authorization_router.is_some()
    }

    async fn fleet_json(&self, request: reqwest::RequestBuilder) -> Result<serde_json::Value> {
        let mut response = request.send().await.map_err(|_| Error::Unavailable)?;
        if !response.status().is_success() {
            return Err(if matches!(response.status().as_u16(), 401 | 403 | 404) {
                Error::Unauthorized
            } else {
                Error::Unavailable
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err(Error::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)
    }
    async fn access_binding(
        &self,
        token: &str,
        request: &ConnectionRequest,
    ) -> Result<Option<crate::authorization::AccessBinding>> {
        let Some(router) = &self.authorization_router else {
            return if request.identity.is_none() {
                Ok(None)
            } else {
                Err(Error::InvalidContract)
            };
        };
        let identity = request.identity.as_ref().ok_or(Error::Unauthorized)?;
        identity.validate()?;
        let url = self
            .fleet
            .join(&format!("routers/{router}/authorize"))
            .map_err(|_| Error::InvalidContract)?;
        let binding: crate::authorization::AccessBinding = serde_json::from_value(self.fleet_json(self.client.post(url).bearer_auth(token)
            .json(&serde_json::json!({"namespace":request.service.namespace,"workload":request.service.workload,"service":request.service.service,
                "principal":identity.principal,"session":identity.session}))).await?).map_err(|_| Error::Unavailable)?;
        binding.validate()?;
        if binding.principal != identity.principal || binding.session != identity.session {
            return Err(Error::Unauthorized);
        }
        Ok(Some(binding))
    }
    /// A namespace-wide backend delegation credential revokes only its own
    /// identities. Raw user credentials never cross into Fleet or the relay.
    pub async fn revoke_identity(
        &self,
        token: &str,
        identity: &crate::authorization::AccessIdentity,
    ) -> Result<()> {
        identity.validate()?;
        let router = self
            .authorization_router
            .as_ref()
            .ok_or(Error::InvalidContract)?;
        let access = self
            .fleet_json(
                self.client
                    .get(
                        self.fleet
                            .join("access")
                            .map_err(|_| Error::InvalidContract)?,
                    )
                    .bearer_auth(token),
            )
            .await?;
        let namespace = access["namespace"].as_str().ok_or(Error::Unauthorized)?;
        if !access["permissions"]
            .as_array()
            .is_some_and(|p| p.iter().any(|v| v == "router_delegate"))
        {
            return Err(Error::Unauthorized);
        }
        let url = self
            .fleet
            .join(&format!("routers/{router}/revoke-subject"))
            .map_err(|_| Error::InvalidContract)?;
        self.fleet_json(
            self.client
                .post(url)
                .bearer_auth(token)
                .json(&serde_json::json!({"namespace":namespace,
            "principal":identity.principal,"session":identity.session})),
        )
        .await?;
        Ok(())
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/v1/runtime/registration", post(registration))
            .route("/v1/runtime/connections", post(connections))
            .route("/v1/runtime/probes", post(probes))
            .layer(DefaultBodyLimit::max(16384))
            .with_state(self)
    }
    fn node(&self, token: &str) -> Result<NodeCredential> {
        if token.len() > 8192 {
            return Err(Error::Unauthorized);
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[NODE_AUDIENCE]);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        let claims: NodeCredential = self.node_keys.decode(token, &validation)?;
        claims.validate()?;
        Ok(claims)
    }
    async fn instances(&self, token: &str, service: &ServiceId) -> Result<Vec<Instance>> {
        if !label(&service.namespace)
            || !label(&service.workload)
            || !label(&service.service)
            || token.is_empty()
            || token.len() > 8192
            || token.contains(['\r', '\n'])
        {
            return Err(Error::InvalidContract);
        }
        let mut url = self.fleet.clone();
        url.path_segments_mut()
            .map_err(|_| Error::InvalidContract)?
            .extend(["apps", &service.workload]);
        url.query_pairs_mut()
            .append_pair("namespace", &service.namespace);
        // Every issuance rechecks the caller's namespace/tag/app scope in Fleet.
        // No auth cache and no redirects that could disclose the caller's token.
        let mut response = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        match response.status().as_u16() {
            200 => {}
            401 | 403 | 404 => return Err(Error::Unauthorized),
            _ => return Err(Error::Unavailable),
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(Error::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        let view: AppView = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if view.namespace != service.namespace || view.name != service.workload || view.disabled {
            return Err(Error::Unauthorized);
        }
        Ok(view
            .runtime_instances
            .into_iter()
            .filter(|i| {
                i.ready
                    && i.execution.namespace == service.namespace
                    && i.execution.workload == service.workload
                    && i.services.contains(&service.service)
            })
            .collect())
    }
    fn grant(
        &self,
        execution: ExecutionIdentity,
        service: ServiceId,
        purpose: Purpose,
        subject: String,
    ) -> Grant {
        // This names the route ACL, not an action PolicyEngine receipt.
        let sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(&service).expect("service"),
        ));
        Grant {
            iss: self.issuer.clone(),
            aud: grants::AUDIENCE.into(),
            sub: subject,
            nbf: grants::now(),
            exp: grants::now() + GRANT_LIFETIME,
            purpose,
            http_request: None,
            access: None,
            execution,
            service,
            policy: PolicyRef {
                issuer: self.issuer.clone(),
                policy_id: "fleet-service-access/v1".into(),
                version: 1,
                sha256,
            },
        }
    }
    /// The embedding application may call this after its own ownership check,
    /// using its least-privilege Fleet credential. Never pass a browser-supplied
    /// workload through that privileged path without checking ownership.
    pub async fn connections(
        &self,
        fleet_token: &str,
        request: &ConnectionRequest,
    ) -> Result<Vec<Connection>> {
        self.connections_for(fleet_token, request, Purpose::Access)
            .await
    }
    pub async fn probes(
        &self,
        fleet_token: &str,
        request: &ConnectionRequest,
    ) -> Result<Vec<Connection>> {
        self.connections_for(fleet_token, request, Purpose::Probe)
            .await
    }
    async fn connections_for(
        &self,
        fleet_token: &str,
        request: &ConnectionRequest,
        purpose: Purpose,
    ) -> Result<Vec<Connection>> {
        if purpose == Purpose::Probe
            && (request.http_request.is_some() || request.identity.is_some())
        {
            return Err(Error::InvalidContract);
        }
        if let Some(binding) = &request.http_request {
            binding.validate()?;
        }
        let mut request = request.clone();
        if purpose == Purpose::Probe || request.service.service == "control" {
            // Node administration is not granted by ordinary app read access.
            let mut response = self
                .client
                .get(
                    self.fleet
                        .join("access")
                        .map_err(|_| Error::InvalidContract)?,
                )
                .bearer_auth(fleet_token)
                .send()
                .await
                .map_err(|_| Error::Unavailable)?;
            if !response.status().is_success() {
                return Err(Error::Unauthorized);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
                if bytes.len() + chunk.len() > 65536 {
                    return Err(Error::Unavailable);
                }
                bytes.extend_from_slice(&chunk);
            }
            let access: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
            if !access["permissions"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v == "admin"))
            {
                return Err(Error::Unauthorized);
            }
        }
        if purpose == Purpose::Access
            && self.manages_identities()
            && request.service.service == "control"
        {
            // Preserve the operator path used by provisioners, after the admin
            // check above. Callers cannot choose another operator's identity.
            request.identity = Some(crate::authorization::AccessIdentity {
                principal: hex::encode(Sha256::digest(format!("fleet:operator:v1:{fleet_token}"))),
                session: hex::encode(Sha256::digest(format!(
                    "fleet:operator-session:v1:{fleet_token}"
                ))),
            });
        }
        let binding = if purpose == Purpose::Access {
            self.access_binding(fleet_token, &request).await?
        } else {
            None
        };
        let mut output = Vec::new();
        for instance in self.instances(fleet_token, &request.service).await? {
            if request
                .execution
                .as_ref()
                .is_some_and(|e| e != &instance.execution)
            {
                continue;
            }
            let mut grant = self.grant(
                instance.execution,
                request.service.clone(),
                purpose,
                format!(
                    "fleet:{}",
                    hex::encode(Sha256::digest(fleet_token.as_bytes()))
                ),
            );
            if purpose == Purpose::Probe {
                grant.exp = grant.nbf + 30;
            }
            grant.http_request = request.http_request.clone();
            if let Some(expiry) = request.expires_at {
                grant.exp = grant.exp.min(expiry);
            }
            if let Some(binding) = &binding {
                grant.sub = binding.principal.clone();
                grant.access = Some(binding.clone());
            }
            let route_id = grant.route_id();
            if request.route_id.as_ref().is_some_and(|r| r != &route_id) {
                continue;
            }
            output.push(Connection {
                execution: grant.execution.clone(),
                service: grant.service.clone(),
                base_url: format!("{}v1/http/{}", self.relay, route_id),
                route_id,
                token: grants::sign(&self.checked_signing_key()?, &grant)?,
                expires_at: grant.exp,
            });
        }
        if output.is_empty() {
            return Err(Error::Unavailable);
        }
        Ok(output)
    }
    /// Fleet readiness and relay registration are independent observations.
    /// This reads the relay's authenticated route state without dispatching the
    /// application request. Call before returning a newly prepared mutation.
    pub async fn ready(&self, connection: &Connection) -> Result<bool> {
        if connection.base_url != format!("{}v1/http/{}", self.relay, connection.route_id) {
            return Err(Error::InvalidContract);
        }
        let response = self
            .client
            .get(
                self.relay
                    .join(&format!("v1/ready/{}", connection.route_id))
                    .map_err(|_| Error::InvalidContract)?,
            )
            .bearer_auth(&connection.token)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(response.status() == reqwest::StatusCode::NO_CONTENT)
    }

    async fn register(&self, token: &str, request: &Registration) -> Result<String> {
        let node = self.node(token)?;
        if node.sub != request.execution.node_id
            || !node.namespaces.contains(&request.execution.namespace)
            || request.service.id.namespace != request.execution.namespace
            || request.service.id.workload != request.execution.workload
            || !(request.service.endpoint_ref == "app" && request.service.id.service != "control"
                || request.service.endpoint_ref == "control"
                    && request.service.id.service == "control"
                || request.service.id.service != "control"
                    && request.service.endpoint_ref
                        == format!("ingress:{}", request.service.id.service))
        {
            return Err(Error::Unauthorized);
        }
        let path = self
            .namespace_tokens
            .get(&request.execution.namespace)
            .unwrap_or(&self.registration_token_file);
        let token = String::from_utf8(private_file(path)?).map_err(|_| Error::InvalidContract)?;
        if !self
            .instances(token.trim(), &request.service.id)
            .await?
            .iter()
            .any(|i| i.execution == request.execution)
        {
            return Err(Error::Unauthorized);
        }
        grants::sign(
            &self.checked_signing_key()?,
            &self.grant(
                request.execution.clone(),
                request.service.id.clone(),
                Purpose::Register,
                node.sub,
            ),
        )
    }
}

fn bearer(headers: &HeaderMap) -> std::result::Result<&str, StatusCode> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)
}
fn status(error: Error) -> StatusCode {
    match error {
        Error::Unauthorized => StatusCode::FORBIDDEN,
        Error::InvalidContract => StatusCode::BAD_REQUEST,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
async fn registration(
    State(gateway): State<Arc<Gateway>>,
    headers: HeaderMap,
    Json(request): Json<Registration>,
) -> std::result::Result<Json<serde_json::Value>, StatusCode> {
    gateway
        .register(bearer(&headers)?, &request)
        .await
        .map(|token| Json(serde_json::json!({"token":token})))
        .map_err(status)
}
async fn connections(
    State(gateway): State<Arc<Gateway>>,
    headers: HeaderMap,
    Json(request): Json<ConnectionRequest>,
) -> std::result::Result<Json<Vec<Connection>>, StatusCode> {
    gateway
        .connections(bearer(&headers)?, &request)
        .await
        .map(Json)
        .map_err(status)
}

async fn probes(
    State(gateway): State<Arc<Gateway>>,
    headers: HeaderMap,
    Json(request): Json<ConnectionRequest>,
) -> std::result::Result<Json<Vec<Connection>>, StatusCode> {
    gateway
        .probes(bearer(&headers)?, &request)
        .await
        .map(Json)
        .map_err(status)
}

pub(crate) fn http_client(ca: Option<&[u8]>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10));
    if let Some(ca) = ca {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(ca).map_err(|_| Error::InvalidContract)?,
        );
    }
    builder.build().map_err(|_| Error::Unavailable)
}

pub(crate) fn ca_from_env(name: &str) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let Some(path) = std::env::var_os(name) else {
        return Ok(None);
    };
    let file = std::fs::File::open(path).map_err(|_| Error::InvalidContract)?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidContract)?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::InvalidContract);
    }
    Ok(Some(bytes))
}
