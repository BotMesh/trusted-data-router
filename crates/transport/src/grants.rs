//! Short-lived, purpose-separated Ed25519 capabilities issued by the application's
//! control gateway. A signature authorizes a route, not arbitrary agent actions.
use crate::{Error, Result};
use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trusted_contracts::{ExecutionIdentity, PolicyRef, ServiceId};

pub const AUDIENCE: &str = "trusted-data-router/v1";
pub const MAX_LIFETIME: u64 = 3600;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Register,
    Access,
    Revoke,
    /// Read-only route availability; cannot open application streams.
    Probe,
}

/// A single HTTP invocation approved by the application control plane. The
/// node ingress checks the bytes and durably consumes `id` before dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestBinding {
    pub id: String,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
}
impl HttpRequestBinding {
    pub fn validate(&self) -> Result<()> {
        if [&self.id, &self.body_sha256].iter().any(|s| {
            s.len() != 64
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) || !matches!(
            self.method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
        ) || !self.path.starts_with('/')
            || self.path.len() > 256
            || !self.path.is_ascii()
            || self.path.contains(['%', '?', '#', '\\'])
            || self.path.chars().any(char::is_control)
            || self.path.split('/').any(|p| p == "." || p == "..")
        {
            return Err(Error::InvalidContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub nbf: u64,
    pub exp: u64,
    pub purpose: Purpose,
    pub execution: ExecutionIdentity,
    pub service: ServiceId,
    pub policy: PolicyRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_request: Option<HttpRequestBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<crate::authorization::AccessBinding>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Grant {
    /// Exact-instance address. No load balancing or fallback to a replacement.
    pub fn route_id(&self) -> String {
        let bytes = serde_json::to_vec(&(&self.iss, &self.execution, &self.service))
            .expect("serializable identity");
        hex::encode(Sha256::digest(bytes))
    }

    fn validate(&self, issuer: &str, purpose: Purpose, clock: u64) -> Result<()> {
        if let Some(access) = &self.access {
            access.validate()?;
            if self.purpose != Purpose::Access || self.sub != access.principal {
                return Err(Error::Unauthorized);
            }
        }
        if let Some(binding) = &self.http_request {
            binding.validate()?;
            if self.purpose != Purpose::Access {
                return Err(Error::Unauthorized);
            }
        }
        let e = &self.execution;
        if self.iss != issuer
            || self.aud != AUDIENCE
            || self.purpose != purpose
            || self.nbf > clock
            || self.exp <= clock
            || self.exp.saturating_sub(self.nbf) > MAX_LIFETIME
            || self.purpose == Purpose::Probe && self.exp.saturating_sub(self.nbf) > 30
            || e.generation == 0
            || self.service.namespace != e.namespace
            || self.service.workload != e.workload
            || [
                &self.iss,
                &self.sub,
                &e.namespace,
                &e.workload,
                &e.allocation_id,
                &e.lease_id,
                &e.node_id,
                &self.service.service,
                &self.policy.issuer,
                &self.policy.policy_id,
            ]
            .iter()
            .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
            || self.policy.sha256.len() != 64
            || hex::decode(&self.policy.sha256).is_err()
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Verifier {
    keys: crate::keys::VerificationKeys,
    pub(crate) issuer: String,
}
impl Verifier {
    pub fn new(public_pem: &[u8], issuer: String) -> Result<Self> {
        Ok(Self {
            keys: crate::keys::VerificationKeys::new(public_pem)?,
            issuer,
        })
    }
    /// Reload the existing bounded public PEM bundle for each new admission.
    /// Replace it atomically; invalid updates fail closed without retaining keys.
    pub fn from_file(path: std::path::PathBuf, issuer: String) -> Result<Self> {
        Ok(Self {
            keys: crate::keys::VerificationKeys::file(path)?,
            issuer,
        })
    }
    pub fn verify(&self, token: &str, purpose: Purpose) -> Result<Grant> {
        if token.len() > 8192 {
            return Err(Error::Unauthorized);
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[AUDIENCE]);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        let grant: Grant = self.keys.decode(token, &validation)?;
        grant.validate(&self.issuer, purpose, now())?;
        Ok(grant)
    }
}

/// Called only by an authenticated central gateway after it authorizes this
/// principal, execution, policy revision and purpose. Nodes never hold this key.
pub fn sign(private_pem: &[u8], grant: &Grant) -> Result<String> {
    grant.validate(&grant.iss, grant.purpose, now())?;
    let key = EncodingKey::from_ed_pem(private_pem).map_err(|_| Error::InvalidContract)?;
    jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), grant, &key)
        .map_err(|_| Error::InvalidContract)
}
