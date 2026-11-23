//! Data-plane framework. No listener, proxy, tunnel or permissive default is
//! implemented here. Integrations supply authenticated control-plane decisions
//! and an upstream transport implementation after interface review.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use trusted_contracts::{ExecutionIdentity, PolicyRef, ServiceId, Validity};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authorization rejected")]
    Unauthorized,
    #[error("execution or route is stale")]
    StaleExecution,
    #[error("service unavailable")]
    Unavailable,
    #[error("unsupported service or transport")]
    Unsupported,
    #[error("invalid service contract")]
    InvalidContract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http1,
    Http2,
    WebSocket,
    Tcp,
}

/// From the application's existing manifest, resolved by its runtime adapter.
/// `endpoint_ref` is an approved local endpoint identifier, never a user-selected
/// host or URL. SSE uses HTTP; gRPC requires end-to-end HTTP/2 support.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    pub id: ServiceId,
    pub protocol: Protocol,
    pub endpoint_ref: String,
}

/// A grant after the configured verifier has checked its signature, issuer,
/// audience, current allocation, policy and validity. This is not a wire token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationPermit {
    pub execution: ExecutionIdentity,
    pub service: ServiceSpec,
    pub policy: PolicyRef,
    pub validity: Validity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessPermit {
    pub principal: String,
    pub execution: ExecutionIdentity,
    pub service: ServiceId,
    pub operation: String,
    pub policy: PolicyRef,
    pub validity: Validity,
}

/// Routing metadata only: live sockets belong to their relay process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteBinding {
    pub service: ServiceId,
    pub execution: ExecutionIdentity,
    pub relay_id: String,
    pub connection_id: String,
    pub validity: Validity,
}

/// Implement with established signature validation and, where appropriate, rail.
/// Authenticated control-plane state must determine authority; agent-supplied
/// namespace, generation or policy claims are insufficient.
#[async_trait]
pub trait Authorizer: Send + Sync {
    async fn registration(&self, credential: &[u8]) -> Result<RegistrationPermit>;
    async fn access(
        &self,
        credential: &[u8],
        service: &ServiceId,
        operation: &str,
    ) -> Result<AccessPermit>;
}

/// Must atomically fence stale generations and preserve that fence after removal.
/// Resolving an affinity must return that exact execution or an error, never a
/// different replica. This is required for agent sessions and ComfyUI jobs.
#[async_trait]
pub trait RouteDirectory: Send + Sync {
    async fn publish(&self, permit: &RegistrationPermit, binding: RouteBinding) -> Result<()>;
    async fn resolve(
        &self,
        service: &ServiceId,
        affinity: Option<&ExecutionIdentity>,
    ) -> Result<RouteBinding>;
    /// Compare the full binding, so a late disconnect cannot remove a new route.
    async fn withdraw(&self, binding: &RouteBinding) -> Result<()>;
}

/// Node-side adapter managed by trusted-shim, reusing an existing tunnel backend.
/// The node initiates the connection. Publication must bind the grant to both the
/// service and the actual execution. Unsupported isolation profiles fail closed.
#[async_trait]
pub trait Connector: Send + Sync {
    async fn publish(
        &self,
        service: &ServiceSpec,
        execution: &ExecutionIdentity,
        credential: &[u8],
    ) -> Result<RouteBinding>;
    /// Stop accepting new work AND close existing streams for this binding.
    async fn withdraw(&self, binding: &RouteBinding) -> Result<()>;
}
