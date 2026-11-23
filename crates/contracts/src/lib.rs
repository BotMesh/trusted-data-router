//! Shared vocabulary, with no scheduler, network, rule engine or crypto dependency.
//!
//! These records are data, not evidence of authorization. A receiver must validate
//! their issuer and binding before trusting them. Wire encodings and signatures
//! are deliberately outside this framework revision.

use serde::{Deserialize, Serialize};

/// An execution allocated by an authoritative control plane.
///
/// `generation` increases when an instance is replaced. The allocator must retain
/// its generation fence across deletion and restart. An execution lease is not
/// itself an expiring network access token: losing connectivity must not silently
/// release Fleet reservations or start a duplicate workload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIdentity {
    pub namespace: String,
    pub workload: String,
    pub allocation_id: String,
    pub lease_id: String,
    pub generation: u64,
    pub node_id: String,
}

/// A logical service; independent of agent type, replica address and transport.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceId {
    pub namespace: String,
    pub workload: String,
    pub service: String,
}

/// An immutable policy revision owned by the central policy gateway.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    pub issuer: String,
    pub policy_id: String,
    pub version: u64,
    pub sha256: String,
}

/// Validity of a grant or statement, expressed as Unix seconds.
/// Implementations must enforce `not_before <= now < expires_at`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validity {
    pub not_before: u64,
    pub expires_at: u64,
}

/// Distinct proof domains; a policy proof never substitutes for attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    PolicyEvaluation,
    RemoteAttestation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_execution_authority_fields_are_not_silently_accepted() {
        let input = serde_json::json!({
            "namespace": "film", "workload": "qwen", "allocation_id": "a",
            "lease_id": "l", "generation": 1, "node_id": "n", "admin": true
        });
        assert!(serde_json::from_value::<ExecutionIdentity>(input).is_err());
    }

    #[test]
    fn unknown_proof_domain_is_rejected() {
        assert!(serde_json::from_str::<ProofKind>("\"trusted\"").is_err());
    }
}
