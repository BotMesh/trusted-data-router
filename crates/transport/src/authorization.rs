//! Fleet-approved access bindings, separate from connector registration policy.
//! Wire records mirror fleet-proto RouterAuthorization and RouterAccessBinding.
use crate::{grants::Grant, sync::valid_route, Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessIdentity {
    pub principal: String,
    pub session: String,
}
impl AccessIdentity {
    pub fn validate(&self) -> Result<()> {
        if valid_route(&self.principal) && valid_route(&self.session) {
            Ok(())
        } else {
            Err(Error::InvalidContract)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessBinding {
    pub principal: String,
    pub session: String,
    pub policy_version: u64,
    pub policy_sha256: String,
}
impl AccessBinding {
    pub fn validate(&self) -> Result<()> {
        if valid_route(&self.principal)
            && valid_route(&self.session)
            && self.policy_version > 0
            && valid_route(&self.policy_sha256)
        {
            Ok(())
        } else {
            Err(Error::InvalidContract)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicy {
    pub namespace: String,
    pub workload: String,
    pub service: String,
    pub version: u64,
    pub sha256: String,
    pub enabled: bool,
}
impl AccessPolicy {
    fn same_target(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            && self.workload == other.workload
            && self.service == other.service
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRevocation {
    pub namespace: String,
    pub principal: String,
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_only: Option<bool>,
    /// Unix seconds after which a delegate (application-only) denial may be
    /// dropped. Fleet sets it beyond the longest grant signed before the
    /// denial, so dropping it cannot revive one. Operator bans never expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}
/// Policies and permanent denials, as before expiry existed.
pub const MAX_PERMANENT_RECORDS: usize = 1024;
/// Expiring delegate denials, bounded separately so logouts never consume the
/// permanent budget.
pub const MAX_EXPIRING_REVOCATIONS: usize = 4096;
impl SubjectRevocation {
    /// Replacement must deny every identity and service denied by the old record,
    /// for at least as long. In particular, application-only revocation cannot
    /// replace operator denial, and an expiring one cannot replace a permanent one.
    fn covers(&self, old: &Self) -> bool {
        self.namespace == old.namespace
            && self.principal == old.principal
            && (self.session.is_none() || self.session == old.session)
            && (self.application_only != Some(true) || old.application_only == Some(true))
            && match (self.expires_at, old.expires_at) {
                (None, _) => true,
                (Some(new), Some(old)) => new >= old,
                (Some(_), None) => false,
            }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationState {
    pub revision: u64,
    pub policies: Vec<AccessPolicy>,
    pub revoked_subjects: Vec<SubjectRevocation>,
    /// The highest version of any policy Fleet has removed; it never decreases.
    /// Fleet creates every later policy above it, so a grant bound to a removed
    /// policy can never match one created afterwards for the same target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_policy_version: Option<u64>,
}
fn namespace(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
impl AuthorizationState {
    pub fn validate(&self, previous: Option<&Self>) -> Result<()> {
        self.validate_at(previous, crate::grants::now())
    }
    /// `now` is this relay's own clock: an expiring denial may be absent only
    /// once it has passed here, whatever Fleet's clock says.
    pub fn validate_at(&self, previous: Option<&Self>, now: u64) -> Result<()> {
        let expiring = self
            .revoked_subjects
            .iter()
            .filter(|s| s.expires_at.is_some())
            .count();
        if self.revision == 0
            || self.policies.len() + self.revoked_subjects.len() - expiring > MAX_PERMANENT_RECORDS
            || expiring > MAX_EXPIRING_REVOCATIONS
            // Only a namespace delegate's denial may expire.
            || self.revoked_subjects.iter().any(|s| {
                s.expires_at
                    .is_some_and(|e| e == 0 || s.application_only != Some(true))
            })
        {
            return Err(Error::InvalidContract);
        }
        let mut policies = std::collections::HashSet::new();
        for p in &self.policies {
            if !namespace(&p.namespace)
                || !(p.workload == "*" || name(&p.workload))
                || !name(&p.service)
                || p.version == 0
                || !valid_route(&p.sha256)
                || !policies.insert((&p.namespace, &p.workload, &p.service))
            {
                return Err(Error::InvalidContract);
            }
        }
        let mut subjects = std::collections::HashSet::new();
        for s in &self.revoked_subjects {
            if !namespace(&s.namespace)
                || !valid_route(&s.principal)
                || s.session.as_ref().is_some_and(|s| !valid_route(s))
                || !subjects.insert((
                    &s.namespace,
                    &s.principal,
                    &s.session,
                    s.application_only == Some(true),
                ))
            {
                return Err(Error::InvalidContract);
            }
        }
        if let Some(old) = previous {
            if self.revision < old.revision
                || self.revision == old.revision && self != old
                || old.revoked_subjects.iter().any(|s| {
                    s.expires_at.is_none_or(|e| now < e)
                        && !self.revoked_subjects.iter().any(|new| new.covers(s))
                })
                || self.retired_policy_version < old.retired_policy_version
                || old.policies.iter().any(|p| !self.succeeds(p))
                || self.policies.iter().any(|n| {
                    Some(n.version) <= old.retired_policy_version
                        && !old.policies.iter().any(|p| p.same_target(n))
                })
            {
                return Err(Error::InvalidContract);
            }
        }
        Ok(())
    }
    /// Whether this snapshot accounts for the previous snapshot's policy `old`:
    /// it keeps the policy, replaces it with a higher version, or retires it.
    /// Only an enabled policy can be retired: a disabled exact policy is what
    /// keeps its namespace's `*` default from applying to that workload.
    fn succeeds(&self, old: &AccessPolicy) -> bool {
        match self.policies.iter().find(|n| n.same_target(old)) {
            Some(new) => new == old || new.version > old.version,
            None => old.enabled && Some(old.version) <= self.retired_policy_version,
        }
    }
    pub fn allows(&self, grant: &Grant) -> bool {
        let Some(binding) = &grant.access else {
            return false;
        };
        !self.revoked_subjects.iter().any(|r| {
            r.namespace == grant.execution.namespace
                && (grant.service.service != "control" || r.application_only != Some(true))
                && r.principal == binding.principal
                && r.session.as_ref().is_none_or(|s| s == &binding.session)
        }) && {
            let scoped = |p: &&AccessPolicy| {
                p.namespace == grant.execution.namespace && p.service == grant.service.service
            };
            self.policies
                .iter()
                .filter(scoped)
                .find(|p| p.workload == grant.service.workload)
                .or_else(|| {
                    self.policies
                        .iter()
                        .filter(scoped)
                        .find(|p| p.workload == "*" && grant.service.service != "control")
                })
                .is_some_and(|p| {
                    p.enabled
                        && p.version == binding.policy_version
                        && p.sha256 == binding.policy_sha256
                })
        }
    }
}
