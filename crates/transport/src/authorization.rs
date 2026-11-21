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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRevocation {
    pub namespace: String,
    pub principal: String,
    pub session: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationState {
    pub revision: u64,
    pub policies: Vec<AccessPolicy>,
    pub revoked_subjects: Vec<SubjectRevocation>,
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
        if self.revision == 0 || self.policies.len() + self.revoked_subjects.len() > 1024 {
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
                || !subjects.insert((&s.namespace, &s.principal, &s.session))
            {
                return Err(Error::InvalidContract);
            }
        }
        if let Some(old) = previous {
            if self.revision < old.revision
                || self.revision == old.revision && self != old
                || old
                    .revoked_subjects
                    .iter()
                    .any(|s| !self.revoked_subjects.contains(s))
                || old.policies.iter().any(|p| {
                    !self.policies.iter().any(|n| {
                        n.namespace == p.namespace
                            && n.workload == p.workload
                            && n.service == p.service
                            && (n == p || n.version > p.version)
                    })
                })
            {
                return Err(Error::InvalidContract);
            }
        }
        Ok(())
    }
    pub fn allows(&self, grant: &Grant) -> bool {
        let Some(binding) = &grant.access else {
            return false;
        };
        !self.revoked_subjects.iter().any(|r| {
            r.namespace == grant.execution.namespace
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
                        .find(|p| p.workload == "*")
                })
                .is_some_and(|p| {
                    p.enabled
                        && p.version == binding.policy_version
                        && p.sha256 == binding.policy_sha256
                })
        }
    }
}
