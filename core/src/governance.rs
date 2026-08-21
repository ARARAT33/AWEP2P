//! Decentralized TLD Governance, capability-scoped delegation, and administrative policy rules.

use crate::registry::{RegistryRecord, TldKind};
use serde::{Deserialize, Serialize};

pub const DEFAULT_OTLD_MAX_DOMAINS: u32 = 10;
pub const PROTECTED_ADMIN_NAMESPACE: &str = ".awea";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceCapability {
    pub issuer: Vec<u8>,
    pub holder: Vec<u8>,
    pub scope: String,
    pub kind: TldKind,
    pub max_domains: Option<u32>,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceAuditRecord {
    pub timestamp: u64,
    pub actor_public_key: Vec<u8>,
    pub action: String,
    pub target: String,
    pub details: String,
}

pub struct GovernanceEngine;

impl GovernanceEngine {
    pub fn validate_domain_registration(
        tld_record: &RegistryRecord,
        user_domain_count: u32,
    ) -> Result<(), &'static str> {
        let kind = tld_record.kind.as_ref().ok_or("missing TLD kind")?;
        match kind {
            TldKind::Otld => {
                if user_domain_count >= DEFAULT_OTLD_MAX_DOMAINS {
                    return Err("OTLD domain quota exceeded (max 10 domains)");
                }
            }
            TldKind::ThreeOtld => {
                // Open creation according to policy
            }
            TldKind::Ctld => {
                // Requires community creator authorization
            }
            TldKind::Atld | TldKind::Vtld | TldKind::Oatld | TldKind::Octld => {
                // Managed TLDs
            }
            TldKind::Autl => {
                // Specific user assigned namespace
            }
        }
        Ok(())
    }

    pub fn is_protected_namespace(name: &str) -> bool {
        name == "awea" || name.ends_with(PROTECTED_ADMIN_NAMESPACE)
    }

    pub fn authorize_action(
        cap: &GovernanceCapability,
        target: &str,
        now: u64,
    ) -> Result<(), &'static str> {
        if cap.expires_at > 0 && now >= cap.expires_at {
            return Err("governance capability expired");
        }
        if !target.ends_with(&cap.scope) && target != cap.scope {
            return Err("action out of capability scope");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::RegistryStatus;

    #[test]
    fn otld_quota_enforced() {
        let record = RegistryRecord {
            object_type: crate::registry::RegistryObjectType::Tld,
            kind: Some(TldKind::Otld),
            name: "user".into(),
            owner_public_key: vec![0u8; 32],
            parent: None,
            status: RegistryStatus::Active,
            sequence: 1,
            content_hash: [0u8; 32],
            signature: vec![],
        };

        assert!(GovernanceEngine::validate_domain_registration(&record, 9).is_ok());
        assert!(GovernanceEngine::validate_domain_registration(&record, 10).is_err());
    }

    #[test]
    fn awea_protected() {
        assert!(GovernanceEngine::is_protected_namespace("sys.awea"));
        assert!(!GovernanceEngine::is_protected_namespace("example.com"));
    }
}
