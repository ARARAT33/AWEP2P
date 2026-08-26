use crate::registry::{valid_name, Registry, RegistryRecord, RegistryStatus, TldKind};
use serde::{Deserialize, Serialize};

pub const ADMIN_NAMESPACE: &str = ".awea";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnifiedEntityUri {
    PublicFile { fid: String },
    SecretFile { sfid: String },
    SiteId { sid: String },
    UserIdentity { uid: String },
    Channel { chid: String },
    Group { gid: String },
    App { aid: String },
    Node { nid: String },
    DomainOrService { domain: String },
    SearchQuery { query: String },
}

pub struct AweBrowserResolver;

impl AweBrowserResolver {
    pub fn parse_and_resolve(input: &str) -> UnifiedEntityUri {
        let trimmed = input.trim();
        let lower = trimmed.to_lowercase();

        if lower.starts_with("fid-") {
            UnifiedEntityUri::PublicFile {
                fid: trimmed.to_string(),
            }
        } else if lower.starts_with("sfid-") {
            UnifiedEntityUri::SecretFile {
                sfid: trimmed.to_string(),
            }
        } else if lower.starts_with("sid-") {
            UnifiedEntityUri::SiteId {
                sid: trimmed.to_string(),
            }
        } else if lower.starts_with("uid-") {
            UnifiedEntityUri::UserIdentity {
                uid: trimmed.to_string(),
            }
        } else if lower.starts_with("chid-") || lower.starts_with("cid-") {
            UnifiedEntityUri::Channel {
                chid: trimmed.to_string(),
            }
        } else if lower.starts_with("gid-") {
            UnifiedEntityUri::Group {
                gid: trimmed.to_string(),
            }
        } else if lower.starts_with("aid-") {
            UnifiedEntityUri::App {
                aid: trimmed.to_string(),
            }
        } else if lower.starts_with("nid-") {
            UnifiedEntityUri::Node {
                nid: trimmed.to_string(),
            }
        } else if lower.ends_with(".awe")
            || lower.starts_with("a2p2://")
            || lower.starts_with("awe://")
        {
            UnifiedEntityUri::DomainOrService {
                domain: trimmed.to_string(),
            }
        } else {
            UnifiedEntityUri::SearchQuery {
                query: trimmed.to_string(),
            }
        }
    }
}

pub fn resolve(registry: &Registry, name: &str) -> Option<RegistryRecord> {
    if !valid_name(name) {
        return None;
    }
    registry.resolve(name).cloned()
}

pub fn can_register_domain(parent: &RegistryRecord, requested: &str) -> bool {
    parent.status == RegistryStatus::Active
        && valid_name(requested)
        && requested.ends_with(&format!(".{}", parent.name))
}

pub fn kind_name(kind: &TldKind) -> &'static str {
    match kind {
        TldKind::Otld => "otld",
        TldKind::ThreeOtld => "3otld",
        TldKind::Ctld => "ctld",
        TldKind::Oatld => "oatld",
        TldKind::Octld => "octld",
        TldKind::Vtld => "vtld",
        TldKind::Autl => "autl",
        TldKind::Atld => "atld",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_awe_browser_resolver() {
        assert_eq!(
            AweBrowserResolver::parse_and_resolve("fid-123456"),
            UnifiedEntityUri::PublicFile {
                fid: "fid-123456".into()
            }
        );
        assert_eq!(
            AweBrowserResolver::parse_and_resolve("sfid-secret789"),
            UnifiedEntityUri::SecretFile {
                sfid: "sfid-secret789".into()
            }
        );
        assert_eq!(
            AweBrowserResolver::parse_and_resolve("uid-awe-msg-user1"),
            UnifiedEntityUri::UserIdentity {
                uid: "uid-awe-msg-user1".into()
            }
        );
        assert_eq!(
            AweBrowserResolver::parse_and_resolve("chid-channel1"),
            UnifiedEntityUri::Channel {
                chid: "chid-channel1".into()
            }
        );
        assert_eq!(
            AweBrowserResolver::parse_and_resolve("gid-group1"),
            UnifiedEntityUri::Group {
                gid: "gid-group1".into()
            }
        );
        assert_eq!(
            AweBrowserResolver::parse_and_resolve("site.awe"),
            UnifiedEntityUri::DomainOrService {
                domain: "site.awe".into()
            }
        );
        assert_eq!(
            AweBrowserResolver::parse_and_resolve("a2p2://portal.awe"),
            UnifiedEntityUri::DomainOrService {
                domain: "a2p2://portal.awe".into()
            }
        );
        assert_eq!(
            AweBrowserResolver::parse_and_resolve("sovereign p2p search"),
            UnifiedEntityUri::SearchQuery {
                query: "sovereign p2p search".into()
            }
        );
    }
}
