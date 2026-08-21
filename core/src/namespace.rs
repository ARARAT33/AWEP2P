use crate::registry::{valid_name, Registry, RegistryRecord, RegistryStatus, TldKind};

pub const ADMIN_NAMESPACE: &str = ".awea";

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
