use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    IdentityRead,
    IdentityExport,
    NetworkConnect,
    NetworkListen,
    StorageRead,
    StorageWrite,
    HostPublish,
    StoreInstall,
    DeviceMedia,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl CapabilitySet {
    pub fn grant(&mut self, capability: Capability) {
        self.0.insert(capability);
    }
    pub fn revoke(&mut self, capability: &Capability) {
        self.0.remove(capability);
    }
    pub fn allows(&self, capability: &Capability) -> bool {
        self.0.contains(capability)
    }
}
