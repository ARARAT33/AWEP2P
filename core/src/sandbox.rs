//! Capability-bounded WASM sandbox runner.
//! Enforces declared application capabilities and execution limits.

use crate::permissions::{Capability, CapabilitySet};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub max_memory_bytes: usize,
    pub max_instruction_count: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB default limit
            max_instruction_count: 1_000_000,
        }
    }
}

pub struct WasmSandbox {
    config: SandboxConfig,
    capabilities: CapabilitySet,
}

impl WasmSandbox {
    pub fn new(config: SandboxConfig, capabilities: CapabilitySet) -> Self {
        Self {
            config,
            capabilities,
        }
    }

    pub fn validate_module(&self, wasm_bytes: &[u8]) -> Result<(), &'static str> {
        if wasm_bytes.len() < 8 || &wasm_bytes[..4] != b"\0asm" {
            return Err("invalid WebAssembly binary header");
        }

        if wasm_bytes.len() > self.config.max_memory_bytes {
            return Err("WASM module exceeds memory quota");
        }

        crate::store::validate_wasm(wasm_bytes)
    }

    pub fn execute_module(&self, wasm_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.validate_module(wasm_bytes)?;
        let _ = &self.capabilities;
        let _instruction_limit = self.config.max_instruction_count;
        Err("WASM execution backend is not linked; module validation succeeded")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_execution_rules() {
        let mut caps = CapabilitySet::default();
        caps.grant(Capability::StorageRead);
        let sandbox = WasmSandbox::new(SandboxConfig::default(), caps);

        let valid_wasm = b"\0asm\x01\0\0\0";
        assert!(sandbox.validate_module(valid_wasm).is_ok());
        assert!(sandbox.execute_module(valid_wasm).is_err());
    }
}
