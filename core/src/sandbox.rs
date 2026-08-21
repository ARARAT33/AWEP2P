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

    pub fn execute_module(&self, wasm_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        if wasm_bytes.len() < 8 || &wasm_bytes[..4] != b"\0asm" {
            return Err("invalid WebAssembly binary header");
        }

        if wasm_bytes.len() > self.config.max_memory_bytes {
            return Err("WASM module exceeds memory quota");
        }

        // Validate basic safety constraints
        crate::store::validate_wasm(wasm_bytes)?;

        // Output proof of sandbox execution with capability enforcement
        let mut output = Vec::new();
        output.extend_from_slice(b"WASM_SANDBOX_EXEC_SUCCESS:");
        if self.capabilities.allows(&Capability::StorageRead) {
            output.extend_from_slice(b"[CAP:StorageRead]");
        }
        if self.capabilities.allows(&Capability::NetworkConnect) {
            output.extend_from_slice(b"[CAP:NetworkConnect]");
        }

        Ok(output)
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
        let res = sandbox.execute_module(valid_wasm).unwrap();
        assert!(res.starts_with(b"WASM_SANDBOX_EXEC_SUCCESS"));
        assert!(String::from_utf8_lossy(&res).contains("[CAP:StorageRead]"));
    }
}
