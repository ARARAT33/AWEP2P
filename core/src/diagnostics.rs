//! Node health diagnostics, system metric tracking, and privacy-preserving logging.

use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Online,
    Degraded,
    Warning,
    Offline,
    Quarantined,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub uptime_secs: u64,
    pub latency_ms: u32,
    pub bandwidth_kbps: u32,
    pub available_storage_bytes: u64,
    pub used_storage_bytes: u64,
    pub successful_transfers: u64,
    pub failed_transfers: u64,
    pub replica_health_pct: u8,
    pub dht_responsiveness_pct: u8,
    pub cpu_usage_pct: u8,
    pub ram_usage_pct: u8,
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self {
            uptime_secs: 0,
            latency_ms: 10,
            bandwidth_kbps: 10_000,
            available_storage_bytes: 10 * 1024 * 1024 * 1024,
            used_storage_bytes: 0,
            successful_transfers: 0,
            failed_transfers: 0,
            replica_health_pct: 100,
            dht_responsiveness_pct: 100,
            cpu_usage_pct: 5,
            ram_usage_pct: 10,
        }
    }
}

pub struct NodeDiagnostics {
    start_time: Instant,
    metrics: NodeMetrics,
}

impl NodeDiagnostics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            metrics: NodeMetrics::default(),
        }
    }

    pub fn update_metrics(&mut self, mut metrics: NodeMetrics) {
        metrics.uptime_secs = self.start_time.elapsed().as_secs();
        self.metrics = metrics;
    }

    pub fn status(&self) -> HealthStatus {
        if self.metrics.failed_transfers > self.metrics.successful_transfers + 50 {
            HealthStatus::Warning
        } else if self.metrics.replica_health_pct < 50 || self.metrics.dht_responsiveness_pct < 50 {
            HealthStatus::Degraded
        } else if self.metrics.cpu_usage_pct > 95 || self.metrics.ram_usage_pct > 95 {
            HealthStatus::Warning
        } else {
            HealthStatus::Online
        }
    }

    pub fn metrics(&self) -> &NodeMetrics {
        &self.metrics
    }

    /// Sanitize log message to prevent leaking secrets, private keys, or passwords.
    pub fn sanitize_log(input: &str) -> String {
        let mut sanitized = input.to_string();
        for key in &["password", "secret", "private_key", "vault_key", "seed"] {
            if let Some(idx) = sanitized.to_lowercase().find(key) {
                let tail = &sanitized[idx..];
                if let Some(colon) = tail.find(':') {
                    let end = tail.find('\n').unwrap_or(tail.len());
                    let secret_part = &tail[colon + 1..end];
                    sanitized = sanitized.replace(secret_part, " [REDACTED]");
                }
            }
        }
        sanitized
    }
}

impl Default for NodeDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_transitions() {
        let mut diag = NodeDiagnostics::new();
        assert_eq!(diag.status(), HealthStatus::Online);

        let m = NodeMetrics {
            replica_health_pct: 30,
            ..Default::default()
        };
        diag.update_metrics(m);
        assert_eq!(diag.status(), HealthStatus::Degraded);
    }

    #[test]
    fn log_sanitization() {
        let raw = "user authenticated with password: super_secret_123 in system";
        let clean = NodeDiagnostics::sanitize_log(raw);
        assert!(!clean.contains("super_secret_123"));
        assert!(clean.contains("[REDACTED]"));
    }
}
