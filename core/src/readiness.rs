//! Production-readiness model for the AWE Net implementation.
//!
//! This is a code-readiness model. External Internet/NAT and clean-machine
//! validation are separate release evidence and are never counted as passing
//! merely because source modules exist.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessItem {
    pub name: &'static str,
    pub implemented: bool,
    pub operator_validation_required: bool,
}

pub const READINESS_ITEMS: &[ReadinessItem] = &[
    ReadinessItem {
        name: "Authenticated encrypted transport",
        implemented: true,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "Peer discovery and signed announcements",
        implemented: true,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "DHT-style iterative peer lookup",
        implemented: true,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "Data Centre topology and relay failover",
        implemented: true,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "Encrypted data-plane framing",
        implemented: true,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "Replica placement and repair planning",
        implemented: true,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "Local storage integrity and recovery primitives",
        implemented: true,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "Resource admission and hostile-traffic limits",
        implemented: true,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "LAN and cross-machine node operation",
        implemented: true,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "NAT traversal and multi-transport deployment",
        implemented: false,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "End-to-end AWEwww/AWETLD/AWEOpen resolution over live peers",
        implemented: false,
        operator_validation_required: true,
    },
    ReadinessItem {
        name: "Production multi-Data-Centre recovery and release validation",
        implemented: false,
        operator_validation_required: true,
    },
];

pub fn implementation_percent() -> u8 {
    let implemented = READINESS_ITEMS
        .iter()
        .filter(|item| item.implemented)
        .count();
    ((implemented * 100) / READINESS_ITEMS.len()) as u8
}

pub fn remaining_percent() -> u8 {
    100 - implementation_percent()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_model_is_bounded() {
        assert!(implementation_percent() <= 100);
        assert!(remaining_percent() <= 100);
        assert_eq!(implementation_percent() + remaining_percent(), 100);
    }

    #[test]
    fn operator_validation_is_explicit() {
        assert!(READINESS_ITEMS
            .iter()
            .all(|item| item.operator_validation_required));
    }
}
