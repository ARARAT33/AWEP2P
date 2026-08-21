use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolEnvelope {
    pub version: u16,
    pub message_type: String,
    pub request_id: String,
    pub payload: Vec<u8>,
}

impl ProtocolEnvelope {
    pub fn new(
        message_type: impl Into<String>,
        request_id: impl Into<String>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type: message_type.into(),
            request_id: request_id.into(),
            payload,
        }
    }
}
