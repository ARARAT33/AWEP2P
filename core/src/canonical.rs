use crate::protocol::ProtocolEnvelope;

/// Deterministic wire encoding for protocol envelopes.
/// Fields are length-prefixed big-endian values; no platform-dependent layout is used.
pub fn encode_envelope(envelope: &ProtocolEnvelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + envelope.payload.len());
    out.extend_from_slice(&envelope.version.to_be_bytes());
    put_bytes(&mut out, envelope.message_type.as_bytes());
    put_bytes(&mut out, envelope.request_id.as_bytes());
    put_bytes(&mut out, &envelope.payload);
    out
}

pub fn decode_envelope(mut input: &[u8]) -> Result<ProtocolEnvelope, &'static str> {
    let version = take_u16(&mut input)?;
    let message_type =
        String::from_utf8(take_bytes(&mut input)?.to_vec()).map_err(|_| "invalid message type")?;
    let request_id =
        String::from_utf8(take_bytes(&mut input)?.to_vec()).map_err(|_| "invalid request id")?;
    let payload = take_bytes(&mut input)?.to_vec();
    if !input.is_empty() {
        return Err("trailing bytes");
    }
    Ok(ProtocolEnvelope {
        version,
        message_type,
        request_id,
        payload,
    })
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn take_u16(input: &mut &[u8]) -> Result<u16, &'static str> {
    if input.len() < 2 {
        return Err("truncated u16");
    }
    let (a, b) = input.split_at(2);
    *input = b;
    Ok(u16::from_be_bytes([a[0], a[1]]))
}
fn take_bytes<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], &'static str> {
    if input.len() < 8 {
        return Err("truncated length");
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&input[..8]);
    let len = u64::from_be_bytes(n) as usize;
    *input = &input[8..];
    if len > input.len() {
        return Err("truncated bytes");
    }
    let (a, b) = input.split_at(len);
    *input = b;
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_is_deterministic() {
        let e = ProtocolEnvelope::new("identity", "r1", vec![1, 2, 3]);
        let a = encode_envelope(&e);
        let b = encode_envelope(&e);
        assert_eq!(a, b);
        assert_eq!(decode_envelope(&a).unwrap(), e);
    }
}
