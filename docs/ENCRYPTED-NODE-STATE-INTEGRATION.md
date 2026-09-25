# Encrypted Node State Integration Contract

AWEP2P node state contains identity-linked metadata and must not be treated as public cache data.

## Required behavior

- Use `awep2p_core::secure_state::{save_json, load_json}` for new persistence.
- Keep the state file inside the selected node storage directory.
- Obtain the unlock secret from a platform credential facility or an explicit interactive prompt; do not hard-code it or write it to logs.
- Reject empty secrets and fail closed on authentication failure or envelope corruption.
- Write state atomically (temporary file in the same directory, flush/sync where supported, then rename).
- A future migration must detect legacy plaintext `node_state.json`, require explicit user consent, encrypt it, and remove the plaintext only after the encrypted file is verified.

## Security boundary

This protects the state file against offline disclosure or tampering by a reader that does not possess the unlock secret. It does not prove anonymity, protect a compromised host, or make peer transport secure by itself.

## Validation requirements

Before merge, CI must cover round-trip recovery, wrong-secret failure, tamper detection, no plaintext marker leakage, and interrupted-write recovery. `platforms/linux/**` is intentionally out of scope for this contract.
