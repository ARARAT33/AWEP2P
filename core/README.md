# AWEp2P Core

The core is the platform-independent security and protocol foundation shared by Windows, Linux, Android and the future AWEOS implementation.

## Implemented foundation

- Ed25519 identity key generation and signatures
- deterministic AWE-ID derived from the public key
- validated human-facing usernames
- password-protected encrypted local identity vault
- Argon2 password verification
- ChaCha20-Poly1305 authenticated vault encryption
- secret export/import for explicit user-controlled recovery
- zeroized transient secret buffers
- OS randomness through `OsRng`
- domain-separated SHA-256 protocol hashing
- constant-time byte comparison
- capability-based permission primitives
- deterministic canonical protocol-envelope serialization
- protocol versioning
- replay protection primitive
- signed-registry data model
- unit tests and GitHub Actions validation

## Security model

AWEp2P assumes peers and network transports are hostile. Private identity material is kept locally and is never part of the public AWE-ID. Passwords are verified with Argon2; the encrypted identity secret uses authenticated ChaCha20-Poly1305. Protocol data uses explicit versioning and deterministic length-prefixed encoding where canonical wire representation is required.

The core does not claim absolute security or anonymity. Production deployments still require OS hardening, secure key storage integration, transport security, external auditing and platform-specific security review.
