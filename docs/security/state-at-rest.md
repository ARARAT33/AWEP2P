# Encrypted state at rest

AWEP2P node state can contain identity-linked metadata and storage allocation details. The `awep2p_core::secure_state` module provides an authenticated encrypted JSON envelope using Argon2id-derived keys and ChaCha20-Poly1305.

Use `save_json`/`load_json` for state that must not be written as plaintext. The passphrase is required by the caller and is never persisted by this module. An incorrect passphrase or modified ciphertext fails closed.

This is confidentiality and integrity for the file contents; it is not a claim of anonymity, secure key storage, or protection against a compromised host account. Platform clients should obtain the passphrase from an OS credential/keychain facility before integrating it into default node-state persistence.
