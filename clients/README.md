# AWEp2P communication clients

The shared Rust messenger protocol is transport/UI independent. Production clients MUST use the same AWE-ID identity and encrypted session protocol.

## Platforms

- Windows: native client shell around `awep2p-core`.
- Linux: native client shell around `awep2p-core`.
- Android: Android application shell around the same Rust core through a JNI/FFI boundary.

No email address, phone number, real name, or centralized account is required. AWE-ID is the contact primitive.

## Privacy model

Messages and attachments are encrypted before transport. Optional relay routes reduce direct peer metadata exposure, but do not claim perfect anonymity: IP-layer observers, compromised relays, timing analysis, and endpoint compromise can still reveal information.

Audio/video media must use authenticated encrypted media transport and should never be sent as plaintext. Call signaling uses the same encrypted message protocol.
