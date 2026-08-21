# AWEOS native integration boundary

AWEOS integrates the same AWEp2P Rust core directly. The boundary is deliberately protocol-first: AWEOS supplies filesystem, process, networking, UI and device APIs; the core supplies AWE-ID, P2P transport, AWETLD/AWEOpen, Drive, Host, Store and Messenger protocols.

No Windows, Linux or Android runtime is required by AWEOS. The integration must preserve the same canonical serialization, protocol versions, cryptographic identities and capability model so an AWEOS node interoperates with all other AWEp2P nodes.

The native boundary consists of:

- `AweNodeRuntime` lifecycle
- `AweIdentityProvider` secure key storage
- `AweNetworkProvider` socket/QUIC primitives
- `AweStorageProvider` persistent encrypted objects
- `AweProcessProvider` Store/WASM sandbox
- `AweMediaProvider` microphone/camera
- `AweUiProvider` AWEOpen, Drive, Host, Store and Messenger UI

AWEOS must never expose private keys to the UI or diagnostic logger.
