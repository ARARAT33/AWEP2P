# AWEp2P

AWEp2P is a sovereign, privacy-first, cross-platform peer-to-peer network for AWEwww, AWETLD, AWEOpen, decentralized storage, hosting, applications, messaging, and node infrastructure.

## Project principles

- **Node-first:** the network lives on user-controlled devices. There is no mandatory centralized hosting layer.
- **Self-hostable:** every major service can run on a user's own node.
- **Privacy-first:** no email, phone number, real name, IP address, or other unnecessary personal information is part of the AWE identity model.
- **Cryptographic ownership:** identities, domains, TLDs, packages, manifests, permissions, and governance actions are signed.
- **Cross-platform:** Windows, Linux, Android, and eventually AWEOS share the same Rust protocol/core.
- **Open protocol:** implementations should be interoperable rather than tied to one server.

## Main systems

### AWE Network

- encrypted peer-to-peer transport
- peer discovery and DHT routing
- NAT traversal / relay support
- node health and capability discovery
- signed protocol messages
- resource contribution controls
- LAN / local mesh discovery where supported

### AWE Identity

- username-based human-facing identity
- locally protected credentials
- device cryptographic identity
- public/private key separation
- challenge-response authentication
- encrypted local identity vault
- recovery/export mechanism designed to avoid a central account authority

### AWEwww

AWE's decentralized namespace and application layer.

- `AWETLD` — top-level-domain registry
- `AWEOpen` — resolver/browser/opening layer for registered TLDs and domains
- signed registry snapshots
- domain ownership records
- domain lifecycle and status records
- resolver protocol

### TLD governance model

The initial policy model contains:

- **OTLD:** ordinary user TLD; default limit of 10 domains per account
- **3OTLD:** open TLD where network users can create domains according to network policy
- **CTLD:** community TLD created by an eligible registered user; the creator approves domain creation
- **OATLD:** delegated manager role for eligible OTLD operators, including domain moderation and a default 100-domain management capability
- **OCTLD:** delegated manager role for CTLD operators, including domain approval/deletion and configurable account limits
- **VTLD:** trusted delegated TLD operator role with a dedicated administration interface
- **AUTL:** AWE User TLD assigned by the network's highest authority to a specific user, e.g. `ararat.autl`
- **ATLD:** highest administrative authority and policy namespace
- `.awea`: reserved administrative namespace for the highest-authority control plane

All privileged actions must be capability-based, signed, auditable, and revocable. No UI-only or hard-coded permission is sufficient for security-critical operations.

### AWE Drive

Private distributed storage with client-side encryption.

- files are encrypted before leaving the owner device
- content is content-addressed and split into chunks
- placement metadata is represented by an encrypted manifest for private data
- public archives may expose a public manifest
- configurable replication and erasure-coding policies
- automatic repair/re-replication when replicas disappear
- integrity verification using hashes/MACs/signatures
- resumable upload/download
- streaming for supported media

The design must not assume that a file is always exactly 1,000 or 10,000 chunks. Chunk size, shard count, redundancy, and placement are policy parameters selected according to file size and network conditions.

### AWE Store

A decentralized application distribution system.

- signed packages
- package manifests
- versioning
- dependency metadata
- publisher identity
- permission declarations
- integrity verification
- optional WASM sandbox for portable applications
- P2P package distribution
- configurable local/network storage policy

### AWE Host

A peer-to-peer hosting service in which users can publish content from their own nodes.

- domain-to-content resolution
- replicated hosting
- health checks
- failover
- local/self-hosted operation
- configurable resource limits

### AWE Messenger

Privacy-first P2P communications.

- end-to-end encrypted text
- voice messages
- voice calls
- video calls
- encrypted file transfer
- groups
- presence kept minimal and privacy-aware
- optional privacy relays/onion-style routing

Traffic privacy must never be described as an absolute guarantee: transport metadata, operating-system behavior, relays, and network conditions can still leak information. The implementation should minimize metadata by design.

### Node

Every installed AWEp2P client can become a node.

Two contribution modes are supported:

1. **Recommended automatic profile** — safe defaults based on available storage, RAM, bandwidth, and platform constraints.
2. **Advanced manual profile** — the user explicitly selects storage, bandwidth, CPU/GPU, hosting, relay, and other contributions.

Android must support battery-aware and charging/Wi-Fi-only policies. Desktop nodes may run continuously as services/daemons.

## Security architecture

Security is based on zero-trust assumptions:

- every peer is potentially hostile
- encryption is mandatory for private content
- permissions are capability-based
- privileged actions require signed authorization
- manifests are authenticated
- chunks are independently integrity-checked
- replay protection and sequence/nonce rules are required
- rate limits and abuse controls are node-local and protocol-aware
- secrets never enter logs
- private keys remain in protected local storage

AWEp2P does not promise impossible "100% security" or perfect anonymity. The goal is a formally specified, audited, defense-in-depth architecture with minimal data collection and no unnecessary central authority.

## Repository architecture

```text
AWEP2P/
├── core/                 # Rust protocol/core
│   ├── identity/
│   ├── crypto/
│   ├── protocol/
│   ├── network/
│   ├── discovery/
│   ├── dht/
│   ├── permissions/
│   ├── reputation/
│   └── node/
├── awwww/                # AWEwww namespace layer
│   ├── awetld/
│   ├── aweopen/
│   ├── registry/
│   ├── resolver/
│   └── domains/
├── drive/                # distributed storage
│   ├── encryption/
│   ├── chunking/
│   ├── erasure/
│   ├── replication/
│   └── manifest/
├── messenger/            # encrypted communications
├── store/                # application distribution
├── host/                 # decentralized hosting
├── node/                 # node service/daemon
├── clients/
│   ├── windows/
│   ├── linux/
│   └── android/
├── aweos/                # future AWEOS integration
├── bootstrap/            # discovery bootstrap metadata/services
├── registry/             # signed registry schemas/snapshots
├── protocol/             # protocol specifications
├── docs/
├── tests/
└── .github/workflows/
```

## Protocol namespaces

The protocol is versioned independently from UI applications:

```text
/awe/identity/1
/awe/discovery/1
/awe/dht/1
/awe/registry/1
/awe/domain/1
/awe/storage/1
/awe/messenger/1
/awe/store/1
/awe/host/1
/awe/node/1
```

Protocol messages must be canonical, versioned, authenticated where required, and protected against replay/downgrade attacks.

## Registry model

GitHub is a distribution and public mirror location for registry snapshots and source code. It is **not** the sole runtime authority for the P2P network.

A registry record should contain enough information to verify:

- object identity
- owner/controller public key
- object type
- status
- version/sequence
- creation/update timestamp where appropriate
- policy references
- cryptographic signature
- previous record/hash linkage where applicable

Nodes independently verify registry data and reject invalid or stale records according to the protocol.

## Platform targets

### Windows

Native node service plus desktop management UI.

### Linux

Native daemon, CLI, and optional desktop UI. systemd integration is planned.

### Android

Native application with foreground/background service policies, battery/network controls, and explicit resource contribution settings.

### AWEOS

AWEp2P will eventually become a native AWEOS networking/storage/application subsystem using the same protocol and Rust core instead of a separate implementation.

## Development order

The project should be implemented in dependency order rather than attempting every UI feature simultaneously:

1. protocol specification and threat model
2. cryptographic identity and local vault
3. authenticated node-to-node transport
4. peer discovery and DHT
5. signed registry primitives
6. AWETLD/domain records and resolver
7. node resource manager
8. encrypted chunked storage
9. replication/repair and erasure coding
10. AWE Host
11. AWE Store
12. AWE Messenger
13. Windows/Linux node applications
14. Android node application
15. AWEOpen/AWEwww clients
16. AWEOS integration
17. interoperability, fuzzing, security testing, and performance testing

## License

License and contribution policy will be defined before the first public protocol release.
