# AWEP2P Engineering Charter

AWEP2P is a privacy-first, peer-to-peer networking and application platform. This document defines the engineering rules for turning the current Rust foundation into a deployable end-user ecosystem.

## Scope

Every development cycle reviews the whole repository except `platforms/linux/` and everything below it, which is intentionally out of scope for this automation lane.

The active target areas are `core/`, `apps/`, `platforms/windows/`, `platforms/android/`, `platforms/aweos/`, `.github/`, and the documentation/examples needed to make implemented behavior understandable and testable.

## Non-negotiable engineering rules

1. No fake success. APIs must never report that a packet was routed, a file was replicated, a WASM program was executed, a site was published, or a name was resolved unless the operation actually happened.
2. No fabricated topology. Peer IDs, replica assignments, availability, uptime, capacity and health must come from observed or cryptographically verified state.
3. Security claims are evidence-based. The project must not claim perfect anonymity, immunity from all deanonymization techniques, or guaranteed anonymity against every observer unless the property is formally established.
4. User data minimization is a design requirement. The core protocol must not require a phone number, email address, real name or centralized account record.
5. Secrets stay encrypted at rest by default. Plaintext secret export must always be explicit.
6. Cryptographic verification is mandatory for identity-bound records. Signatures, hashes, sequence numbers and replay protections must be checked at trust boundaries.
7. Local state is minimized on end-user devices. Durable user content should use encrypted, content-addressed, distributed storage where that feature is actually implemented; until then, code must describe local-only behavior honestly.
8. Production changes must include tests or a documented reason why an integration test is required at a higher layer.
9. Every change is validated by GitHub Actions. Main receives changes only from a coherent branch with green CI.
10. Daily work is incremental and production-oriented: fix a concrete gap, add measurable capability, improve failure handling, documentation or UX, and leave the repository in a more usable state.

## Layer roadmap

### Phase A — trustworthy foundation
Real authenticated peer handshakes, encrypted transport, replay protection, signed namespace records, content-addressed storage, erasure coding, honest capability boundaries, safe secret handling and deterministic protocol encoding.

### Phase B — real mesh
Persistent peer routing, iterative Kademlia-style lookup, peer liveness, routing-table refresh, NAT traversal, QUIC transport, multipath scheduling, LAN discovery and authenticated peer exchange.

### Phase C — distributed storage
Chunk manifests, real replica placement, encrypted shard transfer, replica health, repair/self-healing, garbage collection, resumable downloads, streaming and bandwidth-aware scheduling.

### Phase D — decentralized applications
AWE namespace resolution, distributed sites, signed app packages, app capability grants, sandboxed execution with a real WASM runtime, Messenger delivery, group state, Drive, collaborative documents, slides and sheets.

### Phase E — end-user platform
Native Browser, Messenger, Drive, Store, Mini Apps, Sites by Nodes, launcher, account-free onboarding, accessibility, crash recovery, offline mode, updates, package verification and polished cross-platform UX.

## Privacy architecture

The goal is to reduce the amount of information any single participant can learn. A relay should only learn the minimum routing information needed for its hop. Storage nodes should receive encrypted content-addressed objects rather than plaintext user files. Directory and manifest metadata should be separated from payload encryption wherever protocol semantics permit.

Privacy must still be described in threat-model terms. Timing correlation, traffic analysis, malicious peers, endpoint compromise, compromised relays and global observers are distinct threats and require distinct mitigations. The project should prefer measurable protections over absolute anonymity statements.

## Daily delivery loop

1. Inspect the complete in-scope tree and recent CI state.
2. Find the highest-impact real gap.
3. Implement a focused improvement without touching `platforms/linux/`.
4. Add or update tests, CI checks and documentation.
5. Create a branch and pull request against `main`.
6. Merge only after CI is green and the diff is coherent.
7. Record the change in the project changelog/status documentation.

AWEP2P should grow as a real system, not as a collection of placeholders.
