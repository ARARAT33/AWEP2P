# AWENET Creator and Ephemeral Micro-Node Design

## Creator Studio — current implementation boundary

Creator Studio submits an app manifest and file payload to the local node API. The node builds an `AWEPackage`, signs its manifest with the local AWE identity, validates the package integrity, and stores it in the local AWEStore catalog. Supported manifest kinds are WebAssembly, Windows, Linux and Android.

This is **local-store publication**, not yet global marketplace replication, payment settlement, or sandboxed app execution. A package must not be described as globally available until authenticated replication and retrieval from another independent node are implemented and tested.

## Resource-pressure strategy

AWENET should use temporary, quota-limited micro-nodes to add capacity when demand exceeds the stable network pool. This is a scheduler design, not a claim that the current runtime already spawns temporary workers.

1. **Measure demand and capacity.** Track queued jobs, free storage, CPU/RAM pressure, bandwidth, latency and recent failures. Keep a configurable reserve on each host; do not assign the host's full resources to AWENET.
2. **Voluntary enrollment.** A user explicitly opts in and sets hard limits for storage, CPU, RAM, bandwidth and maximum lease duration. No worker may read arbitrary personal folders; only an AWENET-owned sandbox directory is eligible.
3. **Lease-based workers.** Each micro-node receives a short lease (initially 10 minutes) and must renew it with signed heartbeats. A worker that misses renewals stops receiving new work and is shut down after a bounded grace period.
4. **Quota enforcement.** Enforce OS-level process, memory, CPU-time, file-size, network-rate and disk quotas. Reject a job if the host cannot enforce the requested limits. Never use a UI-only limit as a security boundary.
5. **Demand-driven placement.** When the stable pool crosses a pressure threshold, rank eligible workers by measured capacity, trust, latency, failure rate and remaining lease. Place only independently verifiable, restartable tasks on ephemeral workers.
6. **Safe expiry.** Stop accepting work before lease expiry, checkpoint only to a verified AWENET-owned store, finish or cancel active work, revoke worker credentials, and delete only the worker's sandbox. Never automatically delete the user's source files.
7. **Rewards after proof.** ONECOIN rewards require signed usage receipts and independent validation. Declared capacity alone must not mint rewards. Avoid paying for self-reported CPU, storage or uptime.
8. **Abuse and overload controls.** Apply per-AWEID quotas, global admission control, deduplication, resource budgets, back-pressure and circuit breakers. A larger user count must not cause every device to be fully occupied.

## Required implementation sequence

- [x] Local Creator UI for metadata, entry path, declared capabilities, file selection and optional ONECOIN price.
- [x] Local API route to create, sign, verify and store AWEStore packages.
- [ ] End-to-end tests: publish a valid WASM package, reject malformed WASM, reject unsafe paths, tampered package and invalid manifest, then read the package back from catalog.
- [ ] Authenticated package replication and remote catalog discovery across two independent nodes.
- [ ] Sandboxed WASM execution with explicit capability grants and resource limits.
- [ ] OS-specific micro-worker runner with hard quotas and signed lease/heartbeat protocol.
- [ ] Demand monitor, scheduler, graceful expiry, crash recovery and independent usage receipts.
- [ ] Multi-node tests under constrained resources, disconnects, malicious packages and expired leases.

## Security constraints

- Never promise files are undeletable by the operating-system owner. Prefer application-level retention, integrity verification, backups and explicit deletion workflows.
- Do not auto-enroll a device into CPU/GPU work without informed opt-in and clear limits.
- Never execute uploaded native binaries just because they were published. Package signing and integrity checks do not prove software is safe.
- A local package signature proves which local identity signed the manifest; it does not by itself prove the developer is trustworthy or that the package is globally replicated.
