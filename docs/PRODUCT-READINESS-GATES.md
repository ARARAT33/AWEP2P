# AWEP2P Product Readiness Gates

Check an item only when code and repeatable evidence demonstrate it.

## Node lifecycle
- [ ] Clean supported-machine install and first launch.
- [ ] Create/import identity without a central account.
- [ ] Start, inspect, and stop the node without a terminal.
- [ ] Restart preserves identity and durable state; corruption is recoverable.
- [ ] Disk, bandwidth, CPU, memory, and battery policies are enforced.

## Peer networking
- [ ] Independent processes authenticate over real sockets.
- [ ] Peer state is based on observed connections and validated identity.
- [ ] Disconnects, timeouts, malformed frames, and reconnects are tested.
- [ ] Discovery survives loss of one discovery source.
- [ ] Multi-hop requests traverse connected peers with bounded hops, correlation, and replay protection.
- [ ] NAT traversal and relay are advertised only after real connectivity tests.

## Distributed Drive
- [ ] Private data is encrypted before leaving the owner device.
- [ ] Upload sends actual shards to remote authenticated peers.
- [ ] Shards are acknowledged only after integrity verification and durable write.
- [ ] Download fetches remote shards and reconstructs the original bytes.
- [ ] Interrupted transfers resume safely.
- [ ] Replica loss is detected from fresh health evidence.
- [ ] Repair moves/rebuilds actual bytes, verifies persistence, and commits metadata safely.
- [ ] Local, remote, missing, and unknown replicas are distinguished.

## Names, hosting, and apps
- [ ] Registry records pass signature, sequence/freshness, and ownership checks.
- [ ] Names resolve from verified records, not UI-only or hard-coded state.
- [ ] Sites are fetched from remote nodes using versioned manifests and content hashes.
- [ ] Store packages are verified before installation.
- [ ] App permissions are enforced at runtime.
- [ ] WASM is advertised only when a real runtime executes it under limits.

## Messenger
- [ ] Delivery state requires remote acknowledgement.
- [ ] Offline delivery, retry, duplicate suppression, and recovery are tested.
- [ ] Attachments use verified transfer and bounded storage.
- [ ] Voice/video are advertised only when encrypted media transport works end to end.

## User experience and release
- [ ] Desktop launches without a terminal; UI and CLI report consistent core state.
- [ ] Onboarding, accessibility, errors, and resource controls are usable.
- [ ] Logs/diagnostics exclude secrets and private content.
- [ ] Backup, identity recovery, upgrade, and rollback are tested.
- [ ] Windows/Linux builds are reproducible in CI; Android is validated on declared devices/toolchains.
- [ ] Artifacts include version, target, checksum, signing metadata, and release limitations.
- [ ] Clean-machine install and uninstall are tested.

## Automated evidence
- `cargo fmt --all -- --check` must pass in CI without a write-back formatter job.
- `cargo check --workspace --all-targets`, `cargo test --workspace --all-targets`, and `cargo clippy --workspace --all-targets -- -D warnings` are required gates.
- The node product smoke test starts three independent node processes, verifies their HTTP health APIs, authenticates peer connections, and exercises replicated storage through the real process boundary.

## Status rule
A checked box requires a linked test, CI run, or reproducible operator procedure. A module existing or compiling is not enough. The current classification and work tracks are in [daily status](AWEP2P-DAILY-STATUS.md).