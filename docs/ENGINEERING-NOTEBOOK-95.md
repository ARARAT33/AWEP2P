# AWEP2P 95% Engineering Notebook

Date: 2026-10-04
Branch: autonomous-95-code
Base: c6d8e57743257fcfa7cd041102597173e9eade18

## Rule for this phase

Write production code and connect the architecture first. Do NOT execute the test suite in this phase. Tests remain queued for the next validation pass.

## Target

Raise code-level completeness toward the 95% target without pretending that Internet/NAT/clean-machine evidence has passed. External validation is intentionally left for the next phase.

## Dependency map

Identity/Crypto -> authenticated Network -> Discovery -> Routing -> Topology -> relay/failover
Identity/Crypto -> Data plane -> Storage -> Replication -> Repair
Identity/Crypto -> Messenger crypto -> Messenger runtime -> ACK -> offline queue -> retry/backoff
Namespace/Registry -> Host/Sites
Store -> signed package -> capability grant -> install/rollback
Policy -> Permissions -> Sandbox
NAT candidates -> bounded UDP hole punch
Desktop bundle -> bundled awe-node -> local UI

## Completed in this phase

### 1. Messenger runtime hardening

core/src/messenger_runtime.rs now connects bounded offline storage, duplicate suppression, explicit Queued/Sent/Delivered/Read lifecycle, remote-ACK semantics, bounded retries, exponential backoff, attachment limits, and relay-route validation.

The node HTTP messenger path now waits for an application-level `awe.messenger.ack.v1` from the recipient before reporting `delivered`; a transport send alone is no longer treated as delivery.

### 2. NAT transport primitives

core/src/nat.rs adds bounded endpoint candidates, deterministic candidate ordering, short-lived challenge tokens, UDP probe/response framing, bounded simultaneous probe attempts, and timeout-bounded hole-punch coordination.

This is a transport primitive, not a claim that arbitrary consumer NATs have been proven.

### 3. Module wiring

core/src/lib.rs exposes the NAT layer so product/network code can consume the same transport contract instead of creating a second implementation.

## Existing architecture kept intact

- authenticated encrypted TCP transport
- signed discovery announcements
- iterative routing primitives
- 1000-shard / 3-replica storage policy
- real remote shard transfer and ACK flow
- autonomous peer supervision
- autonomous storage repair
- local fail-closed policy
- Store package signatures and capability checks
- namespace/host foundations
- Tauri desktop bundle and bundled node

## Next validation pass (intentionally NOT executed now)

1. workspace compile/check
2. unit/integration tests
3. product smoke
4. three independent nodes
5. remote storage reconstruction
6. messenger delivery/retry across process boundaries
7. NAT candidate exchange and real hole-punch
8. remote site resolution
9. Store install/rollback/capability enforcement
10. clean-machine desktop launch

## Important boundary

A source-level implementation percentage is not the same as operational readiness. The 95% target here means the code paths and contracts are substantially connected; Internet/NAT diversity, real-device behavior and clean-machine installation still require evidence from execution.

### 7. CI/CD hardening and runtime activation (2026-10-04)

- Workspace CI now validates PRs and main changes with unified workflow triggers, bounded concurrency, Rust build caching, architecture boundary checks, and the 95%-phase modules explicitly required.
- Cross-platform product CI now validates desktop builds on Windows/Linux/macOS plus Android APK/AAB on pull requests, while version tags publish release artifacts with checksums and a release manifest.
- Desktop release packaging now covers Windows, Linux, macOS Intel and Apple Silicon, plus portable Windows/Linux packages, with distributable-only latest-release publishing.
- Windows binary/product workflows now use the same checkout/toolchain/cache conventions and expose deterministic artifacts.
- The node now owns a live `MessengerState`: message IDs receive monotonic runtime sequences, enter the bounded offline queue, transition to Sent after transport submission, transition to Delivered only after the recipient ACK, and remain retryable with bounded exponential backoff when the ACK is absent.
- Messenger runtime envelopes are now accepted by the node dispatcher with recipient validation and replay-window enforcement before an application ACK is emitted.
- The implementation phase still intentionally does not execute tests; tomorrow's validation phase must verify compilation, workflow runs, multi-node delivery/retry, NAT behavior, desktop installation, and real product gates.
