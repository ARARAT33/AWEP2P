# AWEp2P Official Platform Applications

This directory defines the production platform boundary for the shared `core` crate. No platform application requires a centralized AWE service for node, identity, Drive, Host, Store, Messenger, namespace resolution, diagnostics, recovery, or updates.

## Windows

`windows/` is the native desktop/service boundary. The service owns the long-lived node and exposes a local authenticated IPC boundary to the desktop UI. The installer is MSI/EXE-packaging-ready and binaries are signed as release artifacts.

## Linux

`linux/` contains the daemon/CLI boundary. The daemon is intended to run under systemd and the CLI communicates through a local Unix socket. Desktop clients use the same local API.

## Android

`android/` defines the native Android application boundary. Rust is embedded through JNI/UniFFI; Android owns lifecycle, foreground-service, battery and metered-network policy while the Rust core owns protocol and cryptographic state.

## AWEOS

`aweos/` is a stable ABI/protocol boundary. AWEOS can embed the same Rust core directly without translating the AWE protocol or depending on Windows/Linux/Android services.

## Shared responsibilities

All clients expose: node status/control, AWE-ID identity and recovery, AWEwww/AWEOpen, Drive, Host, Store, Messenger, resource quotas, security configuration, secret-free diagnostics/logs, update verification and recovery. Private keys never enter diagnostic logs.

## Signing

Release artifacts are reproducibly built by CI, signed with the platform's release key, and verified before installation. The package metadata includes version, target triple, artifact digest and signature. Key material is supplied through protected CI secrets and is never committed.
