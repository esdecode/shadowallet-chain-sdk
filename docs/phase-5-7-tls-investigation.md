# Phase 5.7 TLS Investigation

## Root cause

- Published Bitcoin SDK used `bdk_esplora/blocking-https-native` → `minreq` →
  `native-tls` → OpenSSL.
- Android OpenSSL cross-build failed.
- Switching only the feature to `blocking-https-rustls` selected `minreq`'s
  rustls 0.21 stack (7 advisories).
- Removing the SDK rustls feature was insufficient because the wallet's
  `adapter-bitcoin` still enabled `bdk_esplora/blocking-https-rustls`.

## Selected solution

Use BDK's **async** Esplora transport with reqwest + rustls 0.23:

- `bdk_esplora` features: `std`, `async-https-rustls`, `tokio`.
- `shadowallet-chain-bitcoin` uses `build_async()` and a small Tokio
  current-thread runtime for `full_scan`, `broadcast`, and fee estimates.
- `adapter-bitcoin` no longer supplies its own `bdk_esplora` feature; the SDK
  owns the transport feature set.
- No `minreq` TLS path is active; `cargo tree` shows rustls 0.23.46 only.

## Evidence

- SDK `cargo audit`: clean (330 packages).
- SDK `cargo deny`: advisories pass.
- App `cargo audit`: clean; app `cargo deny check advisories`: pass with
  `unmaintained = "workspace"` (Linux D-Bus maintenance warnings are transitive).
- HTTPS Esplora fee estimates: pass.
- Public Esplora full scan to tip: pass.
- Android FFI rebuilt without OpenSSL.
- App `flutter build apk --debug` and `--release` pass.

Rejected: rustls 0.21 blocking transport (7 advisories), vendoring registry
sources, disabling certificate validation, HTTP fallback.
