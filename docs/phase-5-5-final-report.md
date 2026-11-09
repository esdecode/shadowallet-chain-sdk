# Phase 5.5 Final Report (SDK)

## Android

- Complete wallet FFI is built by the wallet workspace, not this SDK crate.
- `shadowallet-chain-evm` and the full SDK compile for arm64-v8a and x86_64.

## iOS/macOS

- `shadowallet-chain-evm` Apple target checks fail without Apple SDK (`xcrun`).
- macOS CI matrix exists in `.github/workflows/ci.yml`; no executed macOS run
  is available from this Windows host.

## Security

- Raw `cargo audit`: clean (326 packages).
- `cargo deny`: advisories/bans/licenses/sources pass.
- Protocol vectors, property tests and 60,000 fuzz executions pass.

## Status

- EXPERIMENTAL SDK RELEASE: **PARTIALLY VALIDATED**.
  Package/dry-run, audit, vectors, fuzz and Anvil pass; iOS/macOS platform
  verification and independent audit remain.
- No publication or push.
