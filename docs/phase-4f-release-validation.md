# Phase 4F — Release Candidate Validation

Date: 2026-11-08. SDK version `0.1.0-alpha.1` (experimental).

## Crates

| Crate | Version | Intended publication |
|---|---|---|
| shadowallet-chain-core | 0.1.0-alpha.1 | yes |
| shadowallet-chain-utxo | 0.1.0-alpha.1 | yes |
| shadowallet-chain-bitcoin | 0.1.0-alpha.1 | yes |
| shadowallet-chain-litecoin | 0.1.0-alpha.1 | yes |
| shadowallet-chain-dogecoin | 0.1.0-alpha.1 | yes |
| shadowallet-chain-bitcoin-cash | 0.1.0-alpha.1 | yes |

Crate names returned HTTP 404 on crates.io (available) at validation time.

## Licensing

- Workspace license: MIT OR Apache-2.0; `LICENSE-MIT` and `LICENSE-APACHE`
  present.
- Direct/transitive dependencies use permissive licenses (CC0-1.0,
  MIT/Apache-2.0, BSD/ISC family). `bdk_*`/`rust-bitcoin` are CC0-1.0 or
  MIT/Apache-2.0; `ring` uses ISC-style terms. No GPL/AGPL dependency is
  introduced by the SDK.
- No third-party source was relicensed. `cargo deny` was not run in this
  environment; CI is configured to run it.

## Security validation

- `cargo audit` initially reported RUSTSEC-2026-0346/0349/0104/0098/0382/0099/
  0381 through the Esplora `rustls 0.21` / `rustls-webpki 0.101` path.
- Mitigation: Esplora TLS switched from `blocking-https-rustls` to
  `blocking-https-native` (platform TLS), removing the vulnerable rustls
  stack. Audit must be re-run after the lockfile update.
- SDK lints forbid `unsafe_code`, `unwrap_used`, `expect_used` and `panic`.
- Secret scan: no private keys, tokens or recovery phrases in source.
- External signer boundary: SDK accepts no seed/private key; the application
  signs exact digests/PSBTs after authorization.

## Independent build

- The SDK builds and tests standalone (`cargo test --workspace`,
  `cargo clippy`, `cargo fmt --check`).
- No sibling application path is referenced by any SDK crate.
- Path dependencies exist only between SDK crates and carry
  `version = "0.1.0-alpha.1"` metadata for publication.

## Packaging

- `cargo package -p <crate> --list` succeeds for all six crates.
- `cargo publish -p shadowallet-chain-core --dry-run` passed (packaged,
  verified, upload aborted by dry-run).
- Dependent crates cannot be dry-run until their SDK dependencies exist on
  crates.io; publishing order is:
  core → utxo → (bitcoin, litecoin, dogecoin, bitcoin-cash).
- CI/workflows exist for fmt, clippy, tests, docs, audit/deny, Linux/Windows/
  macOS.

## Unverified / blockers

- No native Windows or macOS execution on this host; CI is prepared.
- Mobile/WASM not claimed.
- No independent security audit.
- No GitHub account/organization or crates.io token was supplied, so Phase 4G
  and 4H cannot be executed. See the final report.
