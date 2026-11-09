# EVM Release Readiness

Status: **NOT READY FOR EXPERIMENTAL SDK RELEASE** — protocol and audit gates pass; platform matrix is incomplete.

## Resolved / verified

- RUSTSEC-2026-0387 affected package `crypto-bigint 0.5.5` is no longer in the
  compiled SDK or app dependency graph. `cargo tree -i crypto-bigint@0.5.5`
  and `k256@0.13.4` print nothing.
- Signing uses `secp256k1` 0.31 (libsecp256k1); Alloy provider/signer/network
  stack was removed. Transaction types, ABI and EIP-2718 encoding remain Alloy.
- BIP32 0.6 uses k256 0.14 / crypto-bigint 0.7.11, which is patched.
- Native, ERC-20, and BSC legacy EIP-155 Anvil E2E pass.
- Nonce ambiguity, corruption, restart, concurrency and scope tests pass.

## Blockers

- Alloy core/primitives/consensus/ABI were removed entirely. Transaction RLP,
  EIP-155/1559 signing payloads and ERC-20 ABI encoding are implemented in the
  crate; signing uses libsecp256k1.
- Raw `cargo audit`: **clean** (no vulnerabilities, no ignores).
- `cargo deny check advisories`: **clean**.
- No funded Sepolia account; public RPC read-only was validated.
- L2 L1 data fees not modelled.
- No independent security audit.
- EVM crate remains unpublished; no release authorization.
- Flutter verified separately (analyze clean, 12 tests passed, 11 skipped).
