# Phase 5.1 Overnight Progress

Updated 2026-11-08.

## Done

- Investigated RUSTSEC-2026-0387: `crypto-bigint 0.5.5` via
  `k256 0.13.4`/`elliptic-curve 0.13.8` from Alloy. No patched 0.5.x or 0.7.6
  release exists; Alloy 2.5 still resolves k256 0.13. Kept EVM unpublished.
- Persistent SQLite store: accounts, nonces, transactions, tokens, sync
  checkpoints; WAL, busy timeout, integrity check, schema version.
- Transactional nonce reservation, release, replacement, expiry, restart
  recovery and reconciliation.
- History abstraction with explicit `OutgoingOnly` completeness; local
  pagination; ERC-20 `Transfer` log decoding.
- Fee quote: base fee, priority, max fee, gas caps, checked max cost; L2/BSC
  fail closed.
- ERC-20 `name`, metadata cache, bytes32 fallback, receipt Transfer validation.
- Watch-only `EvmAccount` can no longer sign (random-signer bug fixed).
- Security tests: digest binding, malformed signature, fee overflow.
- Anvil native E2E with nonce reservation, store persistence and restart.
- Anvil ERC-20 E2E with metadata, receipt binding, log decoding.

## Commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
ANVIL_RPC_URL=http://127.0.0.1:8545 \
  cargo test -p shadowallet-chain-evm -- --ignored
```

## Remaining

- EVM crate publication blocked by RUSTSEC-2026-0387 and no release approval.
- Sepolia/public testnet validation (no RPC/funds).
- L2 L1-data-fee modelling.
- WASM transport.
- Independent audit and cross-platform native EVM builds.
