# Phase 5.1 Final Report (SDK)

## Implemented

- Persistent SQLite state: accounts, balance cache, nonces, transactions,
  tokens, sync checkpoints; WAL, busy timeout, integrity check, migration guard.
- Nonce: atomic reservation, release, replacement, expiry, reconciliation,
  restart recovery, concurrent reservation test.
- History: `HistorySource`, `LocalHistory` (OutgoingOnly), ERC-20 `Transfer`
  log decoding, pagination, deduplication by row id.
- Fees: base/priority/max fee, caps, checked max cost; BSC legacy and L2 L1
  data-fee models fail closed.
- ERC-20: balance, decimals, symbol, name, bytes32 fallback, metadata cache,
  canonical transfer, receipt Transfer validation.
- Security: watch-only accounts cannot sign; digest binds all transaction
  fields; malformed signatures and fee overflow rejected.
- Release candidate `shadowallet-chain-evm 0.1.0-alpha.2` (unpublished).
  `cargo package` and `cargo publish --dry-run` pass.

## Security advisory

RUSTSEC-2026-0387: `crypto-bigint 0.5.5` via Alloy → k256 0.13.4 →
elliptic-curve 0.13.8. The advisory requires >=0.7.6; no 0.5.x/0.7.6 release
exists, and Alloy 2.5 still resolves k256 0.13. EVM publication is blocked.

## Verified

- `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`,
  `cargo doc`: pass.
- Anvil native and ERC-20 E2E: pass.
- `cargo audit`: 1 vulnerability (above), 3 allowed warnings.
- `cargo deny`: not run; slim image lacks git for advisory DB.

## Not verified

- Sepolia/public networks: no RPC endpoint or disposable funds.
- L2 fee modelling, WASM transport, independent audit.
- Windows/macOS/Android/iOS native EVM builds.

## Git

Local `master` only. No push, tag, release or crates.io publication.
