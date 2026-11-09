# shadowallet-chain-evm 0.1.0-alpha.2 — NOT RELEASED

Status: release candidate only. Do not publish while RUSTSEC-2026-0387 is
unresolved and until release authorization is granted.

## Contents

- Alloy 1.8.3 EVM provider with mandatory chain-ID validation.
- BIP44 `m/44'/60'/0'/0/i` accounts; EIP-55 addresses; watch-only accounts
  cannot sign.
- EIP-1559 external signing (digest → app signature → finalize/broadcast).
- ERC-20 balance/decimals/symbol/name, metadata cache, canonical transfer and
  receipt `Transfer` validation.
- SQLite state (WAL): accounts, balances cache, nonces, transactions, tokens,
  sync checkpoints.
- Transactional nonce reservation/release/replacement/expiry/reconciliation.
- Outgoing-only history with explicit completeness; ERC-20 Transfer log range
  queries.
- Fee quote with base/priority/max fee, gas caps and checked total cost; BSC
  legacy and L2 L1 data-fee models fail closed.

## Evidence

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass.
- `cargo test --workspace`: pass.
- `cargo doc --workspace --no-deps`: pass.
- Anvil native and ERC-20 E2E: pass.
- `cargo package` and `cargo publish --dry-run`: pass.
- Raw `cargo audit`: pass, 0 vulnerabilities.
- `cargo deny check advisories`: pass.
- Independent EIP-155 and EIP-1559 vectors match `eth_account`.
- BSC legacy EIP-155 Anvil E2E: pass.
- Public read-only RPC matrix: pass.

## Blockers

- No fixed `crypto-bigint` release compatible with the Alloy/k256 0.13 graph.
- No public testnet validation, L2 fee modelling, WASM transport or audit.
