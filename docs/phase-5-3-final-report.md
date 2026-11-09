# Phase 5.3 Final Report (SDK)

## Security

- All Alloy dependencies removed. `cargo audit` raw: clean (313 packages).
- `cargo deny check`: advisories/bans/licenses/sources pass (only unused
  allowance warnings).
- `crypto-bigint` is 0.7.11 only (via bip32 → k256 0.14); 0.5.5 is absent.
- Signing uses libsecp256k1 0.31; EIP-155 and EIP-1559 outputs match independent
  `eth_account` vectors.
- RPC: 15 s timeout, 2 MiB response cap, HTTP 429 classification, chain-ID pin,
  no automatic retry of non-idempotent calls, broadcast hash from provider.
- Ambiguous broadcast retains nonce; cross-connection nonce locking tested.

## SDK

- Native ETH, ERC-20 transfer, BSC legacy EIP-155 Anvil E2E pass.
- Public read-only RPC pass for Sepolia, Polygon, BSC, Arbitrum, OP, Base.
- Package: `shadowallet-chain-evm 0.1.0-alpha.2`; package and publish dry-run pass.
- No publication or push.

## Limitations

- Android/iOS/macOS builds not run.
- No funded Sepolia account; no public-network signing.
- L2 L1 data fees not modelled; L2 sends fail closed.
- No independent audit.
