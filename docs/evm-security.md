# EVM Security Model

- Chain ID is verified by the provider before any operation.
- The unsigned EIP-1559 transaction commits chain ID, nonce, recipient, value,
  calldata, gas limit, max fee and priority fee.
- The application signs only `UnsignedEvmTransaction::signature_hash()`.
- `finalize` rejects malformed 65-byte signatures.
- ERC-20 calldata is generated from decoded `transfer(address,uint256)`, never
  accepted as opaque user input.
- Gas limit over 1,000,000 (5,000,000 for deployment) and fee cost exceeding the
  native balance are rejected before signing.
- No arbitrary contract calls, approvals, permits or EIP-712 signing are exposed.
- Provider responses are untrusted; balances/fees are display data, not signing
  authorization.
- Mainnet/public signing/broadcasting remains disabled in Shadowallet.
- Signing uses libsecp256k1 (`secp256k1` 0.31). Alloy and the advisory-affected
  `crypto-bigint 0.5.5` graph are absent; raw `cargo audit` is clean.
- Ambiguous broadcast outcomes retain the nonce; they are never auto-released.

- Persistence stores only public wallet state; no seed or private key columns.
- Nonce reservations are transactional and release only the highest unbroadcast
  row.
- L2 L1-data-fee components are not modelled; those chains fail closed.
- Historical gaps: no public-testnet validation, no independent audit, and the
  RUSTSEC-2026-0387 `crypto-bigint 0.5.5` advisory remains unresolved.
