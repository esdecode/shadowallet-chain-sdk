# Phase 5 — EVM SDK Report

Status: **EXPERIMENTAL — SDK + Shadowallet Anvil integration; not published.**

## Implementation

- Crate `shadowallet-chain-evm` (Alloy 1.8.3, bip32 0.5.3, MSRV 1.88).
- Chain profiles: Ethereum, Sepolia, Polygon, BSC, Arbitrum, Optimism, Base,
  Anvil (chain IDs 1, 11155111, 137, 56, 42161, 10, 8453, 31337).
- BIP44 `m/44'/60'/0'/0/i` account derivation and EIP-55 address display.
- Alloy HTTP provider with mandatory `eth_chainId` verification.
- Native balance, pending nonce, gas price, EIP-1559 fee estimation, gas
  estimation, `eth_call`.
- External EIP-1559 signing: SDK exposes `signature_hash()`, application signs,
  SDK finalizes/encodes EIP-2718 and broadcasts.
- ERC-20 `balanceOf`, `decimals`, `symbol`, canonical `transfer` calldata,
  external signing and receipt tracking.
- Safety limits: gas cap, value+gas balance check, canonical calldata.

## Verified

- Unit: chain profile uniqueness, known Anvil key address, deterministic
  derivation.
- Anvil native transfer E2E: pass.
- Anvil ERC-20 deploy/transfer E2E: pass.
- UTXO SDK regression: pass.

## Not implemented

- External indexer; incoming native history is not provided.
- Public testnet/mainnet validation.
- BSC legacy transaction path.
- L2 L1 data-fee modelling (Arbitrum/OP/Base).
- Sepolia/public testnet validation.
- WASM transport/key custody.

## Security blocker

`cargo audit` reports RUSTSEC-2026-0387 (`crypto-bigint 0.5.5` timing
variability) in the transitive Alloy/k256 stack. Do not publish this crate until
the dependency is upgraded or the advisory is explicitly accepted after review.
