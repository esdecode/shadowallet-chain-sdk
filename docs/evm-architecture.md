# EVM Architecture

Crate: `shadowallet-chain-evm` (libsecp256k1 0.31, primitive-types, parity RLP, MSRV 1.88). No Alloy dependency remains.

## Layers

- `EvmChain` profiles: chain ID, native symbol/decimals, EIP-1559 support,
  confirmation policy.
- `EvmAccount`: BIP-32 `m/44'/60'/0'/0/i` derivation from BIP-39 seed bytes;
  public address + application-controlled digest signing.
- `EvmProvider`: raw JSON-RPC provider; verifies `eth_chainId` on connect.
- Signing uses `secp256k1` (libsecp256k1), independent of any Alloy graph.
- Transaction RLP, EIP-155/1559 signing payloads, EIP-2718 envelopes and ERC-20
  ABI encoding are implemented in this crate and match independent
  `eth_account` vectors.
- `UnsignedEvmTransaction`: canonical EIP-1559 fields + signing digest.
- `Erc20Token`: `balanceOf`, `decimals`, `symbol`, canonical `transfer` calldata.
- External signing: SDK returns `signature_hash()`, app signer returns a 65-byte
  signature, SDK finalizes and encodes EIP-2718 bytes.

## Security boundary

The SDK accepts no mnemonic or private key for watch-only provider operations.
`EvmAccount::from_seed` exists for local examples/tests; the Shadowallet vault
must keep seed/private-key handling app-side and call `sign_digest` only after
proposal authorization.

The provider is untrusted: chain ID is checked; the node cannot alter the
unsigned transaction after the application commits to it.
