# EVM Protocol Implementation Notes

## Specifications

- Yellow Paper: transaction fields, RLP, Keccak-256.
- EIP-55: mixed-case checksum.
- EIP-155: legacy replay protection (`v = chain_id*2 + 35 + parity`).
- EIP-2718: typed envelope (`0x02` for EIP-1559).
- EIP-1559: `[chain_id, nonce, max_priority_fee, max_fee, gas, to, value,
  data, access_list]` signing payload.
- Solidity ABI: selector + 32-byte words; dynamic string offset/length.
- ERC-20: `balanceOf`, `decimals`, `symbol`, `name`, `transfer`.

## RLP

Encoding uses `parity rlp` with explicit minimal integer encoding:

- `0` → empty byte string.
- Integers omit leading zero bytes.
- Addresses are 20-byte strings; contract creation uses an empty `to`.
- Empty calldata is an empty byte string.
- Outer list length transitions at 56 bytes (`0xf8` long-list prefix).

Decoding is intentionally not part of the public SDK surface; inbound RLP is
never accepted as a signing authorization. Tests parse serialized output with
the independent `rlp` decoder to assert list shape and field values.

## Signing

- libsecp256k1 `sign_ecdsa_recoverable` with RFC6979 nondeterminism removed by
  the library; low-S normalization is enforced.
- 65-byte signature is `r || s || parity` (parity 0/1).
- `finalize` validates the compact signature and parity before serialization.
- Transaction hash is Keccak-256 of the final envelope.

## Test evidence

- `tests/security.rs`: independent EIP-155/EIP-1559 vectors, BIP39/BIP44
  address vector, low-S and recovery, receipt binding.
- `tests/properties.rs`: proptest canonical shape, chain isolation,
  determinism, checksum round-trip, RLP empty/small values, long-list boundary.
- `tests/anvil_*.rs`: native, ERC-20, BSC legacy E2E.
- `fuzz/`: bounded libFuzzer targets for finalize, ABI string and checksum.
