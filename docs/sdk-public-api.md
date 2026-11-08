# Public API (0.1.0-alpha.1)

## `shadowallet-chain-core`

- `ChainId`, `NetworkId`, `NetworkClass`, `Balance`, `Confirmation`
- `SignRequest { chain, network, account_id, algorithm, public_keys, digests }`
- `ExternalSigner::sign(&SignRequest) -> Vec<Vec<u8>>` (DER ECDSA)
- `SignError`, `CoreError`

Digests are transaction sighashes. The SDK does not define a generic
message-signing API.

## `shadowallet-chain-utxo`

- `Utxo { txid, vout, value_sats, confirmations, keychain, index }`
- `UtxoBalance`, `UtxoHistoryEntry`, `SyncStatus`
- `FeePolicy::check(rate, fee, amount)` safety envelope
- `LargestFirst` coin selector
- `UtxoStore` persistence contract (implementations must not store keys)

## `shadowallet-chain-litecoin`

- `LtcNetwork::{Mainnet, Testnet, Regtest}`
- `LtcAccount::from_xpub(network, xpub, fingerprint)`
- `prepare_transfer(...) -> UnsignedTransfer` (rate-based fee)
- `signing_request(...) -> SignRequest`
- `finalize_transfer(account, unsigned, der_signatures) -> Transaction`
- `parse_unsigned(hex)`
- `engine::LtcEngine`: Core RPC sync, UTXO/history, SQLite, fee estimates,
  receive-address derivation, broadcast, status and rescan. Watch-only; it
  never accepts a seed or private key.

## `shadowallet-chain-dogecoin`

Same shape with `DogeAccount`, P2PKH/legacy SIGHASH_ALL and `engine::DogeEngine`.

## `shadowallet-chain-bitcoin`

- `BtcNetwork`, `AddressKind`, `WatchDescriptors`
- `BitcoinEngine`: Esplora/Core sync, balances/history, PSBT build, fee
  estimates, external `finalize_psbt`, broadcast and SQLite persistence.
- No seed or private descriptor is accepted.

## `shadowallet-chain-bitcoin-cash`

- CashAddr encode/decode, network validation
- BCH `SIGHASH_ALL|SIGHASH_FORKID` preimage and P2PKH signing
- Local verification, serialization and transaction commitment
- `engine::BchEngine`: BCHN Core RPC sync, SQLite, balances/history, fees,
  external ForkID signing/finalization, broadcast and rescan.

## Errors

All functions fail closed on wrong network/xpub, insufficient funds, fee policy
violation, premature signatures, signature-count mismatch and invalid
signatures. No function logs secret material.

## Concurrency

`LtcAccount`/`DogeAccount` are immutable and `Send + Sync`; builders are pure.
Signer implementations are caller-owned.
