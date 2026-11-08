# Changelog

## 0.1.0-alpha.1 (2026-11-08)

- Added watch-only Litecoin/Dogecoin Core RPC synchronization, exact balances
  and history, SQLite persistence, node-derived fee estimates, broadcasting,
  confirmation status and rescan.
- Added `shadowallet-chain-bitcoin-cash` with CashAddr, BCH ForkID sighash,
  P2PKH construction, external signing/verification and BCHN regtest acceptance.
- Added `FeeEstimate` to `shadowallet-chain-utxo`.
- Transaction builders now derive fees from an integer rate and a conservative
  size model.
- Shadowallet now consumes the SDK for UTXO models, LTC/DOGE engines and the BCH
  PoC; duplicate protocol implementations were removed from the application.
- Documented the Bitcoin BDK compatibility boundary and component ownership.

All notable changes to the SDK are documented here. This project follows
Semantic Versioning once a stable release exists.

## 0.1.0-alpha.1

- Added `shadowallet-chain-core`: chain/network identifiers, errors, balance
  and confirmation models, `SignRequest` and `ExternalSigner`.
- Added `shadowallet-chain-utxo`: UTXO balance/history, fee safety policy,
  largest-first coin selection and `UtxoStore` contract.
- Added `shadowallet-chain-litecoin`: watch-only xpub BIP84/P2WPKH derivation,
  unsigned P2WPKH construction, SIGHASH_ALL request generation, external
  signature verification/finalization.
- Added `shadowallet-chain-dogecoin`: watch-only xpub BIP44/P2PKH derivation,
  unsigned legacy construction, external signature verification/finalization,
  koinu fee envelope.
- Not yet extracted: RPC synchronization, SQLite persistence, binary adapters,
  Bitcoin crate, examples and network E2E.
