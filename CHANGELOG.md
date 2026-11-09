# Changelog

## Unreleased — Phase 5.12 SQLite security remediation (candidate)

- Removed BDK's `rusqlite` feature. `bdk_chain 0.23.4` pins `rusqlite 0.31`
  (`libsqlite3-sys 0.28`, SQLite 3.45.0), which is affected by
  RUSTSEC-2026-0459.
- `shadowallet-chain-bitcoin` now implements `WalletPersister` on
  `rusqlite 0.41` / `libsqlite3-sys 0.39.1` / bundled SQLite 3.54.1.
- Wallet state is stored as an atomic, compacting JSON changeset log. Databases
  written by BDK's SQLite backend are imported once, read-only, with pinned
  schema-version checks; unsupported versions fail closed.
- All direct SDK SQLite users moved to `rusqlite 0.41`.
- Removed the repository-local `[patch.crates-io]` rusqlite fork.
- Added database creation, reopen, legacy import, corruption rejection,
  schema-version, integrity-check and log-compaction tests.
- Candidate versions: core/utxo unchanged; bitcoin 0.1.0-alpha.3,
  bitcoin-cash/dogecoin/litecoin 0.1.0-alpha.2, evm 0.1.0-alpha.3.
- Not published.

## Unreleased — Phase 5.1 EVM hardening

- SQLite state: accounts, nonces, transactions, tokens, sync checkpoints.
- Transactional nonce reservation, release, replacement, expiry and restart
  reconciliation.
- History abstraction with explicit outgoing-only completeness and ERC-20
  Transfer log decoding.
- Fee quotes with base fee, caps, checked total cost; BSC/L2 fail closed.
- ERC-20 name/metadata cache and receipt Transfer validation.
- Watch-only accounts can no longer sign (removed random signer).
- Removed Alloy core/provider/signer/ABI dependencies. EIP-155/1559 RLP,
  ERC-20 ABI and checksum addresses are implemented in-crate; signing uses
  libsecp256k1.
- Raw `cargo audit` and `cargo deny check`: clean.
- Added BSC legacy EIP-155 E2E, independent `eth_account` vectors, cross-
  connection nonce locking and RPC timeout/size limits.
- Not published.

## Unreleased — Phase 5 EVM

- Added `shadowallet-chain-evm`: Alloy 1.8 provider, BIP44 account derivation,
  chain profiles, EIP-1559 external signing, ERC-20 reads/transfers, Anvil
  native and ERC-20 E2E.
- Not published; existing 0.1.0-alpha.1 crates remain unchanged.

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
