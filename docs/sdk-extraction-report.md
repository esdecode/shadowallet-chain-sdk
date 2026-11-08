# Extraction Report (Phase 4D.2)

Source application: the private Shadowallet wallet repository (not published).
SDK: this standalone repository.
The SDK is standalone and does not reference the application, vault, FFI or
Flutter.

## Extracted in this phase

| Source | SDK crate | Notes |
|---|---|---|
| `crates/utxo-common` | `shadowallet-chain-utxo` | canonical models; application now re-exports the SDK |
| `adapter-sdk` identity/proposal concepts | `shadowallet-chain-core` | reduced, no vault/authorization |
| LTC primitives + `engine.rs` | `shadowallet-chain-litecoin` | watch-only xpub account, Core RPC, SQLite, fees, build/sign-request/finalize |
| BTC BDK engine | `shadowallet-chain-bitcoin` | watch-only descriptors, Esplora/Core sync, PSBT build/finalize |
| DOGE primitives + `engine.rs` | `shadowallet-chain-dogecoin` | watch-only xpub account, Core 1.14 RPC, SQLite, fees, build/sign-request/finalize |
| BCH PoC + full engine | `shadowallet-chain-bitcoin-cash` | CashAddr, ForkID, Core RPC sync, SQLite, persistence, external signing, broadcast; BCHN regtest E2E |

The application crates now:

- depend on the SDK by path;
- keep only key derivation (`LtcAccount`/`DogeAccount`), vault authorization,
  FFI and Flutter;
- use SDK `SignRequest` digests and `finalize_transfer` for signing, so
  transaction construction/serialization is not duplicated;
- re-export SDK UTXO models through `utxo-common` and the BCH crate through
  `adapter-bitcoin-cash` for compatibility while the ABI remains stable.

## Bitcoin boundary

The watch-only BDK engine now lives in `shadowallet-chain-bitcoin`. The
application keeps private descriptor derivation and an in-memory PSBT signer;
the SDK never receives a seed or private descriptor.

## Verification

- SDK standalone: `cargo test --workspace` (LTC/DOGE/BCH unit + vector tests).
- Application: workspace tests, LTC/DOGE Core regtest E2E and native FFI E2E.
- BCHN 29.2.0 regtest acceptance is recorded in the SDK BCH test suite.

## Remaining blockers

- Bitcoin watch-only extraction (see above).
- Public light-client sync (Electrum/Esplora) for LTC/DOGE.
- BCH remains a PoC; no sync/persistence/FFI.
