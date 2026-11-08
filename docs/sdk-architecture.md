# SDK Architecture

## Boundary

The SDK is a standalone Rust workspace. It must never depend on the Shadowallet
application, UWV2 vault, Flutter, FFI or backend services.

```
chain-core      identities, errors, balances, SignRequest, ExternalSigner
chain-utxo      UTXO models, fee policy, coin selection, store trait
chain-litecoin  xpub/BIP84, unsigned P2WPKH, external finalization
chain-dogecoin  xpub/BIP44, unsigned P2PKH, external finalization
```

## Capability split

- Watch-only: public derivation, address validation, unsigned construction.
- External signing: the caller supplies DER signatures for SDK-produced
  transaction digests; the SDK verifies and finalizes.
- No key storage, no vault, no arbitrary-digest signing, no automatic signing.

## Not yet extracted

RPC synchronization, SQLite persistence, adapters/descriptors, Bitcoin crate and
network E2E remain in the application repository. They are listed as explicit
blockers in `sdk-extraction-report.md`; no placeholder crate is published.

## Dependency direction

`chain-litecoin` / `chain-dogecoin` → `chain-core`, `chain-utxo`. No reverse
dependencies. Future account-based chains (EVM/Solana) depend on `chain-core`
only; UTXO abstractions are not forced on them.
