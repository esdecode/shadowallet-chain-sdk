# Component Ownership Matrix

Phase 4D.2 separation between the standalone SDK and the Shadowallet
application. The SDK owns blockchain/protocol work; the application owns
secrets, authorization and UX.

| Component | SDK | Application | Notes |
|---|---|---|---|
| Chain/network parameters | YES | NO | `shadowallet-chain-*` |
| Address generation/validation | YES | NO | SDK watch-only accounts |
| Public derivation | YES | NO | xpub accounts; no seed |
| Core RPC/Esplora clients | YES | NO | BTC/LTC/DOGE/BCH engines |
| Watch-only synchronization | YES | NO | BDK + Core RPC watchers |
| UTXO discovery | YES | NO | SDK engines expose `Utxo` |
| Balance/history models | YES | NO | `shadowallet-chain-utxo` |
| SQLite persistence | YES | NO | all SDK engines, no keys stored |
| Fee estimation | YES | NO | node-derived estimates in SDK |
| Transaction construction | YES | NO | SDK unsigned builders |
| Sighash/serialization | YES | NO | BTC/LTC/DOGE/BCH crates |
| Signature finalization | YES | NO | verifies external DER signatures |
| Transaction broadcasting | YES | NO | SDK provider method |
| Confirmation tracking | YES | NO | SDK RPC status |
| Rescan/recovery primitives | YES | NO | SDK engine |
| Seed/private-key storage | NO | YES | UWV2 vault |
| Private-key derivation | NO | YES | app derives keys; BTC private descriptors stay app-side |
| User authorization/replay protection | NO | YES | app `AuthorizationBoundary` |
| Transaction proposal policy | NO | YES | app owns proposal TTL/commitment |
| Mainnet release policy | NO | YES | disabled by app policy |
| Flutter FFI/UI | NO | YES | `wallet-ffi`, `apps/wallet` |
| Business logic/screens | NO | YES | application |

## Boundary rules

1. The SDK never stores or logs a seed, xprv or private key.
2. Synchronization and unsigned preparation work with public xpubs only.
3. The SDK returns a `SignRequest` containing exact digests; the application
   authorizes the proposal and signs those digests.
4. `finalize_transfer` verifies signatures against SDK-derived public keys
   before assembling the transaction.
5. The application may depend on SDK crates by path/version; the SDK must not
   depend on the application, vault, FFI or Flutter.
