# Shadowallet Chain SDK

Modular Rust blockchain wallet infrastructure for building non-custodial,
multi-chain applications. Extracted from the Shadowallet reference wallet.

**Development status: 0.1.0-alpha.1 — pre-release.** No security audit has been
performed. Do not use with mainnet funds.

## Supported chains

| Chain | Public derivation | Unsigned tx | External signing | RPC sync + SQLite | Status |
|---|---|---|---|---|---|
| Bitcoin | xpub / BIP84 P2WPKH | yes (PSBT) | yes (external PSBT) | yes (Esplora/Core) | alpha, app regtest E2E |
| Litecoin | xpub / BIP84 P2WPKH | yes | yes (verify + finalize) | yes (Litecoin Core) | alpha, regtest E2E in app |
| Dogecoin | xpub / BIP44 P2PKH | yes | yes (verify + finalize) | yes (Dogecoin Core 1.14) | alpha, regtest E2E in app |
| Bitcoin Cash | xpub / BIP44 P2PKH | yes | yes (BCH ForkID) | yes (BCHN Core) | alpha, BCHN regtest E2E |
| EVM (ETH/Anvil) | BIP44 m/44'/60'/0'/0/i | yes (EIP-1559) | yes (digest + finalize) | yes (Alloy HTTP) | alpha, Anvil native/ERC-20 E2E |

## Architecture

```
shadowallet-chain-core      identities, errors, SignRequest, ExternalSigner
shadowallet-chain-bitcoin   watch-only BDK engine, Esplora/Core sync, PSBT
shadowallet-chain-utxo      balances, history, fee policy, coin selection, UtxoStore
shadowallet-chain-litecoin  watch-only BIP84/P2WPKH build, Core RPC, SQLite, finalize
shadowallet-chain-dogecoin  watch-only BIP44/P2PKH build, Core RPC, SQLite, finalize
shadowallet-chain-bitcoin-cash CashAddr, ForkID, Core RPC, SQLite, P2PKH engine
shadowallet-chain-evm 0.1.0-alpha.2 (unpublished)  Alloy profiles, BIP44, RPC, ERC-20, EIP-1559, SQLite state
```

The SDK does **not** include Shadowallet's UWV2 vault, Flutter UI, sessions,
authorization policy or backend. It stores no private keys and cannot sign by
itself.

## External signing model

1. Derive a watch-only account from an account-level xpub.
2. `prepare_transfer` returns an unsigned transaction (no witness/scriptSig).
3. `signing_request` returns the exact SIGHASH_ALL digests and public keys for
   each input.
4. The calling wallet authenticates the user and authorizes that exact request,
   then its signer returns DER signatures.
5. `finalize_transfer` verifies every signature against the SDK-derived public
   key before assembling the witness/scriptSig.
6. The caller broadcasts with its own provider.

Signatures for a modified transaction fail verification. The SDK never exposes
an arbitrary-digest signing API.

## Minimal example (Litecoin, watch-only)

```rust,no_run
use shadowallet_chain_litecoin::{prepare_transfer, signing_request, LtcAccount, LtcNetwork};
use shadowallet_chain_utxo::Utxo;

let account = LtcAccount::from_xpub(LtcNetwork::Regtest, "tpub...", [0,0,0,0])?;
let unsigned = prepare_transfer(&account, &utxos, &destination, 50_000, 1, 0)?;
assert!(unsigned.is_unsigned());
let request = signing_request(&account, &unsigned)?;
// Hand `request` to your authorized signer, then:
// let tx = finalize_transfer(&account, &unsigned, &der_signatures)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`utxos: Vec<Utxo>` must come from your own watch-only provider.

## Security model

Enforced by the SDK:

- no seed/private-key storage or logging;
- unsigned preparation cannot sign;
- transaction-specific digests (no arbitrary message signing);
- signature verification before finalization;
- fee safety envelope (not a substitute for network policy).

Enforced by the calling application:

- user authentication and explicit per-transaction approval;
- vault locking/session expiry and authorization replay protection;
- provider trust and UTXO confirmation policy;
- mainnet enablement and broadcast policy.

See `docs/sdk-security-model.md`.

## Build and test

> Linux builds require OpenSSL development headers (`libssl-dev`, `pkg-config`).
> macOS uses Security.framework and Windows uses SChannel for Esplora TLS.

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps
```

LTC/DOGE regtest E2E is executed by the Shadowallet integration suite; the SDK
unit/vector tests run standalone. See `docs/sdk-extraction-report.md` and
`docs/component-ownership.md`.

## License

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE`, and
`docs/sdk-licensing.md`.

## Responsible disclosure

See `SECURITY.md`. Do not open a public issue for a vulnerability.
