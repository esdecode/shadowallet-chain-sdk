# shadowallet-chain-solana

Solana and SPL token support for the Shadowallet Chain SDK.

**Status: pre-release, unpublished (`publish = false`).** No independent
security audit. Signing is restricted to a disposable local validator
(`SolanaNetwork::Localnet`); devnet, testnet and mainnet-beta are read-only.
Do not use with real funds.

## What it does

- SLIP-0010 Ed25519 derivation at `m/44'/501'/{n}'/0'` from a **64-byte BIP-39
  seed** (PBKDF2-HMAC-SHA512, as every standard wallet computes it).
- Strict base58 `Pubkey`, program-derived addresses, associated token accounts.
- Legacy transaction messages (build, strict parse, signature check).
- JSON-RPC client: bounded retries on reads only, never on `sendTransaction`,
  response size cap, genesis-hash network binding, signature statuses,
  paged signatures, parsed transaction details (explicit transfers only).
- Transfer preparation for native SOL and SPL Token / extension-free
  Token-2022 `TransferChecked` (creating the recipient's associated token
  account when needed), with fee, rent and blockhash-expiry checks.

## Security model (differs from the other SDK crates)

The UTXO and EVM crates are watch-only and sign through an external signer.
This crate contains a **software signer**, `SolanaAccount`, so the host
application must keep it inside its own secret boundary (for example a
vault). What the crate guarantees:

- The secret key never leaves `SolanaAccount` (redacted `Debug`, zeroized on
  drop). There is no accessor for it.
- The only signing entry point is `SolanaAccount::sign_transfer`. It
  re-parses the exact message bytes, allows only System `Transfer`, ATA
  `CreateIdempotent` and SPL `TransferChecked`, requires the fee payer to be
  the sender and requires the instructions to equal the reviewed intent.
- There is **no API that signs caller-supplied bytes**.
- It refuses to sign on any network except `Localnet`.

What it does not do: key storage, user authorization, rate limiting, replay
protection beyond the blockhash, priority fees, durable nonces, address lookup
tables or versioned transactions. Those belong to the host application.

## Example (offline)

```rust
use shadowallet_chain_solana::SolanaAccount;

// BIP-39 seed of the all-"abandon ... art" test phrase (empty passphrase).
let seed: [u8; 64] = [
    0x40, 0x8b, 0x28, 0x5c, 0x12, 0x38, 0x36, 0x00, 0x4f, 0x4b, 0x88, 0x42, 0xc8, 0x93,
    0x24, 0xc1, 0xf0, 0x13, 0x82, 0x45, 0x0c, 0x0d, 0x43, 0x9a, 0xf3, 0x45, 0xba, 0x7f,
    0xc4, 0x9a, 0xcf, 0x70, 0x54, 0x89, 0xc6, 0xfc, 0x77, 0xdb, 0xd4, 0xe3, 0xdc, 0x1d,
    0xd8, 0xcc, 0x6b, 0xc9, 0xf0, 0x43, 0xdb, 0x8a, 0xda, 0x1e, 0x24, 0x3c, 0x4a, 0x0e,
    0xaf, 0xb2, 0x90, 0xd3, 0x99, 0x48, 0x08, 0x40,
];
let account = SolanaAccount::from_seed(&seed, 0).unwrap();
assert_eq!(account.address(), "3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx");
```

The expected address was produced by an independent Python implementation of
SLIP-0010 (see `tests/derivation_vectors.rs`), not by this crate.

## Testing

```text
cargo test -p shadowallet-chain-solana                      # unit + vectors
SOLANA_RPC_URL=http://127.0.0.1:8899 \
  cargo test -p shadowallet-chain-solana --test localnet -- --ignored
```

The ignored test needs a disposable `solana-test-validator`.

## License

See the workspace license.
