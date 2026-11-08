# Shadowallet Chain SDK 0.1.0-alpha.1

Experimental pre-release. **No independent security audit has been performed.**
Do not use with mainnet funds.

## Supported

- `shadowallet-chain-core` — identities, errors, sign requests.
- `shadowallet-chain-utxo` — balances/history/fee policy/selection contracts.
- `shadowallet-chain-bitcoin` — watch-only BDK 3.2 engine, Esplora/Core sync,
  PSBT construction/finalization, SQLite.
- `shadowallet-chain-litecoin` — BIP84 P2WPKH, Litecoin Core sync, SQLite,
  fees, external signature finalization.
- `shadowallet-chain-dogecoin` — BIP44 P2PKH, Dogecoin Core 1.14 sync, SQLite,
  fees, external signature finalization.
- `shadowallet-chain-bitcoin-cash` — CashAddr, ForkID, BCHN Core sync, SQLite,
  P2PKH external signature finalization.

## Verified environments

- Litecoin Core 0.21.5.6 regtest.
- Dogecoin Core 1.14.0 regtest.
- Bitcoin Core regtest (through the Shadowallet integration suite).
- Bitcoin Cash Node 29.2.0 regtest.

## Known limitations

- Core RPC backends only for LTC/DOGE/BCH; no public Electrum/Esplora adapter
  for those chains.
- BCH: P2PKH only; no P2SH, multisig, CashTokens or Schnorr policy.
- No independent security audit.
- Mobile/WASM targets unverified.
- The SDK is pre-1.0; public APIs may change.

License: MIT OR Apache-2.0.
