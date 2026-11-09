# Shadowallet Chain SDK — 0.1.0-alpha.3 security candidate

Status: **prepared, not published**.

## Security

- Fixes `RUSTSEC-2026-0459` (`libsqlite3-sys` bundled SQLite < 3.54.0) by
  removing BDK's `rusqlite 0.31` dependency from the graph.
- `bdk_wallet` / `bdk_chain` are compiled without the `rusqlite` feature.
- `shadowallet-chain-bitcoin` implements `WalletPersister` directly on
  `rusqlite 0.41.1` / `libsqlite3-sys 0.39.1` / SQLite **3.54.1**.
- No advisory suppression, no `[patch.crates-io]`, no vendored rusqlite.
- Existing BDK SQLite databases are imported once, read-only, with pinned
  schema versions. Unsupported versions fail closed.

## Crates and versions

| Crate | Candidate | Reason |
|---|---|---|
| `shadowallet-chain-core` | 0.1.0-alpha.1 (unchanged) | no changes |
| `shadowallet-chain-utxo` | 0.1.0-alpha.1 (unchanged) | no changes |
| `shadowallet-chain-bitcoin` | **0.1.0-alpha.3** | persistence rewrite, rusqlite 0.41 |
| `shadowallet-chain-bitcoin-cash` | **0.1.0-alpha.2** | rusqlite 0.41 |
| `shadowallet-chain-dogecoin` | **0.1.0-alpha.2** | rusqlite 0.41 |
| `shadowallet-chain-litecoin` | **0.1.0-alpha.2** | rusqlite 0.41 |
| `shadowallet-chain-evm` | **0.1.0-alpha.3** | rusqlite 0.41 |

## Release order

1. `shadowallet-chain-bitcoin` 0.1.0-alpha.3
2. `shadowallet-chain-bitcoin-cash` 0.1.0-alpha.2
3. `shadowallet-chain-dogecoin` 0.1.0-alpha.2
4. `shadowallet-chain-litecoin` 0.1.0-alpha.2
5. `shadowallet-chain-evm` 0.1.0-alpha.3

`core`/`utxo` need no release; the packaged candidates depend on the already
published 0.1.0-alpha.1 versions.

## Validation performed

- `cargo package` + verification build for all seven crates.
- Fresh external consumer built from packaged `.crate` sources in a vendored
  directory source (no path deps, no patches): `cargo metadata`, `cargo tree`,
  `cargo run`.
- Resolved graph: only `rusqlite 0.41.1` and `libsqlite3-sys 0.39.1`.
- `cargo audit`: clean. `cargo deny check`: advisories/bans/licenses/sources ok.
- SDK tests, fmt and clippy pass.

## Pending authorization

- `cargo publish` for the five crates above.
- Public GitHub push/tag/release.
- Wallet dependency switch from the local candidate patch to published
  versions (the private Wallet currently uses path overrides for local
  integration testing only).
