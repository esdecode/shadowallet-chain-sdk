# Shadowallet Chain SDK — 0.1.0-alpha.3 security candidate

Status: **published to crates.io on 2026-11-10**. GitHub prerelease tag
`v0.1.0-alpha.3`.

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

## Publication (2026-11-10)

Registry artifacts and SHA-256 checksums:

| Crate | Version | Checksum |
|---|---|---|
| `shadowallet-chain-bitcoin` | 0.1.0-alpha.3 | `9d91bcc5406d69140c1612ddf48b43ec9003613943858318a97582027b052741` |
| `shadowallet-chain-bitcoin-cash` | 0.1.0-alpha.2 | `447391afcb422e2ca4d7b3bad6d9669ff8febfcc62d3912d0cae43fad3d8e6c9` |
| `shadowallet-chain-dogecoin` | 0.1.0-alpha.2 | `ca7f570869be3262963d70e32018ab750c0cdda23afaac793814599ca6af13e9` |
| `shadowallet-chain-litecoin` | 0.1.0-alpha.2 | `5699b54449b7c4ce85aad7ae9e00261c41654ac57957978d9180d89738642e12` |
| `shadowallet-chain-evm` | 0.1.0-alpha.3 | `6dc5c6fd633ec903a61b9f43d3c7b247456e3cec9b29fe996c5e865ebed7a8e1` |

Registry-only consumer (fresh temp workspace, no patches, no sibling checkout)
resolved these exact versions, `rusqlite 0.41.1`, `libsqlite3-sys 0.39.1`,
no OpenSSL, and printed `sqlite=3.54.1` and `consumer-ok`.

The private Wallet was migrated to these versions; its `[patch.crates-io]`
block and sibling checkout assumptions were removed.

GitHub Actions remained disabled for the entire release. No workflow was
enabled, dispatched, re-run, or triggered; release evidence is local.
