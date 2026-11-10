# RUSTSEC-2026-0459 assessment

## Advisory

- `libsqlite3-sys < 0.39.0` bundles SQLite before 3.54.0.
- Crafted database + sibling `-wal` with mismatched page size can return
  uninitialized page-cache bytes (local information disclosure).
- Fixed: `libsqlite3-sys >= 0.39.0` / `rusqlite 0.41`.
- Affected bundled releases: `0.6.0 ..= 0.38.2`.

## Original dependency path

```
bdk_chain 0.23.4 (feature "rusqlite")
  -> rusqlite 0.31.0
     -> libsqlite3-sys 0.28.0 (SQLite 3.45.0)
shadowallet-chain-{bitcoin,bitcoin-cash,dogecoin,litecoin,evm}
  -> rusqlite 0.31.0
```

Latest crates.io releases (`bdk_wallet` 3.2.0, `bdk_chain` 0.23.4) still
declare `rusqlite = "0.31"`. No upstream release fixes the graph.

## Resolution (Phase 5.12 candidate)

- BDK is compiled **without** the `rusqlite` feature. BDK's SQLite feature is
  optional and only supplies schema helpers.
- `shadowallet-chain-bitcoin` implements `bdk_wallet::WalletPersister` on
  `rusqlite 0.41` directly:
  - atomic changeset log + compaction;
  - one-time read-only import of legacy BDK SQLite tables;
  - pinned schema-version checks; unknown/newer versions fail closed.
- All direct `rusqlite` users moved to 0.41.
- The local vendored `rusqlite` fork and `[patch.crates-io]` were removed.

Resolved graph:

```
rusqlite 0.41.1 -> libsqlite3-sys 0.39.1 -> bundled SQLite 3.54.1
```

## Verification

- `cargo tree -i libsqlite3-sys`: only 0.39.1.
- `cargo audit`: clean.
- `cargo deny check`: advisories/bans/licenses/sources ok.
- Packaged-crate external consumer resolves and runs with SQLite 3.54.1.
- Persistence tests cover creation, reopen, legacy import, corruption,
  schema versions, integrity and compaction.

## Status

**REMEDIATED and published.** The fixed versions are on crates.io as of
2026-11-10 (`shadowallet-chain-bitcoin` 0.1.0-alpha.3,
`shadowallet-chain-{bitcoin-cash,dogecoin,litecoin}` 0.1.0-alpha.2,
`shadowallet-chain-evm` 0.1.0-alpha.3). A registry-only consumer resolves
`libsqlite3-sys 0.39.1` / SQLite 3.54.1 and contains no `rusqlite 0.31`. No
advisory is ignored or suppressed.
