# RUSTSEC-2026-0459 assessment

## Advisory

- `libsqlite3-sys < 0.39.0` bundles SQLite before 3.54.0.
- Crafted database + sibling `-wal` with mismatched page size can return
  uninitialized page-cache bytes (local information disclosure).
- Fixed: `libsqlite3-sys >= 0.39.0` / `rusqlite 0.41`.
- Bundled SQLite currently resolved: **3.45.0**.

## Dependency path

```
bdk_chain 0.23.4
  -> rusqlite 0.31.0
     -> libsqlite3-sys 0.28.0
  -> bdk_wallet 3.2.0
shadowallet-chain-{bitcoin,bitcoin-cash,dogecoin,litecoin,evm}
  -> rusqlite 0.31.0
```

`bdk_wallet` 3.2.0 and upstream `bdk_chain` main still declare
`rusqlite = "0.31"`. Cargo cannot unify `rusqlite 0.31` and `0.41` because both
link native library `sqlite3`.

## Why no local upgrade is safe

- Upgrading only this workspace's direct `rusqlite` leaves BDK's vulnerable
  copy in the graph.
- Patching `libsqlite3-sys` to 0.39 violates BDK's `^0.28` requirement.
- Vendoring SQLite 3.54 into `libsqlite3-sys 0.28` leaves the advisory version
  match in place and would not produce a clean `cargo audit`.
- Disabling BDK's `rusqlite` feature changes wallet persistence semantics and
  requires a tested migration; it is not a drop-in alpha fix.

## Status

**BLOCKED upstream.** No SDK release candidate can claim remediation until BDK
publishes a `rusqlite 0.41`/`libsqlite3-sys 0.39` dependency. No advisory is
ignored and no publication was performed.
