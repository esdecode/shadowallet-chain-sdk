# Compatibility patch for the official Zcash database

Source: crates.io `rusqlite 0.37.0`, MIT.

Only the generated Cargo.toml dependency requirement for libsqlite3-sys is changed
from 0.35 to 0.39. This lets librustzcash's rusqlite 0.37 requirement share the
maintained SQLite binding used by rusqlite 0.41 elsewhere in the SDK. No SQLite
cryptography, SQL schema, or Rust wrapper implementation is replaced.

The purpose is to avoid reintroducing the SQLite advisory RUSTSEC-2026-0459 through
zcash_client_sqlite. Cargo.lock resolves libsqlite3-sys 0.39.1. Validation includes
the official wallet database initialization, public testnet sync and reopening,
the SDK workspace tests, cargo audit and cargo deny. This is a compatibility fork,
not an independently audited upstream release. Remove it when the official Zcash
database supports the maintained rusqlite version; never suppress the advisory.
