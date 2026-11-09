//! Wallet persistence for the public SDK.
//!
//! `bdk_chain` 0.23 pins `rusqlite 0.31`, whose bundled SQLite is affected by
//! RUSTSEC-2026-0459. The fix is to compile BDK **without** its SQLite feature
//! and implement `WalletPersister` on top of a maintained `rusqlite` release.
//!
//! The on-disk format is an append-only JSON changeset log in a single SQLite
//! table. The log is compacted into one merged changeset once it grows past
//! `COMPACT_AFTER` rows, which keeps the file bounded while preserving atomic
//! writes and crash recovery.
//!
//! Existing databases written by BDK's SQLite backend (the normalized
//! `bdk_wallet`, `bdk_txs`, `bdk_blocks`, ... tables) are imported once, without
//! modifying the legacy tables. Unsupported legacy schema versions fail closed.

use std::path::Path;
use std::str::FromStr;

use bdk_chain::{
    BlockId, ConfirmationBlockTime, DescriptorId, Merge, keychain_txout, local_chain, tx_graph,
};
use bdk_wallet::bitcoin::consensus::encode::deserialize;
use bdk_wallet::bitcoin::{BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::miniscript::{Descriptor, DescriptorPublicKey};
use bdk_wallet::{ChangeSet, WalletPersister};
use rusqlite::{Connection, OptionalExtension, Transaction as SqlTx, TransactionBehavior, params};
use thiserror::Error;

/// Maximum number of appended changesets before the log is merged.
const COMPACT_AFTER: i64 = 32;

/// Current schema version of `shadowallet_wallet_meta`.
const SCHEMA_VERSION: i64 = 1;

const META_TABLE: &str = "shadowallet_wallet_meta";
const CHANGESET_TABLE: &str = "shadowallet_wallet_changesets";

/// Persistence errors. Failures are never downgraded to warnings: callers must
/// treat them as fatal for the current wallet operation.
#[derive(Debug, Error)]
pub enum SqliteStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("changeset serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("legacy BDK wallet schema is incompatible: {0}")]
    UnsupportedLegacy(String),
    #[error("legacy BDK wallet data is corrupt: {0}")]
    CorruptLegacy(String),
}

/// SQLite-backed [`WalletPersister`] used by [`crate::BitcoinEngine`].
pub struct SqliteStore {
    conn: Connection,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

impl SqliteStore {
    /// Open (or create) the wallet database at `path`.
    pub fn open(path: &Path) -> Result<Self, SqliteStoreError> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// Open an ephemeral in-memory store. Used by tests and ephemeral signers.
    pub fn open_in_memory() -> Result<Self, SqliteStoreError> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, SqliteStoreError> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // WAL is ignored by in-memory databases; the statement is harmless.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;",
        )?;
        Ok(Self { conn })
    }

    /// Raw connection access for tests and integrity checks.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    fn init_schema(&self) -> Result<(), SqliteStoreError> {
        self.conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {META_TABLE} (
                 id INTEGER PRIMARY KEY NOT NULL CHECK (id = 0),
                 version INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS {CHANGESET_TABLE} (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 changeset BLOB NOT NULL
             ) STRICT;"
        ))?;
        let version: Option<i64> = self
            .conn
            .query_row(
                &format!("SELECT version FROM {META_TABLE} WHERE id = 0"),
                [],
                |row| row.get(0),
            )
            .optional()?;
        match version {
            None => {
                self.conn.execute(
                    &format!("INSERT INTO {META_TABLE}(id, version) VALUES(0, ?1)"),
                    params![SCHEMA_VERSION],
                )?;
            }
            Some(found) if found == SCHEMA_VERSION => {}
            Some(found) if found > SCHEMA_VERSION => {
                return Err(SqliteStoreError::UnsupportedLegacy(format!(
                    "database schema version {found} is newer than supported {SCHEMA_VERSION}"
                )));
            }
            Some(_) => {
                return Err(SqliteStoreError::UnsupportedLegacy(
                    "database schema version is not migratable".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn changeset_rows(tx: &SqlTx<'_>) -> Result<Vec<Vec<u8>>, SqliteStoreError> {
        let mut stmt = tx.prepare(&format!(
            "SELECT changeset FROM {CHANGESET_TABLE} ORDER BY id"
        ))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn merge_rows(rows: &[Vec<u8>]) -> Result<ChangeSet, SqliteStoreError> {
        let mut merged = ChangeSet::default();
        for row in rows {
            let changeset: ChangeSet = serde_json::from_slice(row)?;
            merged.merge(changeset);
        }
        Ok(merged)
    }

    fn append(tx: &SqlTx<'_>, changeset: &ChangeSet) -> Result<(), SqliteStoreError> {
        let bytes = serde_json::to_vec(changeset)?;
        tx.execute(
            &format!("INSERT INTO {CHANGESET_TABLE}(changeset) VALUES(?1)"),
            params![bytes],
        )?;
        Ok(())
    }

    fn compact(tx: &SqlTx<'_>) -> Result<(), SqliteStoreError> {
        let merged = Self::merge_rows(&Self::changeset_rows(tx)?)?;
        tx.execute(&format!("DELETE FROM {CHANGESET_TABLE}"), [])?;
        Self::append(tx, &merged)?;
        Ok(())
    }

    fn table_exists(tx: &SqlTx<'_>, name: &str) -> Result<bool, SqliteStoreError> {
        let found: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    fn legacy_schema_version(tx: &SqlTx<'_>, name: &str) -> Result<u32, SqliteStoreError> {
        let version: Option<u32> = tx
            .query_row(
                "SELECT version FROM bdk_schemas WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        version.ok_or_else(|| {
            SqliteStoreError::UnsupportedLegacy(format!("missing `{name}` schema record"))
        })
    }

    /// Import a database written by BDK's own SQLite backend.
    ///
    /// The legacy tables are read only; the imported changeset is written to the
    /// new changeset log by the caller. Schema versions are pinned to the ones
    /// emitted by `bdk_chain 0.23.4`; anything newer fails closed instead of
    /// guessing.
    fn import_legacy(tx: &SqlTx<'_>) -> Result<Option<ChangeSet>, SqliteStoreError> {
        if !Self::table_exists(tx, "bdk_schemas")? || !Self::table_exists(tx, "bdk_wallet")? {
            return Ok(None);
        }
        let expected = [
            ("bdk_wallet", 1u32),
            ("bdk_localchain", 0),
            ("bdk_txgraph", 3),
            ("bdk_keychaintxout", 1),
        ];
        for (name, max) in expected {
            let found = Self::legacy_schema_version(tx, name)?;
            if found > max {
                return Err(SqliteStoreError::UnsupportedLegacy(format!(
                    "`{name}` schema version {found} is newer than supported {max}"
                )));
            }
        }

        let mut changeset = ChangeSet {
            descriptor: Self::legacy_descriptor(tx, "descriptor")?,
            change_descriptor: Self::legacy_descriptor(tx, "change_descriptor")?,
            network: Self::legacy_network(tx)?,
            ..ChangeSet::default()
        };
        Self::legacy_locked_outpoints(tx, &mut changeset)?;
        changeset.local_chain = Self::legacy_blocks(tx)?;
        changeset.tx_graph = Self::legacy_tx_graph(tx)?;
        changeset.indexer = Self::legacy_indexer(tx)?;
        Ok(Some(changeset))
    }

    fn legacy_descriptor(
        tx: &SqlTx<'_>,
        column: &str,
    ) -> Result<Option<Descriptor<DescriptorPublicKey>>, SqliteStoreError> {
        let raw: Option<Option<String>> = tx
            .query_row(
                &format!("SELECT {column} FROM bdk_wallet WHERE id = 0"),
                [],
                |row| row.get(0),
            )
            .optional()?;
        match raw.flatten() {
            None => Ok(None),
            Some(text) => Descriptor::from_str(&text)
                .map(Some)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("{column}: {e}"))),
        }
    }

    fn legacy_network(tx: &SqlTx<'_>) -> Result<Option<Network>, SqliteStoreError> {
        let raw: Option<Option<String>> = tx
            .query_row("SELECT network FROM bdk_wallet WHERE id = 0", [], |row| {
                row.get(0)
            })
            .optional()?;
        match raw.flatten() {
            None => Ok(None),
            Some(text) => Network::from_str(&text)
                .map(Some)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("network: {e}"))),
        }
    }

    fn legacy_locked_outpoints(
        tx: &SqlTx<'_>,
        changeset: &mut ChangeSet,
    ) -> Result<(), SqliteStoreError> {
        let mut stmt = tx.prepare("SELECT txid, vout FROM bdk_wallet_locked_outpoints")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;
        for row in rows {
            let (txid, vout) = row?;
            let txid = Txid::from_str(&txid)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("locked txid: {e}")))?;
            changeset
                .locked_outpoints
                .outpoints
                .insert(OutPoint::new(txid, vout), true);
        }
        Ok(())
    }

    fn legacy_blocks(tx: &SqlTx<'_>) -> Result<local_chain::ChangeSet, SqliteStoreError> {
        let mut changeset = local_chain::ChangeSet::default();
        let mut stmt = tx.prepare("SELECT block_height, block_hash FROM bdk_blocks")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (height, hash) = row?;
            let hash = BlockHash::from_str(&hash)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("block hash: {e}")))?;
            changeset.blocks.insert(height, Some(hash));
        }
        Ok(changeset)
    }

    fn legacy_tx_graph(
        tx: &SqlTx<'_>,
    ) -> Result<tx_graph::ChangeSet<ConfirmationBlockTime>, SqliteStoreError> {
        let mut changeset = tx_graph::ChangeSet::default();
        let mut stmt =
            tx.prepare("SELECT txid, raw_tx, first_seen, last_seen, last_evicted FROM bdk_txs")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?;
        for row in rows {
            let (txid, raw_tx, first_seen, last_seen, last_evicted) = row?;
            let txid = Txid::from_str(&txid)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("txid: {e}")))?;
            if let Some(raw) = raw_tx {
                let tx: Transaction = deserialize(&raw)
                    .map_err(|e| SqliteStoreError::CorruptLegacy(format!("raw tx: {e}")))?;
                changeset.txs.insert(std::sync::Arc::new(tx));
            }
            if let Some(value) = first_seen {
                changeset
                    .first_seen
                    .insert(txid, non_negative(value, "first_seen")?);
            }
            if let Some(value) = last_seen {
                changeset
                    .last_seen
                    .insert(txid, non_negative(value, "last_seen")?);
            }
            if let Some(value) = last_evicted {
                changeset
                    .last_evicted
                    .insert(txid, non_negative(value, "last_evicted")?);
            }
        }

        let mut stmt = tx.prepare("SELECT txid, vout, value, script FROM bdk_txouts")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        for row in rows {
            let (txid, vout, value, script) = row?;
            let txid = Txid::from_str(&txid)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("txout txid: {e}")))?;
            let value = u64::try_from(value)
                .map_err(|_| SqliteStoreError::CorruptLegacy("negative txout value".to_owned()))?;
            let value = bdk_wallet::bitcoin::Amount::from_sat(value);
            changeset.txouts.insert(
                OutPoint::new(txid, vout),
                TxOut {
                    value,
                    script_pubkey: ScriptBuf::from_bytes(script),
                },
            );
        }

        let mut stmt = tx
            .prepare("SELECT block_hash, block_height, confirmation_time, txid FROM bdk_anchors")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (hash, height, confirmation_time, txid) = row?;
            let hash = BlockHash::from_str(&hash)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("anchor hash: {e}")))?;
            let txid = Txid::from_str(&txid)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("anchor txid: {e}")))?;
            changeset.anchors.insert((
                ConfirmationBlockTime {
                    block_id: BlockId { height, hash },
                    confirmation_time: non_negative(confirmation_time, "confirmation_time")?,
                },
                txid,
            ));
        }
        Ok(changeset)
    }

    fn legacy_indexer(tx: &SqlTx<'_>) -> Result<keychain_txout::ChangeSet, SqliteStoreError> {
        let mut changeset = keychain_txout::ChangeSet::default();
        let mut stmt =
            tx.prepare("SELECT descriptor_id, last_revealed FROM bdk_descriptor_last_revealed")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;
        for row in rows {
            let (id, last_revealed) = row?;
            let id = DescriptorId::from_str(&id)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("descriptor id: {e}")))?;
            changeset.last_revealed.insert(id, last_revealed);
        }

        let mut stmt =
            tx.prepare("SELECT descriptor_id, spk_index, spk FROM bdk_descriptor_derived_spks")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (id, spk_index, spk) = row?;
            let id = DescriptorId::from_str(&id)
                .map_err(|e| SqliteStoreError::CorruptLegacy(format!("descriptor id: {e}")))?;
            changeset
                .spk_cache
                .entry(id)
                .or_default()
                .insert(spk_index, ScriptBuf::from_bytes(spk));
        }
        Ok(changeset)
    }

    /// Run SQLite's integrity check. Used by tests and diagnostics; corruption
    /// is reported, never hidden.
    pub fn integrity_check(&self) -> Result<(), SqliteStoreError> {
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result == "ok" {
            Ok(())
        } else {
            Err(SqliteStoreError::CorruptLegacy(result))
        }
    }
}

fn non_negative(value: i64, field: &str) -> Result<u64, SqliteStoreError> {
    u64::try_from(value)
        .map_err(|_| SqliteStoreError::CorruptLegacy(format!("negative {field} value")))
}

impl WalletPersister for SqliteStore {
    type Error = SqliteStoreError;

    fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
        persister.init_schema()?;
        let tx = persister
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows = Self::changeset_rows(&tx)?;
        let mut merged = Self::merge_rows(&rows)?;
        if rows.is_empty()
            && let Some(legacy) = Self::import_legacy(&tx)?
        {
            Self::append(&tx, &legacy)?;
            merged = legacy;
        }
        tx.commit()?;
        Ok(merged)
    }

    fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
        let tx = persister
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::append(&tx, changeset)?;
        let count: i64 = tx.query_row(
            &format!("SELECT COUNT(*) FROM {CHANGESET_TABLE}"),
            [],
            |row| row.get(0),
        )?;
        if count > COMPACT_AFTER {
            Self::compact(&tx)?;
        }
        tx.commit()?;
        Ok(())
    }
}
