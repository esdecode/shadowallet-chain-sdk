//! Durable public EVM wallet state and nonce reservations.
//!
//! Only public data is stored: addresses, public transaction fields, hashes,
//! fees, receipts and sync checkpoints. Seeds, private keys and signing
//! capabilities never enter this database.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{EvmError, EvmProvider};

pub const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDraft {
    pub to: String,
    pub value_wei: String,
    pub input_hex: String,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub tx_type: String,
}

impl TransactionDraft {
    pub fn native(to: &str, value_wei: &str) -> Self {
        Self {
            to: to.to_owned(),
            value_wei: value_wei.to_owned(),
            input_hex: "0x".to_owned(),
            gas_limit: 0,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            tx_type: "eip1559".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedTransaction {
    pub id: i64,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTransaction {
    pub id: i64,
    pub chain_id: u64,
    pub address: String,
    pub nonce: u64,
    pub tx_hash: Option<String>,
    pub status: String,
    pub to: String,
    pub value_wei: String,
    pub input_hex: String,
    pub gas_limit: u64,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    pub block_number: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    pub chain_id: u64,
    pub contract: String,
    pub symbol: Option<String>,
    pub name: Option<String>,
    pub decimals: Option<u8>,
}

pub struct EvmStore {
    conn: Mutex<Connection>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl EvmStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvmError> {
        Self::init(Connection::open(path).map_err(store_err)?)
    }

    pub fn open_in_memory() -> Result<Self, EvmError> {
        Self::init(Connection::open_in_memory().map_err(store_err)?)
    }

    fn init(conn: Connection) -> Result<Self, EvmError> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(store_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(store_err)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(store_err)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(store_err)?;
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(store_err)?;
        if version > SCHEMA_VERSION {
            return Err(EvmError::Store(format!(
                "database schema {version} is newer than supported {SCHEMA_VERSION}"
            )));
        }
        if version < SCHEMA_VERSION {
            conn.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS evm_account (
                    chain_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    balance_wei TEXT NOT NULL DEFAULT '0',
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (chain_id, address)
                );
                CREATE TABLE IF NOT EXISTS evm_nonce (
                    chain_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    next_nonce INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (chain_id, address)
                );
                CREATE TABLE IF NOT EXISTS evm_tx (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    nonce INTEGER NOT NULL,
                    tx_hash TEXT,
                    status TEXT NOT NULL,
                    to_addr TEXT NOT NULL,
                    value_wei TEXT NOT NULL,
                    input_hex TEXT NOT NULL,
                    gas_limit INTEGER NOT NULL,
                    max_fee_per_gas TEXT NOT NULL,
                    max_priority_fee_per_gas TEXT NOT NULL,
                    raw_tx TEXT,
                    block_number INTEGER,
                    error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS evm_tx_hash
                    ON evm_tx(chain_id, address, tx_hash) WHERE tx_hash IS NOT NULL;
                CREATE INDEX IF NOT EXISTS evm_tx_order
                    ON evm_tx(chain_id, address, id DESC);
                CREATE TABLE IF NOT EXISTS evm_token (
                    chain_id INTEGER NOT NULL,
                    contract TEXT NOT NULL,
                    symbol TEXT,
                    name TEXT,
                    decimals INTEGER,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (chain_id, contract)
                );
                CREATE TABLE IF NOT EXISTS evm_sync (
                    chain_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    last_block INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (chain_id, address)
                );
                PRAGMA user_version = 1;
                ",
            )
            .map_err(store_err)?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn integrity_check(&self) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let result: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(store_err)?;
        if result == "ok" {
            Ok(())
        } else {
            Err(EvmError::Store(format!("integrity check failed: {result}")))
        }
    }

    pub fn register_account(&self, chain_id: u64, address: &str) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.execute(
            "INSERT INTO evm_account (chain_id, address, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(chain_id, address) DO UPDATE SET updated_at = excluded.updated_at",
            params![to_i64(chain_id)?, address, now()],
        )
        .map_err(store_err)?;
        Ok(())
    }

    pub fn set_balance(
        &self,
        chain_id: u64,
        address: &str,
        balance_wei: &str,
    ) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let changed = conn
            .execute(
                "UPDATE evm_account SET balance_wei = ?3, updated_at = ?4
                 WHERE chain_id = ?1 AND address = ?2",
                params![to_i64(chain_id)?, address, balance_wei, now()],
            )
            .map_err(store_err)?;
        if changed == 0 {
            return Err(EvmError::Store("account not registered".to_owned()));
        }
        Ok(())
    }

    pub fn balance(&self, chain_id: u64, address: &str) -> Result<Option<String>, EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.query_row(
            "SELECT balance_wei FROM evm_account WHERE chain_id = ?1 AND address = ?2",
            params![to_i64(chain_id)?, address],
            |r| r.get(0),
        )
        .optional()
        .map_err(store_err)
    }

    /// Reserve the next nonce atomically, never below `network_nonce`.
    pub fn reserve_nonce(
        &self,
        chain_id: u64,
        address: &str,
        network_nonce: u64,
        draft: &TransactionDraft,
    ) -> Result<ReservedTransaction, EvmError> {
        let mut conn = self.conn.lock().map_err(lock_err)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_err)?;
        let registered: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM evm_account WHERE chain_id = ?1 AND address = ?2",
                params![to_i64(chain_id)?, address],
                |r| r.get(0),
            )
            .optional()
            .map_err(store_err)?;
        if registered.is_none() {
            return Err(EvmError::UnknownAccount);
        }
        let stored: Option<i64> = tx
            .query_row(
                "SELECT next_nonce FROM evm_nonce WHERE chain_id = ?1 AND address = ?2",
                params![to_i64(chain_id)?, address],
                |r| r.get(0),
            )
            .optional()
            .map_err(store_err)?;
        let next = stored.unwrap_or(0).max(to_i64(network_nonce)?).max(0);
        let timestamp = now();
        tx.execute(
            "INSERT INTO evm_tx
                (chain_id, address, nonce, status, to_addr, value_wei, input_hex,
                 gas_limit, max_fee_per_gas, max_priority_fee_per_gas, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'reserved', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                to_i64(chain_id)?,
                address,
                next,
                draft.to,
                draft.value_wei,
                draft.input_hex,
                to_i64(draft.gas_limit)?,
                draft.max_fee_per_gas.to_string(),
                draft.max_priority_fee_per_gas.to_string(),
                timestamp,
            ],
        )
        .map_err(store_err)?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO evm_nonce (chain_id, address, next_nonce, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(chain_id, address) DO UPDATE
             SET next_nonce = excluded.next_nonce, updated_at = excluded.updated_at",
            params![to_i64(chain_id)?, address, next + 1, timestamp],
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)?;
        Ok(ReservedTransaction {
            id,
            nonce: u64::try_from(next).map_err(|_| EvmError::NonceConflict)?,
        })
    }

    /// Fill gas and fee fields after the transaction was built.
    pub fn update_details(&self, id: i64, draft: &TransactionDraft) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let changed = conn
            .execute(
                "UPDATE evm_tx SET to_addr = ?2, value_wei = ?3, input_hex = ?4,
                    gas_limit = ?5, max_fee_per_gas = ?6, max_priority_fee_per_gas = ?7,
                    updated_at = ?8
                 WHERE id = ?1 AND status = 'reserved'",
                params![
                    id,
                    draft.to,
                    draft.value_wei,
                    draft.input_hex,
                    to_i64(draft.gas_limit)?,
                    draft.max_fee_per_gas.to_string(),
                    draft.max_priority_fee_per_gas.to_string(),
                    now(),
                ],
            )
            .map_err(store_err)?;
        if changed == 0 {
            return Err(EvmError::NonceConflict);
        }
        Ok(())
    }

    /// Reserve an explicit nonce for a replacement transaction. The original
    /// pending row must exist; `next_nonce` is not advanced.
    pub fn reserve_replacement(
        &self,
        chain_id: u64,
        address: &str,
        nonce: u64,
        draft: &TransactionDraft,
    ) -> Result<ReservedTransaction, EvmError> {
        let mut conn = self.conn.lock().map_err(lock_err)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_err)?;
        let active: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM evm_tx WHERE chain_id = ?1 AND address = ?2
                   AND nonce = ?3 AND status IN ('reserved','signed','pending','broadcast_unknown') LIMIT 1",
                params![to_i64(chain_id)?, address, to_i64(nonce)?],
                |r| r.get(0),
            )
            .optional()
            .map_err(store_err)?;
        if active.is_none() {
            return Err(EvmError::NonceConflict);
        }
        let timestamp = now();
        tx.execute(
            "INSERT INTO evm_tx
                (chain_id, address, nonce, status, to_addr, value_wei, input_hex,
                 gas_limit, max_fee_per_gas, max_priority_fee_per_gas, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'reserved', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                to_i64(chain_id)?,
                address,
                to_i64(nonce)?,
                draft.to,
                draft.value_wei,
                draft.input_hex,
                to_i64(draft.gas_limit)?,
                draft.max_fee_per_gas.to_string(),
                draft.max_priority_fee_per_gas.to_string(),
                timestamp,
            ],
        )
        .map_err(store_err)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(store_err)?;
        Ok(ReservedTransaction { id, nonce })
    }

    /// Expire abandoned `reserved`/`signed` rows older than the given age.
    /// Returns the number of rows expired.
    pub fn expire_stale(
        &self,
        chain_id: u64,
        address: &str,
        max_age_secs: i64,
    ) -> Result<u32, EvmError> {
        if max_age_secs <= 0 {
            return Err(EvmError::Store("max_age_secs must be positive".to_owned()));
        }
        let mut conn = self.conn.lock().map_err(lock_err)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_err)?;
        let cutoff = now() - max_age_secs;
        let expired = tx
            .execute(
                "UPDATE evm_tx SET status = 'failed', error = 'expired', updated_at = ?4
                 WHERE chain_id = ?1 AND address = ?2 AND status = 'reserved'
                   AND updated_at < ?3",
                params![to_i64(chain_id)?, address, cutoff, now()],
            )
            .map_err(store_err)?;
        let active_max: Option<i64> = tx
            .query_row(
                "SELECT MAX(nonce) FROM evm_tx
                 WHERE chain_id = ?1 AND address = ?2
                   AND status IN ('reserved','signed','pending','broadcast_unknown')",
                params![to_i64(chain_id)?, address],
                |r| r.get::<_, Option<i64>>(0),
            )
            .map_err(store_err)?;
        tx.execute(
            "UPDATE evm_nonce SET next_nonce = ?3, updated_at = ?4
             WHERE chain_id = ?1 AND address = ?2",
            params![
                to_i64(chain_id)?,
                address,
                active_max.map_or(0, |n| n + 1),
                now()
            ],
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)?;
        Ok(expired as u32)
    }

    pub fn mark_signed(&self, id: i64, tx_hash: &str, raw_tx: &str) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let changed = conn
            .execute(
                "UPDATE evm_tx SET status = 'signed', tx_hash = ?2, raw_tx = ?3, updated_at = ?4
                 WHERE id = ?1 AND status = 'reserved'",
                params![id, tx_hash, raw_tx, now()],
            )
            .map_err(store_err)?;
        if changed == 0 {
            return Err(EvmError::NonceConflict);
        }
        Ok(())
    }

    pub fn mark_broadcast(&self, id: i64, tx_hash: &str, raw_tx: &str) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let changed = conn
            .execute(
                "UPDATE evm_tx SET status = 'pending', tx_hash = ?2, raw_tx = ?3, updated_at = ?4
                 WHERE id = ?1 AND status IN ('reserved', 'signed')",
                params![id, tx_hash, raw_tx, now()],
            )
            .map_err(store_err)?;
        if changed == 0 {
            return Err(EvmError::NonceConflict);
        }
        Ok(())
    }

    /// Broadcast outcome is ambiguous (timeout/reset). The nonce must never be
    /// reused until reconciled against the network.
    pub fn mark_broadcast_unknown(&self, id: i64, error: &str) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.execute(
            "UPDATE evm_tx SET status = 'broadcast_unknown', error = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, error, now()],
        )
        .map_err(store_err)?;
        Ok(())
    }

    /// The node answered an explicit, definitive rejection of a signed transaction: it is not in the
    /// node's pool. Settle the row as `failed`, drop the hash and raw bytes (so an identical retry,
    /// which signs to the very same hash, does not collide with the unique hash index) and recompute
    /// the next nonce from the rows that are still active, so the nonce is reusable. Only valid for
    /// rows that were never confirmed `pending`; an ambiguous outcome must use
    /// [`Self::mark_broadcast_unknown`] instead.
    pub fn mark_rejected(&self, id: i64, error: &str) -> Result<(), EvmError> {
        let mut conn = self.conn.lock().map_err(lock_err)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_err)?;
        let row: Option<(i64, String)> = tx
            .query_row(
                "SELECT chain_id, address FROM evm_tx WHERE id = ?1 AND status IN ('reserved','signed')",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(store_err)?;
        let Some((chain_id, address)) = row else {
            return Err(EvmError::NonceConflict);
        };
        tx.execute(
            "UPDATE evm_tx SET status = 'failed', error = ?2, tx_hash = NULL, raw_tx = NULL, updated_at = ?3
             WHERE id = ?1",
            params![id, error, now()],
        )
        .map_err(store_err)?;
        let active_max: Option<i64> = tx
            .query_row(
                "SELECT MAX(nonce) FROM evm_tx
                 WHERE chain_id = ?1 AND address = ?2
                   AND status IN ('reserved','signed','pending','broadcast_unknown')",
                params![chain_id, address],
                |r| r.get::<_, Option<i64>>(0),
            )
            .map_err(store_err)?;
        tx.execute(
            "UPDATE evm_nonce SET next_nonce = ?3, updated_at = ?4
             WHERE chain_id = ?1 AND address = ?2",
            params![chain_id, address, active_max.map_or(0, |n| n + 1), now()],
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)?;
        Ok(())
    }

    pub fn mark_receipt(&self, id: i64, block_number: u64, success: bool) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let status = if success { "confirmed" } else { "reverted" };
        conn.execute(
            "UPDATE evm_tx SET status = ?2, block_number = ?3, updated_at = ?4 WHERE id = ?1",
            params![id, status, to_i64(block_number)?, now()],
        )
        .map_err(store_err)?;
        Ok(())
    }

    pub fn mark_failed(&self, id: i64, error: &str) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.execute(
            "UPDATE evm_tx SET status = 'failed', error = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, error, now()],
        )
        .map_err(store_err)?;
        Ok(())
    }

    /// Release a nonce only when it is the highest reservation and was never
    /// broadcast. This prevents accidental reuse of an in-flight nonce.
    pub fn release_nonce(&self, id: i64) -> Result<bool, EvmError> {
        let mut conn = self.conn.lock().map_err(lock_err)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_err)?;
        let row: Option<(i64, String, i64, String)> = tx
            .query_row(
                "SELECT chain_id, address, nonce, status FROM evm_tx WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(store_err)?;
        let Some((chain_id, address, nonce, status)) = row else {
            return Err(EvmError::Store("transaction not found".to_owned()));
        };
        if status != "reserved" {
            return Ok(false);
        }
        let max_nonce: Option<i64> = tx
            .query_row(
                "SELECT MAX(nonce) FROM evm_tx
                 WHERE chain_id = ?1 AND address = ?2 AND status NOT IN ('failed')",
                params![chain_id, address],
                |r| r.get::<_, Option<i64>>(0),
            )
            .map_err(store_err)?;
        if max_nonce != Some(nonce) {
            return Ok(false);
        }
        tx.execute(
            "UPDATE evm_tx SET status = 'failed', error = 'released', updated_at = ?2 WHERE id = ?1",
            params![id, now()],
        )
        .map_err(store_err)?;
        tx.execute(
            "UPDATE evm_nonce SET next_nonce = ?3, updated_at = ?4
             WHERE chain_id = ?1 AND address = ?2",
            params![chain_id, address, nonce, now()],
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)?;
        Ok(true)
    }

    /// Reconcile local reservations with the network's next nonce.
    pub fn reconcile_nonce(
        &self,
        chain_id: u64,
        address: &str,
        network_nonce: u64,
    ) -> Result<u64, EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let active_max: Option<i64> = conn
            .query_row(
                "SELECT MAX(nonce) FROM evm_tx
                 WHERE chain_id = ?1 AND address = ?2
                   AND status IN ('reserved','signed','pending','broadcast_unknown')",
                params![to_i64(chain_id)?, address],
                |r| r.get::<_, Option<i64>>(0),
            )
            .map_err(store_err)?;
        let next = to_i64(network_nonce)?
            .max(active_max.map_or(0, |n| n + 1))
            .max(0);
        conn.execute(
            "INSERT INTO evm_nonce (chain_id, address, next_nonce, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(chain_id, address) DO UPDATE
             SET next_nonce = MAX(evm_nonce.next_nonce, excluded.next_nonce),
                 updated_at = excluded.updated_at",
            params![to_i64(chain_id)?, address, next, now()],
        )
        .map_err(store_err)?;
        u64::try_from(next).map_err(|_| EvmError::NonceConflict)
    }

    pub fn next_nonce(&self, chain_id: u64, address: &str) -> Result<Option<u64>, EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let value: Option<i64> = conn
            .query_row(
                "SELECT next_nonce FROM evm_nonce WHERE chain_id = ?1 AND address = ?2",
                params![to_i64(chain_id)?, address],
                |r| r.get(0),
            )
            .optional()
            .map_err(store_err)?;
        value
            .map(|n| u64::try_from(n).map_err(|_| EvmError::NonceConflict))
            .transpose()
    }

    pub fn history(
        &self,
        chain_id: u64,
        address: &str,
        limit: u32,
        before_id: Option<i64>,
    ) -> Result<Vec<StoredTransaction>, EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let limit = limit.clamp(1, 100);
        let mut stmt = conn
            .prepare(
                "SELECT id, chain_id, address, nonce, tx_hash, status, to_addr, value_wei,
                        input_hex, gas_limit, max_fee_per_gas, max_priority_fee_per_gas,
                        block_number, error
                 FROM evm_tx
                 WHERE chain_id = ?1 AND address = ?2 AND (?3 IS NULL OR id < ?3)
                 ORDER BY id DESC LIMIT ?4",
            )
            .map_err(store_err)?;
        let rows = stmt
            .query_map(
                params![to_i64(chain_id)?, address, before_id, i64::from(limit)],
                |r| {
                    Ok(StoredTransaction {
                        id: r.get(0)?,
                        chain_id: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                        address: r.get(2)?,
                        nonce: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                        tx_hash: r.get(4)?,
                        status: r.get(5)?,
                        to: r.get(6)?,
                        value_wei: r.get(7)?,
                        input_hex: r.get(8)?,
                        gas_limit: u64::try_from(r.get::<_, i64>(9)?).unwrap_or(0),
                        max_fee_per_gas: r.get(10)?,
                        max_priority_fee_per_gas: r.get(11)?,
                        block_number: r
                            .get::<_, Option<i64>>(12)?
                            .and_then(|n| u64::try_from(n).ok()),
                        error: r.get(13)?,
                    })
                },
            )
            .map_err(store_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_err)
    }

    pub fn upsert_token(&self, token: &TokenRecord) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.execute(
            "INSERT INTO evm_token (chain_id, contract, symbol, name, decimals, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(chain_id, contract) DO UPDATE SET
               symbol = excluded.symbol, name = excluded.name,
               decimals = excluded.decimals, updated_at = excluded.updated_at",
            params![
                to_i64(token.chain_id)?,
                token.contract,
                token.symbol,
                token.name,
                token.decimals.map(i64::from),
                now()
            ],
        )
        .map_err(store_err)?;
        Ok(())
    }

    pub fn tokens(&self, chain_id: u64) -> Result<Vec<TokenRecord>, EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let mut stmt = conn
            .prepare(
                "SELECT chain_id, contract, symbol, name, decimals
                 FROM evm_token WHERE chain_id = ?1 ORDER BY contract",
            )
            .map_err(store_err)?;
        let rows = stmt
            .query_map([to_i64(chain_id)?], |r| {
                Ok(TokenRecord {
                    chain_id: u64::try_from(r.get::<_, i64>(0)?).unwrap_or(0),
                    contract: r.get(1)?,
                    symbol: r.get(2)?,
                    name: r.get(3)?,
                    decimals: r
                        .get::<_, Option<i64>>(4)?
                        .and_then(|d| u8::try_from(d).ok()),
                })
            })
            .map_err(store_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_err)
    }

    /// Explicitly set a checkpoint. Lower values are allowed so callers can
    /// rewind after a reorg; use [`Self::advance_sync_checkpoint`] for normal
    /// forward-only progress.
    pub fn set_sync_checkpoint(
        &self,
        chain_id: u64,
        address: &str,
        block: u64,
    ) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.execute(
            "INSERT INTO evm_sync (chain_id, address, last_block, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(chain_id, address) DO UPDATE SET
               last_block = excluded.last_block,
               updated_at = excluded.updated_at",
            params![to_i64(chain_id)?, address, to_i64(block)?, now()],
        )
        .map_err(store_err)?;
        Ok(())
    }

    /// Advance a checkpoint monotonically.
    pub fn advance_sync_checkpoint(
        &self,
        chain_id: u64,
        address: &str,
        block: u64,
    ) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.execute(
            "INSERT INTO evm_sync (chain_id, address, last_block, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(chain_id, address) DO UPDATE SET
               last_block = MAX(evm_sync.last_block, excluded.last_block),
               updated_at = excluded.updated_at",
            params![to_i64(chain_id)?, address, to_i64(block)?, now()],
        )
        .map_err(store_err)?;
        Ok(())
    }

    pub fn sync_checkpoint(&self, chain_id: u64, address: &str) -> Result<Option<u64>, EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let block: Option<i64> = conn
            .query_row(
                "SELECT last_block FROM evm_sync WHERE chain_id = ?1 AND address = ?2",
                params![to_i64(chain_id)?, address],
                |r| r.get(0),
            )
            .optional()
            .map_err(store_err)?;
        block
            .map(|b| u64::try_from(b).map_err(|_| EvmError::Store("negative block".to_owned())))
            .transpose()
    }

    /// Reject a store whose existing rows belong to another chain/account.
    pub fn assert_scope(&self, chain_id: u64, address: &str) -> Result<(), EvmError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        let other: Option<String> = conn
            .query_row(
                "SELECT address FROM evm_account WHERE chain_id = ?1 AND address <> ?2 LIMIT 1",
                params![to_i64(chain_id)?, address],
                |r| r.get(0),
            )
            .optional()
            .map_err(store_err)?;
        if other.is_some() {
            return Err(EvmError::Store("database account mismatch".to_owned()));
        }
        Ok(())
    }
}

fn to_i64<T>(value: T) -> Result<i64, EvmError>
where
    T: TryInto<i64> + Copy,
{
    value.try_into().map_err(|_| EvmError::NonceConflict)
}

fn store_err(e: rusqlite::Error) -> EvmError {
    EvmError::Store(e.to_string())
}

fn lock_err<T>(_: T) -> EvmError {
    EvmError::Store("store lock poisoned".to_owned())
}

/// Fetch a receipt and update the local record; returns `(confirmed, block)`.
pub async fn reconcile_receipt(
    store: &EvmStore,
    provider: &EvmProvider,
    id: i64,
    tx_hash: crate::B256,
) -> Result<Option<bool>, EvmError> {
    let receipt = provider.receipt(tx_hash).await?;
    match receipt {
        Some(receipt) => {
            store.mark_receipt(id, receipt.block_number.unwrap_or_default(), receipt.status)?;
            Ok(Some(receipt.status))
        }
        None => Ok(None),
    }
}
