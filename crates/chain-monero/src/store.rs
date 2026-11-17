//! Local Monero wallet state (SQLite). Holds public/derived data only: serialized outputs (which contain the
//! output keys and amounts, no spend secret), key images, history and the scan checkpoint. The vault, not this
//! file, holds the keys.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::MoneroError;

fn db(e: rusqlite::Error) -> MoneroError {
    MoneroError::Store(e.to_string())
}

pub struct MoneroStore {
    conn: Connection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedOutput {
    pub id: i64,
    pub txid: [u8; 32],
    pub index_in_tx: u64,
    pub amount: u64,
    pub height: u64,
    pub key_image: [u8; 32],
    pub subaddress: Option<(u32, u32)>,
    /// Unlock height from an additional timelock, 0 if none.
    pub timelock_height: u64,
    pub blob: Vec<u8>,
    pub spent_in: Option<[u8; 32]>,
    /// Outputs reserved by a prepared (not yet published/failed) send.
    pub reserved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRecord {
    pub txid: [u8; 32],
    /// `in` or `out`.
    pub direction: String,
    pub amount: u64,
    pub fee: u64,
    pub height: Option<u64>,
    /// `pending`, `confirmed`, `failed`, `expired`.
    pub status: String,
    pub counterparty: Option<String>,
    pub created_ms: u64,
}

fn h32(v: Vec<u8>) -> Result<[u8; 32], rusqlite::Error> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)
}

impl MoneroStore {
    pub fn open(path: &Path) -> Result<Self, MoneroError> {
        let conn = Connection::open(path).map_err(db)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS xmr_meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS xmr_output(
               id INTEGER PRIMARY KEY AUTOINCREMENT, txid BLOB NOT NULL, idx INTEGER NOT NULL, amount INTEGER NOT NULL,
               height INTEGER NOT NULL, key_image BLOB NOT NULL UNIQUE, sub_account INTEGER, sub_index INTEGER,
               timelock INTEGER NOT NULL DEFAULT 0, blob BLOB NOT NULL, spent_in BLOB, reserved INTEGER NOT NULL DEFAULT 0,
               UNIQUE(txid, idx));
             CREATE TABLE IF NOT EXISTS xmr_tx(
               txid BLOB PRIMARY KEY, direction TEXT NOT NULL, amount INTEGER NOT NULL, fee INTEGER NOT NULL DEFAULT 0,
               height INTEGER, status TEXT NOT NULL, counterparty TEXT, created_ms INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS xmr_block(height INTEGER PRIMARY KEY, hash BLOB NOT NULL);",
        )
        .map_err(db)?;
        Ok(Self { conn })
    }

    /// One store file belongs to one (network, primary address, account).
    pub fn register_account(
        &self,
        network: &str,
        address: &str,
        restore_height: u64,
    ) -> Result<(), MoneroError> {
        let want = format!("{network}|{address}");
        let have: Option<String> = self
            .conn
            .query_row("SELECT v FROM xmr_meta WHERE k='account'", [], |r| r.get(0))
            .optional()
            .map_err(db)?;
        match have {
            None => {
                // One transaction: a process killed in the middle must not leave an account row without its restore
                // height and scan checkpoint (the next start would then trust a half-registered store).
                let transaction = self.conn.unchecked_transaction().map_err(db)?;
                self.conn
                    .execute("INSERT INTO xmr_meta(k,v) VALUES('account',?1)", [&want])
                    .map_err(db)?;
                self.set_meta("restore_height", &restore_height.to_string())?;
                self.set_meta("last_issued_subaddress", "0")?;
                self.set_meta(
                    "scanned_height",
                    &(i64::try_from(restore_height).map_err(|_| {
                        MoneroError::Store("restore height is too large".to_owned())
                    })? - 1)
                        .to_string(),
                )?;
                transaction.commit().map_err(db)?;
                Ok(())
            }
            Some(h) if h == want => Ok(()),
            Some(_) => Err(MoneroError::Store(
                "this store belongs to another account or network".to_owned(),
            )),
        }
    }

    /// SQLite's own consistency check (`PRAGMA integrity_check`), used after an abrupt termination.
    pub fn integrity_ok(&self) -> Result<bool, MoneroError> {
        let answer: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(db)?;
        Ok(answer == "ok")
    }

    pub fn set_meta(&self, k: &str, v: &str) -> Result<(), MoneroError> {
        self.conn
            .execute(
                "INSERT INTO xmr_meta(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                [k, v],
            )
            .map_err(db)?;
        Ok(())
    }

    /// Legacy wallets could display indexes 1..=20 without persisting them. Treat
    /// all of these as issued during migration, so a restart never reuses one.
    pub fn last_issued_subaddress(&self) -> Result<u32, MoneroError> {
        let value = self.meta("last_issued_subaddress")?;
        match value {
            None => Ok(20),
            Some(v) => v
                .parse::<u32>()
                .ok()
                .filter(|i| *i <= 10_000)
                .ok_or_else(|| MoneroError::Store("invalid subaddress high-water mark".to_owned())),
        }
    }

    pub fn watch_subaddress(&self, index: u32) -> Result<(), MoneroError> {
        if index > 10_000 {
            return Err(MoneroError::Store(
                "subaddress index exceeds the supported 10000".to_owned(),
            ));
        }
        let high = self.last_issued_subaddress()?.max(index);
        self.set_meta("last_issued_subaddress", &high.to_string())
    }

    /// Allocate and persist before displaying the address. A crash can skip an
    /// index, but must never cause an already displayed address to be reissued.
    pub fn next_subaddress(&self) -> Result<u32, MoneroError> {
        self.apply_block(|| {
            let next = self.last_issued_subaddress()? + 1;
            self.watch_subaddress(next)?;
            Ok(next)
        })
    }

    /// Commit all changes for one scanned block together. An interrupted or failed scan
    /// must not leave deduplicated outputs behind without their history/checkpoint.
    pub(crate) fn apply_block<T>(
        &self,
        apply: impl FnOnce() -> Result<T, MoneroError>,
    ) -> Result<T, MoneroError> {
        let transaction = self.conn.unchecked_transaction().map_err(db)?;
        let result = apply()?;
        transaction.commit().map_err(db)?;
        Ok(result)
    }

    pub fn meta(&self, k: &str) -> Result<Option<String>, MoneroError> {
        self.conn
            .query_row("SELECT v FROM xmr_meta WHERE k=?1", [k], |r| r.get(0))
            .optional()
            .map_err(db)
    }

    pub fn restore_height(&self) -> Result<u64, MoneroError> {
        Ok(self
            .meta("restore_height")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    /// Height of the last fully scanned block (restore_height - 1 before the first scan).
    pub fn scanned_height(&self) -> Result<i64, MoneroError> {
        Ok(self
            .meta("scanned_height")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(-1))
    }

    pub fn set_scanned(&self, height: u64) -> Result<(), MoneroError> {
        self.set_meta("scanned_height", &height.to_string())
    }

    pub fn record_block(&self, height: u64, hash: &[u8; 32]) -> Result<(), MoneroError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO xmr_block(height,hash) VALUES(?1,?2)",
                params![height as i64, hash.as_slice()],
            )
            .map_err(db)?;
        self.conn
            .execute(
                "DELETE FROM xmr_block WHERE height < ?1",
                [height as i64 - 200],
            )
            .map_err(db)?;
        Ok(())
    }

    pub fn block_hash(&self, height: u64) -> Result<Option<[u8; 32]>, MoneroError> {
        let v: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT hash FROM xmr_block WHERE height=?1",
                [height as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        v.map(|v| {
            <[u8; 32]>::try_from(v.as_slice())
                .map_err(|_| MoneroError::Store("bad block hash".to_owned()))
        })
        .transpose()
    }

    /// Insert an owned output; duplicates (same tx and index) are ignored.
    pub fn add_output(&self, o: &OwnedOutput) -> Result<bool, MoneroError> {
        let n = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO xmr_output(txid,idx,amount,height,key_image,sub_account,sub_index,timelock,blob)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    o.txid.as_slice(), o.index_in_tx as i64, o.amount as i64, o.height as i64, o.key_image.as_slice(),
                    o.subaddress.map(|s| i64::from(s.0)), o.subaddress.map(|s| i64::from(s.1)), o.timelock_height as i64, o.blob
                ],
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    fn map_output(r: &rusqlite::Row<'_>) -> Result<OwnedOutput, rusqlite::Error> {
        let sub_a: Option<i64> = r.get(6)?;
        let sub_i: Option<i64> = r.get(7)?;
        let spent: Option<Vec<u8>> = r.get(10)?;
        Ok(OwnedOutput {
            id: r.get(0)?,
            txid: h32(r.get(1)?)?,
            index_in_tx: r.get::<_, i64>(2)? as u64,
            amount: r.get::<_, i64>(3)? as u64,
            height: r.get::<_, i64>(4)? as u64,
            key_image: h32(r.get(5)?)?,
            subaddress: sub_a.zip(sub_i).map(|(a, i)| (a as u32, i as u32)),
            timelock_height: r.get::<_, i64>(8)? as u64,
            blob: r.get(9)?,
            spent_in: spent.map(h32).transpose()?,
            reserved: r.get::<_, i64>(11)? != 0,
        })
    }

    const OUT_COLS: &'static str =
        "id,txid,idx,amount,height,key_image,sub_account,sub_index,timelock,blob,spent_in,reserved";

    pub fn outputs(&self) -> Result<Vec<OwnedOutput>, MoneroError> {
        let sql = format!(
            "SELECT {} FROM xmr_output ORDER BY height,id",
            Self::OUT_COLS
        );
        let mut stmt = self.conn.prepare(&sql).map_err(db)?;
        let rows = stmt.query_map([], Self::map_output).map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    }

    pub fn mark_spent(&self, key_image: &[u8; 32], txid: &[u8; 32]) -> Result<bool, MoneroError> {
        let n = self
            .conn
            .execute(
                "UPDATE xmr_output SET spent_in=?2, reserved=0 WHERE key_image=?1 AND spent_in IS NULL",
                params![key_image.as_slice(), txid.as_slice()],
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    pub fn reserve(&self, ids: &[i64], on: bool) -> Result<(), MoneroError> {
        for id in ids {
            self.conn
                .execute(
                    "UPDATE xmr_output SET reserved=?2 WHERE id=?1",
                    params![id, i64::from(on)],
                )
                .map_err(db)?;
        }
        Ok(())
    }

    pub fn unreserve_all(&self) -> Result<(), MoneroError> {
        self.conn
            .execute("UPDATE xmr_output SET reserved=0", [])
            .map_err(db)?;
        Ok(())
    }

    pub fn upsert_tx(&self, t: &TxRecord) -> Result<(), MoneroError> {
        self.conn
            .execute(
                "INSERT INTO xmr_tx(txid,direction,amount,fee,height,status,counterparty,created_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(txid) DO UPDATE SET height=excluded.height, status=excluded.status",
                params![t.txid.as_slice(), t.direction, t.amount as i64, t.fee as i64, t.height.map(|h| h as i64), t.status, t.counterparty, t.created_ms as i64],
            )
            .map_err(db)?;
        Ok(())
    }

    pub fn set_tx_status(
        &self,
        txid: &[u8; 32],
        status: &str,
        height: Option<u64>,
    ) -> Result<(), MoneroError> {
        self.conn
            .execute(
                "UPDATE xmr_tx SET status=?2, height=COALESCE(?3,height) WHERE txid=?1",
                params![txid.as_slice(), status, height.map(|h| h as i64)],
            )
            .map_err(db)?;
        Ok(())
    }

    pub fn history(&self, limit: u32) -> Result<Vec<TxRecord>, MoneroError> {
        let mut stmt = self
            .conn
            .prepare("SELECT txid,direction,amount,fee,height,status,counterparty,created_ms FROM xmr_tx ORDER BY COALESCE(height, 9223372036854775807) DESC, created_ms DESC LIMIT ?1")
            .map_err(db)?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok(TxRecord {
                    txid: h32(r.get(0)?)?,
                    direction: r.get(1)?,
                    amount: r.get::<_, i64>(2)? as u64,
                    fee: r.get::<_, i64>(3)? as u64,
                    height: r.get::<_, Option<i64>>(4)?.map(|h| h as u64),
                    status: r.get(5)?,
                    counterparty: r.get(6)?,
                    created_ms: r.get::<_, i64>(7)? as u64,
                })
            })
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    }

    /// Drop everything above `height` (reorg): outputs found there, spends recorded there, history rows, block hashes.
    pub fn rollback_to(&self, height: u64) -> Result<(), MoneroError> {
        let h = height as i64;
        // outputs created above the fork are gone
        self.conn
            .execute("DELETE FROM xmr_output WHERE height > ?1", [h])
            .map_err(db)?;
        // spends confirmed above the fork are undone: outputs become unspent again (the tx may be re-mined)
        self.conn
            .execute(
                "UPDATE xmr_output SET spent_in=NULL, reserved=1 WHERE spent_in IN (SELECT txid FROM xmr_tx WHERE height > ?1)",
                [h],
            )
            .map_err(db)?;
        self.conn.execute("UPDATE xmr_tx SET status='pending', height=NULL WHERE direction='out' AND height > ?1", [h]).map_err(db)?;
        self.conn
            .execute(
                "DELETE FROM xmr_tx WHERE direction='in' AND height > ?1",
                [h],
            )
            .map_err(db)?;
        self.conn
            .execute("DELETE FROM xmr_block WHERE height > ?1", [h])
            .map_err(db)?;
        self.set_scanned(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_subaddresses_never_repeat_after_restart_or_legacy_migration() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("addresses.sqlite");
        let store = MoneroStore::open(&path).unwrap();
        store
            .register_account("monero-stagenet", "primary", 0)
            .unwrap();
        for index in 1..=25 {
            assert_eq!(store.next_subaddress().unwrap(), index);
        }
        drop(store);
        let store = MoneroStore::open(&path).unwrap();
        assert_eq!(store.next_subaddress().unwrap(), 26);
        store.watch_subaddress(50).unwrap();
        assert_eq!(store.next_subaddress().unwrap(), 51);
        assert!(store.watch_subaddress(10_001).is_err());
        store
            .conn
            .execute("DELETE FROM xmr_meta WHERE k='last_issued_subaddress'", [])
            .unwrap();
        assert_eq!(
            store.next_subaddress().unwrap(),
            21,
            "legacy displayed addresses are not reused"
        );
    }

    fn out(n: u8, height: u64) -> OwnedOutput {
        OwnedOutput {
            id: 0,
            txid: [n; 32],
            index_in_tx: 0,
            amount: 1_000_000_000_000,
            height,
            key_image: [n.wrapping_add(100); 32],
            subaddress: None,
            timelock_height: 0,
            blob: vec![1, 2, 3],
            spent_in: None,
            reserved: false,
        }
    }

    #[test]
    fn genesis_restore_and_failed_block_are_recoverable_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("restore.db");
        let store = MoneroStore::open(&path).unwrap();
        store
            .register_account("monero-stagenet", "5abc", 0)
            .unwrap();
        assert_eq!(
            store.scanned_height().unwrap(),
            -1,
            "genesis must be scanned"
        );
        let failed: Result<(), MoneroError> = store.apply_block(|| {
            store.add_output(&out(1, 2))?;
            store.record_block(2, &[2; 32])?;
            store.set_scanned(2)?;
            Err(MoneroError::Scan(
                "interrupted before history was written".into(),
            ))
        });
        assert!(failed.is_err());
        drop(store);
        let store = MoneroStore::open(&path).unwrap();
        assert!(store.outputs().unwrap().is_empty());
        assert!(store.block_hash(2).unwrap().is_none());
        assert_eq!(store.scanned_height().unwrap(), -1);
        store
            .apply_block(|| {
                assert!(store.add_output(&out(1, 2))?);
                store.upsert_tx(&TxRecord {
                    txid: [1; 32],
                    direction: "in".into(),
                    amount: 1_000_000_000_000,
                    fee: 0,
                    height: Some(2),
                    status: "confirmed".into(),
                    counterparty: None,
                    created_ms: 0,
                })?;
                store.record_block(2, &[2; 32])?;
                store.set_scanned(2)
            })
            .unwrap();
        drop(store);
        let reopened = MoneroStore::open(&path).unwrap();
        assert_eq!(reopened.outputs().unwrap().len(), 1);
        assert_eq!(reopened.history(10).unwrap().len(), 1);
        assert_eq!(reopened.scanned_height().unwrap(), 2);
    }

    #[test]
    fn outputs_dedupe_spend_and_reorg() {
        let dir = tempfile::tempdir().unwrap();
        let s = MoneroStore::open(&dir.path().join("x.db")).unwrap();
        s.register_account("monero-stagenet", "5abc", 100).unwrap();
        assert!(
            s.register_account("monero-stagenet", "5other", 100)
                .is_err()
        );
        assert!(s.register_account("monero-mainnet", "5abc", 100).is_err());
        assert_eq!(s.scanned_height().unwrap(), 99);
        assert!(s.add_output(&out(1, 120)).unwrap());
        assert!(
            !s.add_output(&out(1, 120)).unwrap(),
            "same output twice is ignored"
        );
        assert!(s.add_output(&out(2, 130)).unwrap());
        assert!(s.mark_spent(&[101; 32], &[9; 32]).unwrap());
        assert!(
            !s.mark_spent(&[101; 32], &[8; 32]).unwrap(),
            "an already spent output is not respent"
        );
        s.upsert_tx(&TxRecord {
            txid: [9; 32],
            direction: "out".into(),
            amount: 5,
            fee: 1,
            height: Some(135),
            status: "confirmed".into(),
            counterparty: None,
            created_ms: 1,
        })
        .unwrap();
        s.set_scanned(140).unwrap();
        // reorg back to 125: output at 130 vanishes; the spend at 135 is undone
        s.rollback_to(125).unwrap();
        let outs = s.outputs().unwrap();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].spent_in, None);
        assert!(
            outs[0].reserved,
            "a reorged signed spend must remain reserved"
        );
        assert_eq!(s.scanned_height().unwrap(), 125);
        assert_eq!(s.history(10).unwrap()[0].status, "pending");
        drop(s);
        let s = MoneroStore::open(&dir.path().join("x.db")).unwrap();
        assert_eq!(s.outputs().unwrap().len(), 1, "state survives a restart");
    }
}
