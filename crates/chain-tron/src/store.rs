//! Local TRON transaction ledger (SQLite). It holds public data only: no key, no authorization.
//!
//! Statuses: `signed` (txid persisted before the broadcast), `broadcast_unknown` (ambiguous network
//! answer), `pending` (accepted or included but not yet final), `confirmed`, `failed` (included but the
//! execution failed), `rejected` (the node definitively refused it) and `expired` (the expiration passed
//! without inclusion, so it can never be included later).

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::TronError;

pub struct TronStore {
    conn: Connection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TronRecord {
    pub id: i64,
    pub txid: String,
    pub kind: String,
    pub to: String,
    pub contract: Option<String>,
    pub amount_raw: String,
    pub symbol: String,
    pub decimals: u8,
    pub fee_limit_sun: u64,
    pub status: String,
    pub block_number: Option<u64>,
    pub expiration_ms: u64,
    pub raw_hex: String,
    pub error: Option<String>,
    pub created_ms: u64,
}

pub struct NewRecord<'a> {
    pub txid: &'a str,
    pub kind: &'a str,
    pub to: &'a str,
    pub contract: Option<&'a str>,
    pub amount_raw: &'a str,
    pub symbol: &'a str,
    pub decimals: u8,
    pub fee_limit_sun: u64,
    pub expiration_ms: u64,
    pub raw_hex: &'a str,
    pub created_ms: u64,
}

fn db(e: rusqlite::Error) -> TronError {
    TronError::Store(e.to_string())
}

impl TronStore {
    pub fn open(path: &Path) -> Result<Self, TronError> {
        let conn = Connection::open(path).map_err(db)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS tron_meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS tron_tx(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               network TEXT NOT NULL, owner TEXT NOT NULL, txid TEXT NOT NULL UNIQUE,
               kind TEXT NOT NULL, to_addr TEXT NOT NULL, contract TEXT,
               amount_raw TEXT NOT NULL, symbol TEXT NOT NULL, decimals INTEGER NOT NULL,
               fee_limit_sun INTEGER NOT NULL, status TEXT NOT NULL, block_number INTEGER,
               expiration_ms INTEGER NOT NULL, raw_hex TEXT NOT NULL, error TEXT, created_ms INTEGER NOT NULL);",
        )
        .map_err(db)?;
        Ok(Self { conn })
    }

    /// A store file belongs to exactly one (network, owner); anything else is refused.
    pub fn register_account(&self, network: &str, owner: &str) -> Result<(), TronError> {
        let want = format!("{network}|{owner}");
        let have: Option<String> = self
            .conn
            .query_row("SELECT v FROM tron_meta WHERE k='account'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db)?;
        match have {
            None => {
                self.conn
                    .execute("INSERT INTO tron_meta(k,v) VALUES('account',?1)", [&want])
                    .map_err(db)?;
                Ok(())
            }
            Some(h) if h == want => Ok(()),
            Some(_) => Err(TronError::Store(
                "this store belongs to another account or network".to_owned(),
            )),
        }
    }

    fn account(&self) -> Result<(String, String), TronError> {
        let v: String = self
            .conn
            .query_row("SELECT v FROM tron_meta WHERE k='account'", [], |r| {
                r.get(0)
            })
            .map_err(db)?;
        let (n, o) = v
            .split_once('|')
            .ok_or_else(|| TronError::Store("corrupt account row".to_owned()))?;
        Ok((n.to_owned(), o.to_owned()))
    }

    /// Persist a signed transaction BEFORE it is broadcast, so a lost answer is recoverable by txid.
    pub fn insert_signed(&self, r: &NewRecord<'_>) -> Result<i64, TronError> {
        let (network, owner) = self.account()?;
        self.conn
            .execute(
                "INSERT INTO tron_tx(network,owner,txid,kind,to_addr,contract,amount_raw,symbol,decimals,fee_limit_sun,status,expiration_ms,raw_hex,created_ms)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'signed',?11,?12,?13)",
                params![network, owner, r.txid, r.kind, r.to, r.contract, r.amount_raw, r.symbol, r.decimals, r.fee_limit_sun as i64, r.expiration_ms as i64, r.raw_hex, r.created_ms as i64],
            )
            .map_err(db)?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn set_status(
        &self,
        id: i64,
        status: &str,
        block: Option<u64>,
        error: Option<&str>,
    ) -> Result<(), TronError> {
        self.conn
            .execute(
                "UPDATE tron_tx SET status=?2, block_number=COALESCE(?3,block_number), error=?4 WHERE id=?1",
                params![id, status, block.map(|b| b as i64), error],
            )
            .map_err(db)?;
        Ok(())
    }

    pub fn get(&self, id: i64) -> Result<Option<TronRecord>, TronError> {
        self.query("WHERE id=?1", params![id]).map(|mut v| v.pop())
    }

    /// Newest first.
    pub fn history(&self, limit: u32) -> Result<Vec<TronRecord>, TronError> {
        self.query("ORDER BY id DESC LIMIT ?1", params![limit])
    }

    /// Rows whose outcome is not final yet.
    pub fn unsettled(&self) -> Result<Vec<TronRecord>, TronError> {
        self.query(
            "WHERE status IN ('signed','broadcast_unknown','pending') ORDER BY id",
            params![],
        )
    }

    fn query(&self, tail: &str, p: impl rusqlite::Params) -> Result<Vec<TronRecord>, TronError> {
        let sql = format!(
            "SELECT id,txid,kind,to_addr,contract,amount_raw,symbol,decimals,fee_limit_sun,status,block_number,expiration_ms,raw_hex,error,created_ms FROM tron_tx {tail}"
        );
        let mut stmt = self.conn.prepare(&sql).map_err(db)?;
        let rows = stmt
            .query_map(p, |r| {
                Ok(TronRecord {
                    id: r.get(0)?,
                    txid: r.get(1)?,
                    kind: r.get(2)?,
                    to: r.get(3)?,
                    contract: r.get(4)?,
                    amount_raw: r.get(5)?,
                    symbol: r.get(6)?,
                    decimals: r.get::<_, i64>(7)? as u8,
                    fee_limit_sun: r.get::<_, i64>(8)? as u64,
                    status: r.get(9)?,
                    block_number: r.get::<_, Option<i64>>(10)?.map(|b| b as u64),
                    expiration_ms: r.get::<_, i64>(11)? as u64,
                    raw_hex: r.get(12)?,
                    error: r.get(13)?,
                    created_ms: r.get::<_, i64>(14)? as u64,
                })
            })
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(txid: &str) -> NewRecord<'_> {
        NewRecord {
            txid,
            kind: "trx",
            to: "TTo",
            contract: None,
            amount_raw: "1000000",
            symbol: "TRX",
            decimals: 6,
            fee_limit_sun: 0,
            expiration_ms: 5_000,
            raw_hex: "00",
            created_ms: 1,
        }
    }

    #[test]
    fn lifecycle_and_account_binding() {
        let dir = tempfile::tempdir().unwrap();
        let s = TronStore::open(&dir.path().join("t.db")).unwrap();
        s.register_account("tron-nile", "TOwner").unwrap();
        s.register_account("tron-nile", "TOwner").unwrap();
        assert!(s.register_account("tron-nile", "TOther").is_err());
        assert!(s.register_account("tron-mainnet", "TOwner").is_err());
        let id = s.insert_signed(&rec("aa")).unwrap();
        assert!(
            s.insert_signed(&rec("aa")).is_err(),
            "txid is unique: no duplicate rows"
        );
        assert_eq!(s.unsettled().unwrap().len(), 1);
        s.set_status(id, "pending", Some(7), None).unwrap();
        s.set_status(id, "confirmed", None, None).unwrap();
        let r = s.get(id).unwrap().unwrap();
        assert_eq!((r.status.as_str(), r.block_number), ("confirmed", Some(7)));
        assert!(s.unsettled().unwrap().is_empty());
        // survives a reopen
        drop(s);
        let s = TronStore::open(&dir.path().join("t.db")).unwrap();
        assert_eq!(s.history(10).unwrap().len(), 1);
    }
}
