//! Watch-only Bitcoin Cash Core synchronization and SQLite persistence.
//!
//! The engine never sees a seed or private key. It derives public addresses
//! from an account xpub, imports them into a disposable node wallet, and
//! returns unsigned transactions for external authorization/signing.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use rusqlite::{Connection as Sqlite, params};
use serde::{Deserialize, Serialize};
use shadowallet_chain_utxo::{FeeEstimate, UtxoBalance, UtxoHistoryEntry};

use crate::{
    BchError, BchNetwork, BchPublicAccount, BchWatchAccount, CashAddress, UnsignedTransfer,
    build_unsigned,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BchUtxo {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub confirmations: u32,
    pub keychain: u32,
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BchSyncReport {
    pub tip_height: u64,
    pub utxos: usize,
    pub history: usize,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    network: String,
    fingerprint: String,
    external_index: u32,
    change_index: u32,
    history: Vec<UtxoHistoryEntry>,
}

pub struct BchEngine {
    account: BchWatchAccount,
    rpc: Client,
    db: Sqlite,
    addresses: Vec<(u32, u32, CashAddress, ScriptBuf)>,
    utxos: Vec<BchUtxo>,
    history: Vec<UtxoHistoryEntry>,
    external_index: u32,
    change_index: u32,
}

impl std::fmt::Debug for BchEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BchEngine")
            .field("network", &self.account.network)
            .field("utxos", &self.utxos.len())
            .finish_non_exhaustive()
    }
}

fn coin_per_kvb_to_sat_vb(value: f64) -> Option<u64> {
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    Some(((value * 100_000_000.0 / 1000.0).ceil() as u64).max(1))
}

impl BchEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        network: BchNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
        rpc_url: &str,
        rpc_user: &str,
        rpc_password: &str,
        db_path: &Path,
        lookahead: u32,
    ) -> Result<Self, BchError> {
        let account = BchWatchAccount::from_xpub(network, xpub, fingerprint)?;
        let rpc = Client::new(
            rpc_url,
            Auth::UserPass(rpc_user.to_owned(), rpc_password.to_owned()),
        )
        .map_err(|e| BchError::Transaction(e.to_string()))?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| BchError::Transaction(e.to_string()))?;
        }
        let db = Sqlite::open(db_path).map_err(|e| BchError::Transaction(e.to_string()))?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|e| BchError::Transaction(format!("database unreadable: {e}")))?;
        if integrity != "ok" {
            return Err(BchError::Transaction(format!(
                "database integrity check failed: {integrity}"
            )));
        }
        db.execute_batch("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);")
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        let mut engine = Self {
            account,
            rpc,
            db,
            addresses: Vec::new(),
            utxos: Vec::new(),
            history: Vec::new(),
            external_index: 0,
            change_index: 0,
        };
        engine.load_meta()?;
        engine.build_addresses(lookahead)?;
        engine.import_addresses()?;
        Ok(engine)
    }

    pub fn network(&self) -> BchNetwork {
        self.account.network
    }

    pub fn account(&self) -> &BchWatchAccount {
        &self.account
    }

    pub fn utxos(&self) -> &[BchUtxo] {
        &self.utxos
    }

    pub fn history(&self) -> &[UtxoHistoryEntry] {
        &self.history
    }

    pub fn change_index(&self) -> u32 {
        self.change_index
    }

    pub fn mark_change_used(&mut self) {
        self.change_index = self.change_index.saturating_add(1);
        let _ = self.persist();
    }

    fn load_meta(&mut self) -> Result<(), BchError> {
        let value: Option<String> = self
            .db
            .query_row("SELECT v FROM meta WHERE k = 'state'", [], |row| row.get(0))
            .ok();
        if let Some(json) = value {
            let state: Persisted =
                serde_json::from_str(&json).map_err(|e| BchError::Transaction(e.to_string()))?;
            if state.network != self.account.network.network_id()
                || state.fingerprint != self.account.account_id()
            {
                return Err(BchError::WrongNetwork);
            }
            self.external_index = state.external_index;
            self.change_index = state.change_index;
            self.history = state.history;
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), BchError> {
        let state = Persisted {
            network: self.account.network.network_id().to_owned(),
            fingerprint: self.account.account_id(),
            external_index: self.external_index,
            change_index: self.change_index,
            history: self.history.clone(),
        };
        let json =
            serde_json::to_string(&state).map_err(|e| BchError::Transaction(e.to_string()))?;
        self.db
            .execute(
                "INSERT INTO meta (k, v) VALUES ('state', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![json],
            )
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        Ok(())
    }

    fn build_addresses(&mut self, lookahead: u32) -> Result<(), BchError> {
        self.addresses.clear();
        for index in 0..lookahead {
            let address = self.account.address(0, index)?;
            self.addresses
                .push((0, index, address.clone(), address.script_pubkey()?));
        }
        for index in 0..(lookahead / 4).max(1) {
            let address = self.account.address(1, index)?;
            self.addresses
                .push((1, index, address.clone(), address.script_pubkey()?));
        }
        Ok(())
    }

    fn import_addresses(&self) -> Result<(), BchError> {
        for (_, _, address, _) in &self.addresses {
            let _: serde_json::Value = self
                .rpc
                .call(
                    "importaddress",
                    &[
                        serde_json::json!(address.encode()),
                        serde_json::json!(""),
                        serde_json::json!(false),
                    ],
                )
                .map_err(|e| BchError::Transaction(e.to_string()))?;
        }
        Ok(())
    }

    fn import_address(&self, address: &CashAddress) -> Result<(), BchError> {
        let _: serde_json::Value = self
            .rpc
            .call(
                "importaddress",
                &[
                    serde_json::json!(address.encode()),
                    serde_json::json!(""),
                    serde_json::json!(false),
                ],
            )
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        Ok(())
    }

    fn address_set(&self) -> HashSet<ScriptBuf> {
        self.addresses
            .iter()
            .map(|(_, _, _, spk)| spk.clone())
            .collect()
    }

    fn raw_transaction(&self, txid: &Txid) -> Result<Transaction, BchError> {
        let hex: String = self
            .rpc
            .call("getrawtransaction", &[serde_json::json!(txid.to_string())])
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        deserialize_hex(&hex).map_err(|e| BchError::Transaction(e.to_string()))
    }

    pub fn sync(&mut self) -> Result<BchSyncReport, BchError> {
        let tip = self
            .rpc
            .get_block_count()
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        let addresses: Vec<String> = self
            .addresses
            .iter()
            .map(|(_, _, a, _)| a.encode())
            .collect();
        let unspent: Vec<serde_json::Value> = self
            .rpc
            .call(
                "listunspent",
                &[
                    serde_json::json!(0),
                    serde_json::json!(9_999_999),
                    serde_json::json!(addresses),
                ],
            )
            .map_err(|e| BchError::Transaction(e.to_string()))?;

        let mut utxos = Vec::new();
        let mut tx_cache: HashMap<Txid, Transaction> = HashMap::new();
        for entry in unspent {
            let txid_str = entry
                .get("txid")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let vout = entry.get("vout").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let confirmations = entry
                .get("confirmations")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let addr = entry
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let (keychain, index) = self
                .addresses
                .iter()
                .find(|(_, _, a, _)| a.encode() == addr)
                .map(|(k, i, _, _)| (*k, *i))
                .ok_or_else(|| BchError::Transaction("unknown address".to_owned()))?;
            let txid = Txid::from_str(txid_str)
                .map_err(|_| BchError::Transaction("bad txid".to_owned()))?;
            let tx = match tx_cache.get(&txid) {
                Some(tx) => tx.clone(),
                None => {
                    let tx = self.raw_transaction(&txid)?;
                    tx_cache.insert(txid, tx.clone());
                    tx
                }
            };
            let value = tx
                .output
                .get(vout as usize)
                .ok_or_else(|| BchError::Transaction("vout missing".to_owned()))?
                .value
                .to_sat();
            utxos.push(BchUtxo {
                outpoint: OutPoint { txid, vout },
                value_sats: value,
                confirmations,
                keychain,
                index,
            });
        }
        self.utxos = utxos;

        let listed: Vec<serde_json::Value> = self
            .rpc
            .call(
                "listtransactions",
                &[
                    serde_json::json!("*"),
                    serde_json::json!(1000),
                    serde_json::json!(0),
                    serde_json::json!(true),
                ],
            )
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        let mut seen = HashSet::new();
        let mut history = Vec::new();
        let ours = self.address_set();
        for entry in listed {
            let txid_str = entry
                .get("txid")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let Ok(txid) = Txid::from_str(txid_str) else {
                continue;
            };
            if !seen.insert(txid) {
                continue;
            }
            let height = entry.get("blockheight").and_then(|v| v.as_u64());
            let tx = match tx_cache.get(&txid) {
                Some(tx) => tx.clone(),
                None => {
                    let tx = self.raw_transaction(&txid)?;
                    tx_cache.insert(txid, tx.clone());
                    tx
                }
            };
            let received: u64 = tx
                .output
                .iter()
                .filter(|o| ours.contains(&o.script_pubkey))
                .map(|o| o.value.to_sat())
                .sum();
            let mut sent = 0u64;
            for input in &tx.input {
                let prev_txid = input.previous_output.txid;
                let prev = match tx_cache.get(&prev_txid) {
                    Some(tx) => tx.clone(),
                    None => {
                        if let Ok(tx) = self.raw_transaction(&prev_txid) {
                            tx_cache.insert(prev_txid, tx.clone());
                            tx
                        } else {
                            continue;
                        }
                    }
                };
                if let Some(out) = prev.output.get(input.previous_output.vout as usize)
                    && ours.contains(&out.script_pubkey)
                {
                    sent = sent.saturating_add(out.value.to_sat());
                }
            }
            history.push(UtxoHistoryEntry {
                txid: txid.to_string(),
                received_sats: received,
                sent_sats: sent,
                confirmation_height: height,
            });
        }
        self.history = history;
        self.persist()?;
        Ok(BchSyncReport {
            tip_height: tip,
            utxos: self.utxos.len(),
            history: self.history.len(),
        })
    }

    pub fn balance(&self) -> UtxoBalance {
        let mut balance = UtxoBalance::default();
        for utxo in &self.utxos {
            if utxo.confirmations > 0 {
                balance.confirmed_sats = balance.confirmed_sats.saturating_add(utxo.value_sats);
            } else {
                balance.untrusted_pending_sats = balance
                    .untrusted_pending_sats
                    .saturating_add(utxo.value_sats);
            }
        }
        balance
    }

    pub fn next_receive_address(&mut self) -> Result<CashAddress, BchError> {
        let address = self.account.address(0, self.external_index)?;
        self.external_index = self.external_index.saturating_add(1);
        let _ = self.import_address(&address);
        self.persist()?;
        Ok(address)
    }

    pub fn prepare_transfer(
        &self,
        destination: &str,
        amount_sats: u64,
        fee_rate_sat_vb: u64,
    ) -> Result<UnsignedTransfer, BchError> {
        let utxos: Vec<crate::Utxo> = self
            .utxos
            .iter()
            .map(|u| crate::Utxo {
                outpoint: u.outpoint,
                value_sats: u.value_sats,
                keychain: u.keychain,
                index: u.index,
            })
            .collect();
        build_unsigned(
            &self.account,
            utxos.as_slice(),
            destination,
            amount_sats,
            fee_rate_sat_vb,
            self.change_index,
        )
    }

    pub fn fee_estimates(&self) -> FeeEstimate {
        let target = |blocks: u64| -> Option<u64> {
            let value: serde_json::Value = self
                .rpc
                .call("estimatesmartfee", &[serde_json::json!(blocks)])
                .ok()?;
            value
                .get("feerate")
                .and_then(|v| v.as_f64())
                .and_then(coin_per_kvb_to_sat_vb)
        };
        let economy = target(6);
        let normal = target(2).or(economy);
        let priority = target(1).or(normal);
        if let (Some(economy), Some(normal), Some(priority)) = (economy, normal, priority) {
            return FeeEstimate {
                economy_sat_vb: economy,
                normal_sat_vb: normal,
                priority_sat_vb: priority,
                source: "estimatesmartfee".to_owned(),
            };
        }
        let relay = self
            .rpc
            .call::<serde_json::Value>("getnetworkinfo", &[])
            .ok()
            .and_then(|v| v.get("relayfee").and_then(|r| r.as_f64()))
            .and_then(coin_per_kvb_to_sat_vb);
        match relay {
            Some(rate) => FeeEstimate {
                economy_sat_vb: rate,
                normal_sat_vb: rate,
                priority_sat_vb: rate,
                source: "relay-floor".to_owned(),
            },
            None => FeeEstimate {
                economy_sat_vb: 1,
                normal_sat_vb: 1,
                priority_sat_vb: 1,
                source: "policy-floor".to_owned(),
            },
        }
    }

    pub fn broadcast_hex(&self, hex: &str) -> Result<String, BchError> {
        self.rpc
            .call("sendrawtransaction", &[serde_json::json!(hex)])
            .map_err(|e| BchError::Transaction(e.to_string()))
    }

    pub fn transaction_status(&self, txid: &str) -> Result<serde_json::Value, BchError> {
        let tx: serde_json::Value = self
            .rpc
            .call(
                "gettransaction",
                &[serde_json::json!(txid), serde_json::json!(true)],
            )
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        Ok(serde_json::json!({
            "txid": txid,
            "confirmations": tx.get("confirmations").and_then(|v| v.as_i64()).unwrap_or(0),
            "blockhash": tx.get("blockhash").and_then(|v| v.as_str()),
        }))
    }

    pub fn rescan(&self) -> Result<(), BchError> {
        let _: serde_json::Value = self
            .rpc
            .call("rescanblockchain", &[])
            .map_err(|e| BchError::Transaction(e.to_string()))?;
        Ok(())
    }
}
