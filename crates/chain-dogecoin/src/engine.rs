//! Watch-only Dogecoin Core synchronization and SQLite persistence.
//!
//! The engine never sees a seed or private key. It derives public addresses
//! from an account xpub, imports them into a disposable node wallet, and
//! returns unsigned transactions for external authorization/signing.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use doge::consensus::encode::deserialize_hex;
use doge::dogecoin::Address;
use doge::{OutPoint, ScriptBuf, Transaction, Txid};
use rusqlite::{Connection as Sqlite, params};
use serde::{Deserialize, Serialize};
use shadowallet_chain_utxo::{FeeEstimate, Utxo, UtxoBalance, UtxoHistoryEntry};

use crate::indexer::{Indexer, IndexerConfig};
use crate::{DogeAccount, DogeNetwork, DogecoinSdkError, UnsignedTransfer, prepare_transfer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DogeUtxo {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub confirmations: u32,
    pub keychain: u32,
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DogeSyncReport {
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

/// Where chain data comes from: a Dogecoin Core node with a wallet, or (testnet only) the two public
/// untrusted services of [`crate::indexer`].
enum Backend {
    Node(Client),
    Indexer(Box<Indexer>),
}

pub struct DogeEngine {
    account: DogeAccount,
    backend: Backend,
    db: Sqlite,
    addresses: Vec<(u32, u32, Address, ScriptBuf)>,
    utxos: Vec<DogeUtxo>,
    history: Vec<UtxoHistoryEntry>,
    external_index: u32,
    change_index: u32,
}

impl std::fmt::Debug for DogeEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DogeEngine")
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

impl DogeEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        network: DogeNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
        rpc_url: &str,
        rpc_user: &str,
        rpc_password: &str,
        db_path: &Path,
        lookahead: u32,
    ) -> Result<Self, DogecoinSdkError> {
        let rpc = Client::new(
            rpc_url,
            Auth::UserPass(rpc_user.to_owned(), rpc_password.to_owned()),
        )
        .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        Self::open_with(
            network,
            xpub,
            fingerprint,
            Backend::Node(rpc),
            db_path,
            lookahead,
        )
    }

    /// Open on the public-testnet indexer backend. Only the Dogecoin testnet may use it: the genesis
    /// identity of both services is verified before the first read and signing never depends on it.
    pub fn open_indexer(
        network: DogeNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
        config: IndexerConfig,
        db_path: &Path,
    ) -> Result<Self, DogecoinSdkError> {
        if network != DogeNetwork::Testnet {
            return Err(DogecoinSdkError::Transaction(
                "the public indexer backend is for the Dogecoin testnet only".to_owned(),
            ));
        }
        let indexer = Indexer::new(config)?;
        Self::open_with(
            network,
            xpub,
            fingerprint,
            Backend::Indexer(Box::new(indexer)),
            db_path,
            5,
        )
    }

    fn open_with(
        network: DogeNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
        backend: Backend,
        db_path: &Path,
        lookahead: u32,
    ) -> Result<Self, DogecoinSdkError> {
        let account = DogeAccount::from_xpub(network, xpub, fingerprint)?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        }
        let db = Sqlite::open(db_path).map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|e| DogecoinSdkError::Transaction(format!("database unreadable: {e}")))?;
        if integrity != "ok" {
            return Err(DogecoinSdkError::Transaction(format!(
                "database integrity check failed: {integrity}"
            )));
        }
        db.execute_batch("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);")
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        let indexed = matches!(backend, Backend::Indexer(_));
        let mut engine = Self {
            account,
            backend,
            db,
            addresses: Vec::new(),
            utxos: Vec::new(),
            history: Vec::new(),
            external_index: 0,
            change_index: 0,
        };
        engine.load_meta()?;
        // The indexer is queried address by address, so scan only what has been handed out (+ a gap).
        let lookahead = if indexed {
            lookahead.max(engine.external_index.saturating_add(3))
        } else {
            lookahead
        };
        engine.build_addresses(lookahead)?;
        engine.import_addresses()?;
        Ok(engine)
    }

    fn node(&self) -> Result<&Client, DogecoinSdkError> {
        match &self.backend {
            Backend::Node(rpc) => Ok(rpc),
            Backend::Indexer(_) => Err(DogecoinSdkError::Transaction(
                "operation needs a node backend".to_owned(),
            )),
        }
    }

    fn indexer(&self) -> Option<&Indexer> {
        match &self.backend {
            Backend::Indexer(i) => Some(i),
            Backend::Node(_) => None,
        }
    }

    pub fn uses_indexer(&self) -> bool {
        self.indexer().is_some()
    }

    /// Prove both services of the indexer backend are the Dogecoin testnet and agree on a recent block
    /// (memoised). A node backend is verified separately by its caller; this is then a no-op.
    pub fn verify_backend_identity(&self) -> Result<(), DogecoinSdkError> {
        match self.indexer() {
            Some(ix) => ix.ensure_identity(),
            None => Ok(()),
        }
    }

    pub fn network(&self) -> DogeNetwork {
        self.account.network
    }

    pub fn account(&self) -> &DogeAccount {
        &self.account
    }

    pub fn utxos(&self) -> &[DogeUtxo] {
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

    fn load_meta(&mut self) -> Result<(), DogecoinSdkError> {
        let value: Option<String> = self
            .db
            .query_row("SELECT v FROM meta WHERE k = 'state'", [], |row| row.get(0))
            .ok();
        if let Some(json) = value {
            let state: Persisted = serde_json::from_str(&json)
                .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
            if state.network != self.account.network.network_id()
                || state.fingerprint != self.account.account_id()
            {
                return Err(DogecoinSdkError::WrongNetwork);
            }
            self.external_index = state.external_index;
            self.change_index = state.change_index;
            self.history = state.history;
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), DogecoinSdkError> {
        let state = Persisted {
            network: self.account.network.network_id().to_owned(),
            fingerprint: self.account.account_id(),
            external_index: self.external_index,
            change_index: self.change_index,
            history: self.history.clone(),
        };
        let json = serde_json::to_string(&state)
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        self.db
            .execute(
                "INSERT INTO meta (k, v) VALUES ('state', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![json],
            )
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        Ok(())
    }

    fn build_addresses(&mut self, lookahead: u32) -> Result<(), DogecoinSdkError> {
        self.addresses.clear();
        for index in 0..lookahead {
            let address = self.account.address(0, index)?;
            self.addresses
                .push((0, index, address.clone(), address.script_pubkey()));
        }
        for index in 0..(lookahead / 4)
            .max(1)
            .max(self.change_index.saturating_add(Self::CHANGE_GAP))
        {
            let address = self.account.address(1, index)?;
            self.addresses
                .push((1, index, address.clone(), address.script_pubkey()));
        }
        Ok(())
    }

    /// How many change addresses beyond the highest one in use are watched.
    const CHANGE_GAP: u32 = 2;

    /// Bring the change index past every change address that a known transaction already paid, so a
    /// restored or reinstalled wallet never hands out a used change address again, and keep the
    /// watched change window ahead of it.
    fn adopt_used_change<'a>(
        &mut self,
        txs: impl Iterator<Item = &'a Transaction>,
    ) -> Result<(), DogecoinSdkError> {
        let change: HashMap<ScriptBuf, u32> = self
            .addresses
            .iter()
            .filter(|(k, _, _, _)| *k == 1)
            .map(|(_, i, _, s)| (s.clone(), *i))
            .collect();
        let highest = txs
            .flat_map(|t| t.output.iter())
            .filter_map(|o| change.get(&o.script_pubkey))
            .max()
            .copied();
        if let Some(h) = highest {
            self.change_index = self.change_index.max(h.saturating_add(1));
        }
        self.extend_change_window()
    }

    fn extend_change_window(&mut self) -> Result<(), DogecoinSdkError> {
        let want = self.change_index.saturating_add(Self::CHANGE_GAP);
        let have = self.addresses.iter().filter(|(k, _, _, _)| *k == 1).count() as u32;
        for index in have..want {
            let address = self.account.address(1, index)?;
            self.import_address(&address)?;
            self.addresses
                .push((1, index, address.clone(), address.script_pubkey()));
        }
        Ok(())
    }

    fn import_addresses(&self) -> Result<(), DogecoinSdkError> {
        let Backend::Node(rpc) = &self.backend else {
            return Ok(());
        };
        for (_, _, address, _) in &self.addresses {
            let _: serde_json::Value = rpc
                .call(
                    "importaddress",
                    &[
                        serde_json::json!(address.to_string()),
                        serde_json::json!(""),
                        serde_json::json!(false),
                    ],
                )
                .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        }
        Ok(())
    }

    fn import_address(&self, address: &Address) -> Result<(), DogecoinSdkError> {
        let Backend::Node(rpc) = &self.backend else {
            return Ok(());
        };
        let _: serde_json::Value = rpc
            .call(
                "importaddress",
                &[
                    serde_json::json!(address.to_string()),
                    serde_json::json!(""),
                    serde_json::json!(false),
                ],
            )
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        Ok(())
    }

    fn address_set(&self) -> HashSet<ScriptBuf> {
        self.addresses
            .iter()
            .map(|(_, _, _, spk)| spk.clone())
            .collect()
    }

    fn raw_transaction(&self, txid: &Txid) -> Result<Transaction, DogecoinSdkError> {
        // `getrawtransaction` only finds confirmed transactions on a node with `-txindex`; a pruned
        // node (every public test network here) has none. The node wallet knows every transaction
        // that pays one of our imported addresses, so fall back to `gettransaction` (its `hex`).
        let rpc = self.node()?;
        let hex: String =
            match rpc.call::<String>("getrawtransaction", &[serde_json::json!(txid.to_string())]) {
                Ok(hex) => hex,
                Err(_) => {
                    let wallet_tx: serde_json::Value = rpc
                        .call("gettransaction", &[serde_json::json!(txid.to_string())])
                        .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
                    wallet_tx
                        .get("hex")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            DogecoinSdkError::Transaction("transaction hex unavailable".to_owned())
                        })?
                }
            };
        deserialize_hex(&hex).map_err(|e| DogecoinSdkError::Transaction(e.to_string()))
    }

    /// Synchronise from the two public services: every spendable UTXO is validated against its own raw
    /// transaction and confirmed by the second service before it is accepted.
    fn sync_indexer(&mut self) -> Result<DogeSyncReport, DogecoinSdkError> {
        self.sync_indexer_round(0)
    }

    fn sync_indexer_round(&mut self, round: u32) -> Result<DogeSyncReport, DogecoinSdkError> {
        let Some(ix) = self.indexer() else {
            return Err(DogecoinSdkError::Transaction("no indexer".to_owned()));
        };
        ix.ensure_identity()?;
        let (tip, _) = ix.tip()?;
        let scan: Vec<(String, ScriptBuf)> = self
            .addresses
            .iter()
            .map(|(_, _, a, spk)| (a.to_string(), spk.clone()))
            .collect();
        let verified = ix.verified_utxos(&scan, tip)?;
        let names: Vec<String> = scan.iter().map(|(a, _)| a.clone()).collect();
        let (history, used) = ix.history_with_used(&names, tip)?;
        let highest_used_change = used
            .iter()
            .filter_map(|i| self.addresses.get(*i))
            .filter(|(k, _, _, _)| *k == 1)
            .map(|(_, index, _, _)| *index)
            .max();
        // A used change address near the end of the watched window means more may follow: widen the
        // window and look again (bounded), exactly as a gap limit does on restore.
        if let Some(h) = highest_used_change {
            self.change_index = self.change_index.max(h.saturating_add(1));
        }
        let watched = self.addresses.len();
        self.extend_change_window()?;
        if self.addresses.len() > watched && round < 16 {
            return self.sync_indexer_round(round + 1);
        }
        let mut utxos = Vec::new();
        for (i, u) in verified {
            let (keychain, index, _, _) = &self.addresses[i];
            utxos.push(DogeUtxo {
                outpoint: OutPoint {
                    txid: u.txid,
                    vout: u.vout,
                },
                value_sats: u.value_sats,
                confirmations: u.confirmations,
                keychain: *keychain,
                index: *index,
            });
        }
        self.utxos = utxos;
        self.history = history;
        self.persist()?;
        Ok(DogeSyncReport {
            tip_height: tip,
            utxos: self.utxos.len(),
            history: self.history.len(),
        })
    }

    pub fn sync(&mut self) -> Result<DogeSyncReport, DogecoinSdkError> {
        if self.uses_indexer() {
            return self.sync_indexer();
        }
        let tip = self
            .node()?
            .get_block_count()
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        let addresses: Vec<String> = self
            .addresses
            .iter()
            .map(|(_, _, a, _)| a.to_string())
            .collect();
        let unspent: Vec<serde_json::Value> = self
            .node()?
            .call(
                "listunspent",
                &[
                    serde_json::json!(0),
                    serde_json::json!(9_999_999),
                    serde_json::json!(addresses),
                ],
            )
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;

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
                .find(|(_, _, a, _)| a.to_string() == addr)
                .map(|(k, i, _, _)| (*k, *i))
                .ok_or_else(|| DogecoinSdkError::Transaction("unknown address".to_owned()))?;
            let txid = Txid::from_str(txid_str)
                .map_err(|_| DogecoinSdkError::Transaction("bad txid".to_owned()))?;
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
                .ok_or_else(|| DogecoinSdkError::Transaction("vout missing".to_owned()))?
                .value
                .to_sat();
            utxos.push(DogeUtxo {
                outpoint: OutPoint { txid, vout },
                value_sats: value,
                confirmations,
                keychain,
                index,
            });
        }
        self.utxos = utxos;

        let listed: Vec<serde_json::Value> = self
            .node()?
            .call(
                "listtransactions",
                &[
                    serde_json::json!("*"),
                    serde_json::json!(1000),
                    serde_json::json!(0),
                    serde_json::json!(true),
                ],
            )
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
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
            // Dogecoin Core's `listtransactions` carries no `blockheight`; derive it from the
            // confirmation count so a confirmed transaction is never shown as unconfirmed.
            let height = entry
                .get("blockheight")
                .and_then(|v| v.as_u64())
                .or_else(|| {
                    let confirmations = entry.get("confirmations").and_then(|v| v.as_u64())?;
                    (confirmations > 0).then(|| tip.saturating_sub(confirmations) + 1)
                });
            let tx = match tx_cache.get(&txid) {
                Some(tx) => tx.clone(),
                None => match self.raw_transaction(&txid) {
                    Ok(tx) => {
                        tx_cache.insert(txid, tx.clone());
                        tx
                    }
                    // Listed by the node wallet but no longer known to the node: it was
                    // replaced or evicted from the mempool. Such a transaction is not
                    // history, and it must never make the whole synchronisation fail.
                    Err(_) => continue,
                },
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
        self.adopt_used_change(tx_cache.values())?;
        self.history = history;
        self.persist()?;
        Ok(DogeSyncReport {
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

    pub fn next_receive_address(&mut self) -> Result<Address, DogecoinSdkError> {
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
    ) -> Result<UnsignedTransfer, DogecoinSdkError> {
        let utxos: Vec<Utxo> = self
            .utxos
            .iter()
            .map(|u| Utxo {
                txid: u.outpoint.txid.to_string(),
                vout: u.outpoint.vout,
                value_sats: u.value_sats,
                confirmations: u.confirmations,
                keychain: u.keychain,
                index: u.index,
            })
            .collect();
        prepare_transfer(
            &self.account,
            &utxos,
            destination,
            amount_sats,
            fee_rate_sat_vb,
            self.change_index,
        )
    }

    pub fn fee_estimates(&self) -> FeeEstimate {
        if let Some(ix) = self.indexer() {
            let (rate, source) = ix.fee_rate();
            return FeeEstimate {
                economy_sat_vb: rate,
                normal_sat_vb: rate,
                priority_sat_vb: rate,
                source: source.to_owned(),
            };
        }
        let Ok(rpc) = self.node() else {
            return FeeEstimate {
                economy_sat_vb: 1,
                normal_sat_vb: 1,
                priority_sat_vb: 1,
                source: "policy-floor".to_owned(),
            };
        };
        let target = |blocks: u64| -> Option<u64> {
            let value: serde_json::Value = rpc
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
        let flat: Option<u64> = rpc
            .call::<serde_json::Value>("estimatefee", &[])
            .ok()
            .and_then(|v| v.as_f64())
            .and_then(coin_per_kvb_to_sat_vb);
        if let Some(rate) = flat {
            return FeeEstimate {
                economy_sat_vb: rate,
                normal_sat_vb: rate,
                priority_sat_vb: rate,
                source: "estimatefee".to_owned(),
            };
        }
        let relay = rpc
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

    pub fn broadcast_hex(&self, hex: &str) -> Result<String, DogecoinSdkError> {
        if let Some(ix) = self.indexer() {
            // Exactly one attempt; an uncertain outcome is reported as such and never retried.
            return ix.broadcast(hex);
        }
        self.node()?
            .call("sendrawtransaction", &[serde_json::json!(hex)])
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))
    }

    pub fn transaction_status(&self, txid: &str) -> Result<serde_json::Value, DogecoinSdkError> {
        if let Some(ix) = self.indexer() {
            let (status, block_hash) = ix.transaction_status(txid)?;
            return Ok(serde_json::json!({
                "txid": txid,
                "confirmations": status.confirmations,
                "blockhash": block_hash,
            }));
        }
        let tx: serde_json::Value = self
            .node()?
            .call(
                "gettransaction",
                &[serde_json::json!(txid), serde_json::json!(true)],
            )
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        Ok(serde_json::json!({
            "txid": txid,
            "confirmations": tx.get("confirmations").and_then(|v| v.as_i64()).unwrap_or(0),
            "blockhash": tx.get("blockhash").and_then(|v| v.as_str()),
        }))
    }

    /// Settlement evidence straight from the node (second service in indexer mode): is the outpoint
    /// still unspent, mempool included? `Err` is no evidence.
    pub fn input_unspent_at_node(&self, txid: &str, vout: u32) -> Result<bool, DogecoinSdkError> {
        if let Some(ix) = self.indexer() {
            return ix.input_unspent(txid, vout);
        }
        let answer: serde_json::Value = self
            .node()?
            .call(
                "gettxout",
                &[
                    serde_json::json!(txid),
                    serde_json::json!(vout),
                    serde_json::json!(true),
                ],
            )
            .map_err(|e| DogecoinSdkError::Transaction(format!("node: {e}")))?;
        Ok(!answer.is_null())
    }

    /// Is the transaction in the node's mempool right now? `Err` is no evidence.
    pub fn in_mempool(&self, txid: &str) -> Result<bool, DogecoinSdkError> {
        if let Some(ix) = self.indexer() {
            return ix.in_mempool(txid);
        }
        let answer: Result<serde_json::Value, _> = self
            .node()?
            .call("getmempoolentry", &[serde_json::json!(txid)]);
        match answer {
            Ok(_) => Ok(true),
            Err(e) => {
                let m = e.to_string();
                if m.contains("-5") && m.to_ascii_lowercase().contains("not in mempool") {
                    Ok(false)
                } else {
                    Err(DogecoinSdkError::Transaction(format!("node: {m}")))
                }
            }
        }
    }

    pub fn rescan(&self) -> Result<(), DogecoinSdkError> {
        let Backend::Node(rpc) = &self.backend else {
            return Ok(()); // the indexer always answers from the chain; there is nothing to rescan
        };
        for (_, _, address, _) in &self.addresses {
            let _: serde_json::Value = rpc
                .call(
                    "importaddress",
                    &[
                        serde_json::json!(address.to_string()),
                        serde_json::json!(""),
                        serde_json::json!(true),
                    ],
                )
                .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        }
        Ok(())
    }
}
