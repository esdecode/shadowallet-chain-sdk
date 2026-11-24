//! Watch-only Litecoin Core synchronization and SQLite persistence.
//!
//! The engine never sees a seed or private key. It derives public addresses
//! from an account xpub, imports them into a disposable node wallet, and
//! returns unsigned transactions for external authorization/signing.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use litecoin::consensus::encode::deserialize_hex;
use litecoin::{Address, OutPoint, ScriptBuf, Transaction, Txid};
use rusqlite::{Connection as Sqlite, params};
use serde::{Deserialize, Serialize};
use shadowallet_chain_utxo::{FeeEstimate, Utxo, UtxoBalance, UtxoHistoryEntry};

use crate::esplora::EsploraClient;
use crate::{LitecoinSdkError, LtcAccount, LtcNetwork, UnsignedTransfer, prepare_transfer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtcUtxo {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub confirmations: u32,
    pub keychain: u32,
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtcSyncReport {
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

pub struct LtcEngine {
    account: LtcAccount,
    /// Exactly one backend is set: Litecoin Core RPC or an Esplora REST server.
    rpc: Option<Client>,
    esplora: Option<EsploraClient>,
    lookahead: u32,
    db: Sqlite,
    addresses: Vec<(u32, u32, Address, ScriptBuf)>,
    utxos: Vec<LtcUtxo>,
    history: Vec<UtxoHistoryEntry>,
    external_index: u32,
    change_index: u32,
}

impl std::fmt::Debug for LtcEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LtcEngine")
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

impl LtcEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        network: LtcNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
        rpc_url: &str,
        rpc_user: &str,
        rpc_password: &str,
        db_path: &Path,
        lookahead: u32,
    ) -> Result<Self, LitecoinSdkError> {
        let rpc = Client::new(
            rpc_url,
            Auth::UserPass(rpc_user.to_owned(), rpc_password.to_owned()),
        )
        .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        let engine = Self::open_inner(
            network,
            xpub,
            fingerprint,
            Some(rpc),
            None,
            db_path,
            lookahead,
        )?;
        engine.import_addresses()?;
        Ok(engine)
    }

    /// Open against an Esplora REST server (for example `https://litecoinspace.org/testnet/api`). Nothing is
    /// imported anywhere: the server only ever sees public addresses when `sync` asks about them.
    pub fn open_esplora(
        network: LtcNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
        base_url: &str,
        db_path: &Path,
        lookahead: u32,
    ) -> Result<Self, LitecoinSdkError> {
        let esplora = EsploraClient::new(base_url)?;
        Self::open_inner(
            network,
            xpub,
            fingerprint,
            None,
            Some(esplora),
            db_path,
            lookahead,
        )
    }

    fn open_inner(
        network: LtcNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
        rpc: Option<Client>,
        esplora: Option<EsploraClient>,
        db_path: &Path,
        lookahead: u32,
    ) -> Result<Self, LitecoinSdkError> {
        let account = LtcAccount::from_xpub(network, xpub, fingerprint)?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        }
        let db = shadowallet_chain_securedb::open_resolved(db_path)
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|e| LitecoinSdkError::Transaction(format!("database unreadable: {e}")))?;
        if integrity != "ok" {
            return Err(LitecoinSdkError::Transaction(format!(
                "database integrity check failed: {integrity}"
            )));
        }
        db.execute_batch("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);")
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        let mut engine = Self {
            account,
            rpc,
            esplora,
            lookahead,
            db,
            addresses: Vec::new(),
            utxos: Vec::new(),
            history: Vec::new(),
            external_index: 0,
            change_index: 0,
        };
        engine.load_meta()?;
        engine.build_addresses(lookahead)?;
        Ok(engine)
    }

    fn rpc(&self) -> Result<&Client, LitecoinSdkError> {
        self.rpc
            .as_ref()
            .ok_or_else(|| LitecoinSdkError::Transaction("no Litecoin Core backend".to_owned()))
    }

    pub fn esplora(&self) -> Option<&EsploraClient> {
        self.esplora.as_ref()
    }

    pub fn network(&self) -> LtcNetwork {
        self.account.network
    }

    pub fn account(&self) -> &LtcAccount {
        &self.account
    }

    pub fn utxos(&self) -> &[LtcUtxo] {
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

    fn load_meta(&mut self) -> Result<(), LitecoinSdkError> {
        let value: Option<String> = self
            .db
            .query_row("SELECT v FROM meta WHERE k = 'state'", [], |row| row.get(0))
            .ok();
        if let Some(json) = value {
            let state: Persisted = serde_json::from_str(&json)
                .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
            if state.network != self.account.network.network_id()
                || state.fingerprint != self.account.account_id()
            {
                return Err(LitecoinSdkError::WrongNetwork);
            }
            self.external_index = state.external_index;
            self.change_index = state.change_index;
            self.history = state.history;
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), LitecoinSdkError> {
        let state = Persisted {
            network: self.account.network.network_id().to_owned(),
            fingerprint: self.account.account_id(),
            external_index: self.external_index,
            change_index: self.change_index,
            history: self.history.clone(),
        };
        let json = serde_json::to_string(&state)
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        self.db
            .execute(
                "INSERT INTO meta (k, v) VALUES ('state', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![json],
            )
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        Ok(())
    }

    fn build_addresses(&mut self, lookahead: u32) -> Result<(), LitecoinSdkError> {
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
    ) -> Result<(), LitecoinSdkError> {
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

    fn extend_change_window(&mut self) -> Result<(), LitecoinSdkError> {
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

    fn import_addresses(&self) -> Result<(), LitecoinSdkError> {
        for (_, _, address, _) in &self.addresses {
            let _: serde_json::Value = self
                .rpc()?
                .call(
                    "importaddress",
                    &[
                        serde_json::json!(address.to_string()),
                        serde_json::json!(""),
                        serde_json::json!(false),
                    ],
                )
                .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        }
        Ok(())
    }

    fn import_address(&self, address: &Address) -> Result<(), LitecoinSdkError> {
        if self.esplora.is_some() {
            return Ok(());
        }
        let _: serde_json::Value = self
            .rpc()?
            .call(
                "importaddress",
                &[
                    serde_json::json!(address.to_string()),
                    serde_json::json!(""),
                    serde_json::json!(false),
                ],
            )
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        Ok(())
    }

    fn address_set(&self) -> HashSet<ScriptBuf> {
        self.addresses
            .iter()
            .map(|(_, _, _, spk)| spk.clone())
            .collect()
    }

    fn raw_transaction(&self, txid: &Txid) -> Result<Transaction, LitecoinSdkError> {
        // `getrawtransaction` only finds confirmed transactions on a node with `-txindex`; a pruned
        // node (every public test network here) has none. The node wallet knows every transaction
        // that pays one of our imported addresses, so fall back to `gettransaction` (its `hex`).
        let hex: String = match self
            .rpc()?
            .call::<String>("getrawtransaction", &[serde_json::json!(txid.to_string())])
        {
            Ok(hex) => hex,
            Err(_) => {
                let wallet_tx: serde_json::Value = self
                    .rpc()?
                    .call("gettransaction", &[serde_json::json!(txid.to_string())])
                    .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
                wallet_tx
                    .get("hex")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        LitecoinSdkError::Transaction("transaction hex unavailable".to_owned())
                    })?
            }
        };
        deserialize_hex(&hex).map_err(|e| LitecoinSdkError::Transaction(e.to_string()))
    }

    pub fn sync(&mut self) -> Result<LtcSyncReport, LitecoinSdkError> {
        if self.esplora.is_some() {
            return self.sync_esplora();
        }
        let tip = self
            .rpc()?
            .get_block_count()
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        let addresses: Vec<String> = self
            .addresses
            .iter()
            .map(|(_, _, a, _)| a.to_string())
            .collect();
        let unspent: Vec<serde_json::Value> = self
            .rpc()?
            .call(
                "listunspent",
                &[
                    serde_json::json!(0),
                    serde_json::json!(9_999_999),
                    serde_json::json!(addresses),
                ],
            )
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;

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
                .ok_or_else(|| LitecoinSdkError::Transaction("unknown address".to_owned()))?;
            let txid = Txid::from_str(txid_str)
                .map_err(|_| LitecoinSdkError::Transaction("bad txid".to_owned()))?;
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
                .ok_or_else(|| LitecoinSdkError::Transaction("vout missing".to_owned()))?
                .value
                .to_sat();
            utxos.push(LtcUtxo {
                outpoint: OutPoint { txid, vout },
                value_sats: value,
                confirmations,
                keychain,
                index,
            });
        }
        self.utxos = utxos;

        let listed: Vec<serde_json::Value> = self
            .rpc()?
            .call(
                "listtransactions",
                &[
                    serde_json::json!("*"),
                    serde_json::json!(1000),
                    serde_json::json!(0),
                    serde_json::json!(true),
                ],
            )
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
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
        Ok(LtcSyncReport {
            tip_height: tip,
            utxos: self.utxos.len(),
            history: self.history.len(),
        })
    }

    /// Esplora synchronization: full history per watched address (paginated), BIP44 gap extension on both
    /// chains, UTXOs re-read from verified transaction bytes. Only addresses and txids go to the server.
    fn sync_esplora(&mut self) -> Result<LtcSyncReport, LitecoinSdkError> {
        let es = self
            .esplora
            .clone()
            .ok_or_else(|| LitecoinSdkError::Transaction("no Esplora backend".to_owned()))?;
        let tip = es.tip_height()?;
        let mut scanned: HashMap<String, Vec<crate::esplora::EsploraTx>> = HashMap::new();
        loop {
            let pending: Vec<String> = self
                .addresses
                .iter()
                .map(|(_, _, a, _)| a.to_string())
                .filter(|a| !scanned.contains_key(a))
                .collect();
            for address in pending {
                let txs = es.address_txs(&address)?;
                scanned.insert(address, txs);
            }
            let highest = |keychain: u32| -> Option<u32> {
                self.addresses
                    .iter()
                    .filter(|(k, _, a, _)| {
                        *k == keychain && scanned.get(&a.to_string()).is_some_and(|t| !t.is_empty())
                    })
                    .map(|(_, i, _, _)| *i)
                    .max()
            };
            let used_external = highest(0);
            let used_change = highest(1);
            let mut grew = false;
            if let Some(h) = used_external {
                self.external_index = self.external_index.max(h.saturating_add(1));
                grew |= self.extend_chain(0, h.saturating_add(1).saturating_add(self.lookahead))?;
            }
            if let Some(h) = used_change {
                self.change_index = self.change_index.max(h.saturating_add(1));
            }
            grew |= self.extend_chain(1, self.change_index.saturating_add(Self::CHANGE_GAP))?;
            if !grew {
                break;
            }
        }

        let ours: HashSet<String> = self
            .addresses
            .iter()
            .map(|(_, _, _, spk)| hex::encode(spk.as_bytes()))
            .collect();
        let mut by_txid: HashMap<String, crate::esplora::EsploraTx> = HashMap::new();
        for tx in scanned.values().flatten() {
            by_txid.entry(tx.txid.clone()).or_insert_with(|| tx.clone());
        }
        let mut history: Vec<UtxoHistoryEntry> = by_txid
            .values()
            .map(|tx| UtxoHistoryEntry {
                txid: tx.txid.clone(),
                received_sats: tx
                    .outputs
                    .iter()
                    .filter(|(s, _)| ours.contains(s))
                    .map(|(_, v)| *v)
                    .sum(),
                sent_sats: tx
                    .inputs
                    .iter()
                    .flatten()
                    .filter(|(s, _)| ours.contains(s))
                    .map(|(_, v)| *v)
                    .sum(),
                confirmation_height: tx.height,
            })
            .collect();
        // Oldest first, unconfirmed last (the order the node wallet lists them in).
        history.sort_by(|a, b| {
            let key = |h: &UtxoHistoryEntry| {
                (
                    h.confirmation_height.is_none(),
                    h.confirmation_height,
                    h.txid.clone(),
                )
            };
            key(a).cmp(&key(b))
        });

        let mut utxos = Vec::new();
        let mut tx_cache: HashMap<String, Transaction> = HashMap::new();
        let owned: Vec<(u32, u32, String, ScriptBuf)> = self
            .addresses
            .iter()
            .map(|(k, i, a, s)| (*k, *i, a.to_string(), s.clone()))
            .collect();
        for (keychain, index, address, spk) in owned {
            if scanned.get(&address).is_none_or(|t| t.is_empty()) {
                continue;
            }
            for entry in es.address_utxos(&address)? {
                let tx = match tx_cache.get(&entry.txid) {
                    Some(tx) => tx.clone(),
                    None => {
                        let raw = es.tx_hex(&entry.txid)?;
                        let tx: Transaction = deserialize_hex(&raw)
                            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
                        // The server is untrusted: the bytes must hash to the txid that was asked for.
                        if tx.compute_txid().to_string() != entry.txid {
                            return Err(LitecoinSdkError::Transaction(
                                "backend returned a transaction that does not match its txid"
                                    .to_owned(),
                            ));
                        }
                        tx_cache.insert(entry.txid.clone(), tx.clone());
                        tx
                    }
                };
                let out = tx
                    .output
                    .get(entry.vout as usize)
                    .ok_or_else(|| LitecoinSdkError::Transaction("vout missing".to_owned()))?;
                if out.script_pubkey != spk {
                    return Err(LitecoinSdkError::Transaction(
                        "backend reported an output that does not pay the watched address"
                            .to_owned(),
                    ));
                }
                let txid = Txid::from_str(&entry.txid)
                    .map_err(|_| LitecoinSdkError::Transaction("bad txid".to_owned()))?;
                let confirmations = entry
                    .height
                    .map_or(0, |h| tip.saturating_sub(h).saturating_add(1))
                    as u32;
                utxos.push(LtcUtxo {
                    outpoint: OutPoint {
                        txid,
                        vout: entry.vout,
                    },
                    value_sats: out.value.to_sat(),
                    confirmations,
                    keychain,
                    index,
                });
            }
        }
        self.utxos = utxos;
        self.history = history;
        self.persist()?;
        Ok(LtcSyncReport {
            tip_height: tip,
            utxos: self.utxos.len(),
            history: self.history.len(),
        })
    }

    /// Derive watched addresses of `keychain` up to (excluding) `count`. Returns whether any were added.
    fn extend_chain(&mut self, keychain: u32, count: u32) -> Result<bool, LitecoinSdkError> {
        let have = self
            .addresses
            .iter()
            .filter(|(k, _, _, _)| *k == keychain)
            .count() as u32;
        for index in have..count {
            let address = self.account.address(keychain, index)?;
            self.addresses
                .push((keychain, index, address.clone(), address.script_pubkey()));
        }
        Ok(count > have)
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

    pub fn next_receive_address(&mut self) -> Result<Address, LitecoinSdkError> {
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
    ) -> Result<UnsignedTransfer, LitecoinSdkError> {
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
        let floor = |source: &str| FeeEstimate {
            economy_sat_vb: 1,
            normal_sat_vb: 1,
            priority_sat_vb: 1,
            source: source.to_owned(),
        };
        if let Some(es) = &self.esplora {
            return match es.fees() {
                Some(f) => FeeEstimate {
                    economy_sat_vb: f.economy,
                    normal_sat_vb: f.normal,
                    priority_sat_vb: f.priority,
                    source: f.source.to_owned(),
                },
                // Neither fee dialect answered: Litecoin's minimum relay fee is 1 sat/vB.
                None => floor("policy-floor"),
            };
        }
        let Ok(rpc) = self.rpc() else {
            return floor("policy-floor");
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

    pub fn broadcast_hex(&self, hex: &str) -> Result<String, LitecoinSdkError> {
        if let Some(es) = &self.esplora {
            let local: Transaction =
                deserialize_hex(hex).map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
            let answered = es.broadcast(hex)?;
            let expected = local.compute_txid().to_string();
            if answered != expected {
                return Err(LitecoinSdkError::Transaction(format!(
                    "backend answered txid {answered}, expected {expected}"
                )));
            }
            return Ok(answered);
        }
        self.rpc()?
            .call("sendrawtransaction", &[serde_json::json!(hex)])
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))
    }

    pub fn transaction_status(&self, txid: &str) -> Result<serde_json::Value, LitecoinSdkError> {
        if let Some(es) = &self.esplora {
            let confirmations = match es.tx_status(txid)? {
                Some(height) => es.tip_height()?.saturating_sub(height).saturating_add(1),
                None => 0,
            };
            return Ok(serde_json::json!({
                "txid": txid,
                "confirmations": confirmations,
                "blockhash": serde_json::Value::Null,
            }));
        }
        let tx: serde_json::Value = self
            .rpc()?
            .call(
                "gettransaction",
                &[serde_json::json!(txid), serde_json::json!(true)],
            )
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        Ok(serde_json::json!({
            "txid": txid,
            "confirmations": tx.get("confirmations").and_then(|v| v.as_i64()).unwrap_or(0),
            "blockhash": tx.get("blockhash").and_then(|v| v.as_str()),
        }))
    }

    /// Is the outpoint still unspent according to the backend (mempool spends included)?
    pub fn output_unspent(&self, txid: &str, vout: u32) -> Result<bool, LitecoinSdkError> {
        match &self.esplora {
            Some(es) => es.output_unspent(txid, vout),
            None => {
                let answer: serde_json::Value = self
                    .rpc()?
                    .call(
                        "gettxout",
                        &[
                            serde_json::json!(txid),
                            serde_json::json!(vout),
                            serde_json::json!(true),
                        ],
                    )
                    .map_err(|e| LitecoinSdkError::Transaction(format!("node: {e}")))?;
                Ok(!answer.is_null())
            }
        }
    }

    /// Is the transaction known and unconfirmed right now? `Err` means no usable answer.
    pub fn in_mempool(&self, txid: &str) -> Result<bool, LitecoinSdkError> {
        match &self.esplora {
            Some(es) => match es.tx_status(txid) {
                Ok(None) => Ok(true),
                Ok(Some(_)) => Ok(false),
                Err(e) if e.to_string().contains("HTTP 404") => Ok(false),
                Err(e) => Err(e),
            },
            None => {
                let answer: Result<serde_json::Value, _> = self
                    .rpc()?
                    .call("getmempoolentry", &[serde_json::json!(txid)]);
                match answer {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        let m = e.to_string();
                        if m.contains("-5") && m.to_ascii_lowercase().contains("not in mempool") {
                            Ok(false)
                        } else {
                            Err(LitecoinSdkError::Transaction(format!("node: {m}")))
                        }
                    }
                }
            }
        }
    }

    pub fn rescan(&self) -> Result<(), LitecoinSdkError> {
        if self.esplora.is_some() {
            // An Esplora server is queried for the full history on every sync; there is nothing to rescan.
            return Ok(());
        }
        let _: serde_json::Value = self
            .rpc()?
            .call("rescanblockchain", &[])
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        Ok(())
    }
}
