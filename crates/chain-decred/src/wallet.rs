use std::collections::HashMap;

use serde_json::Value;

use crate::DecredError;
use crate::account::Account;
use crate::rpc::DcrdRpc;

/// Addresses derived up front per branch. Scanning blocks needs the script set in advance (dcrd 2.x has no address
/// index), so a wallet that used more than this many addresses on one branch needs a larger limit.
pub const SCAN_ADDRESSES: u32 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub tree: u8,
    pub value: i64,
    pub script: Vec<u8>,
    pub confirmations: u64,
    pub coinbase: bool,
    pub branch: u32,
    pub index: u32,
    pub address: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRow {
    pub txid: String,
    pub height: Option<u64>,
    pub confirmations: u64,
    /// Received by this account minus spent from it, in atoms.
    pub delta: i64,
    pub fee: Option<i64>,
}

#[derive(Clone, Debug, Default)]
pub struct Scan {
    pub utxos: Vec<Utxo>,
    pub history: Vec<HistoryRow>,
    pub next_external: u32,
    pub next_internal: u32,
    pub tip: u64,
    pub coinbase_maturity: u64,
}

impl Scan {
    fn mature(&self, u: &Utxo) -> bool {
        !u.coinbase || u.confirmations >= self.coinbase_maturity
    }

    /// Confirmed, mature, spendable atoms.
    pub fn spendable(&self) -> i64 {
        self.utxos
            .iter()
            .filter(|u| u.confirmations >= 1 && self.mature(u))
            .map(|u| u.value)
            .sum()
    }

    /// Unconfirmed atoms (mempool).
    pub fn pending(&self) -> i64 {
        self.utxos
            .iter()
            .filter(|u| u.confirmations == 0)
            .map(|u| u.value)
            .sum()
    }

    /// Confirmed coinbase atoms that are not yet mature.
    pub fn immature(&self) -> i64 {
        self.utxos
            .iter()
            .filter(|u| u.confirmations >= 1 && !self.mature(u))
            .map(|u| u.value)
            .sum()
    }
}

pub(crate) fn atoms(v: &Value) -> i64 {
    v.as_f64().map(|f| (f * 1e8).round() as i64).unwrap_or(0)
}

struct Row {
    height: Option<u64>,
    delta: i64,
    fee: Option<i64>,
}

/// Rebuild the account's unspent outputs and history by reading every block from `birthday` to the tip, then the
/// mempool, from a dcrd node (no address index needed). The node learns which blocks you read but not your addresses.
pub async fn scan(rpc: &DcrdRpc, account: &Account, birthday: u64) -> Result<Scan, DecredError> {
    let mut scripts: HashMap<Vec<u8>, (u32, u32, String)> = HashMap::new();
    for branch in [0u32, 1u32] {
        for index in 0..SCAN_ADDRESSES {
            let address = account.address(branch, index)?;
            let decoded = dcr_rs::address::Address::decode(&address)
                .map_err(|e| DecredError::Address(format!("{e:?}")))?;
            scripts.insert(decoded.pk_script(), (branch, index, address));
        }
    }
    let tip = rpc.block_count().await?;
    let mut owned: HashMap<(String, u32), Utxo> = HashMap::new();
    let mut rows: Vec<(String, Row)> = Vec::new();
    let (mut max_external, mut max_internal) = (0u32, 0u32);

    let mut process =
        |tx: &Value, height: Option<u64>, owned: &mut HashMap<(String, u32), Utxo>| {
            let Some(txid) = tx.get("txid").and_then(Value::as_str) else {
                return;
            };
            let (mut spent, mut received, mut all_in, mut total_in, mut total_out) =
                (0i64, 0i64, true, 0i64, 0i64);
            let is_coinbase = tx["vin"]
                .as_array()
                .and_then(|v| v.first())
                .is_some_and(|v| v.get("coinbase").is_some());
            for vin in tx["vin"].as_array().into_iter().flatten() {
                if vin.get("coinbase").is_some() || vin.get("stakebase").is_some() {
                    all_in = false;
                    continue;
                }
                total_in += atoms(&vin["amountin"]);
                let key = (
                    vin["txid"].as_str().unwrap_or_default().to_string(),
                    vin["vout"].as_u64().unwrap_or(0) as u32,
                );
                if let Some(u) = owned.remove(&key) {
                    spent += u.value;
                }
            }
            for vout in tx["vout"].as_array().into_iter().flatten() {
                let value = atoms(&vout["value"]);
                total_out += value;
                let script = hex::decode(vout["scriptPubKey"]["hex"].as_str().unwrap_or_default())
                    .unwrap_or_default();
                let Some((branch, index, address)) = scripts.get(&script) else {
                    continue;
                };
                received += value;
                if *branch == 0 {
                    max_external = max_external.max(index + 1);
                } else {
                    max_internal = max_internal.max(index + 1);
                }
                let n = vout["n"].as_u64().unwrap_or(0) as u32;
                owned.insert(
                    (txid.to_string(), n),
                    Utxo {
                        txid: txid.to_string(),
                        vout: n,
                        tree: 0,
                        value,
                        script,
                        confirmations: height.map_or(0, |h| tip.saturating_sub(h) + 1),
                        coinbase: is_coinbase,
                        branch: *branch,
                        index: *index,
                        address: address.clone(),
                    },
                );
            }
            if spent > 0 || received > 0 {
                rows.push((
                    txid.to_string(),
                    Row {
                        height,
                        delta: received - spent,
                        fee: all_in.then_some(total_in - total_out),
                    },
                ));
            }
        };

    for height in birthday..=tip {
        let hash = rpc.block_hash(height).await?;
        let block = rpc.block(&hash).await?;
        for tx in block["rawtx"].as_array().into_iter().flatten() {
            process(tx, Some(height), &mut owned);
        }
    }
    for txid in rpc.mempool_txids().await? {
        let tx = rpc.raw_tx(&txid).await?;
        process(&tx, None, &mut owned);
    }
    let mut utxos: Vec<Utxo> = owned.into_values().collect();
    utxos.sort_by(|a, b| a.txid.cmp(&b.txid).then(a.vout.cmp(&b.vout)));
    let mut history: Vec<HistoryRow> = rows
        .into_iter()
        .map(|(txid, r)| HistoryRow {
            txid,
            height: r.height,
            confirmations: r.height.map_or(0, |h| tip.saturating_sub(h) + 1),
            delta: r.delta,
            fee: r.fee,
        })
        .collect();
    history.sort_by(|a, b| {
        b.height
            .unwrap_or(u64::MAX)
            .cmp(&a.height.unwrap_or(u64::MAX))
    });
    Ok(Scan {
        utxos,
        history,
        next_external: max_external,
        next_internal: max_internal,
        tip,
        coinbase_maturity: account.net.coinbase_maturity,
    })
}
