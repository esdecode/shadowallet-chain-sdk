use std::time::Duration;

use serde_json::{Value, json};

use crate::NanoError;
use crate::address::encode_address;
use crate::block::{BlockKind, SignedBlock};
use crate::keys::public_key;
use crate::network::NanoNet;
use crate::wallet::Prepared;
use crate::work::{Difficulty, generate_work};

/// Account chain head as reported by a node. `confirmed_*` come from the cemented (confirmation-height) state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountState {
    pub exists: bool,
    pub frontier: [u8; 32],
    pub balance: u128,
    pub representative: [u8; 32],
    pub confirmed_frontier: [u8; 32],
    pub confirmed_balance: u128,
    pub height: u64,
    pub confirmation_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receivable {
    pub hash: [u8; 32],
    pub amount: u128,
    pub source: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryItem {
    pub kind: String,
    pub counterparty: String,
    pub amount: u128,
    pub hash: String,
    pub height: u64,
    pub confirmed: bool,
    pub timestamp: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thresholds {
    pub send: Difficulty,
    pub receive: Difficulty,
}

pub struct NanoRpc {
    url: String,
    client: reqwest::Client,
}

fn hex32(v: &Value, what: &str) -> Result<[u8; 32], NanoError> {
    let s = v
        .as_str()
        .ok_or_else(|| NanoError::Rpc(format!("missing {what}")))?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| NanoError::Rpc(format!("bad {what}")))?;
    Ok(out)
}

fn u128_of(v: &Value, what: &str) -> Result<u128, NanoError> {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| NanoError::Rpc(format!("bad {what}")))
}

fn u64_of(v: &Value) -> u64 {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| v.as_u64())
        .unwrap_or(0)
}

impl NanoRpc {
    pub fn new(url: &str) -> Result<Self, NanoError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| NanoError::Rpc(e.to_string()))?;
        Ok(Self {
            url: url.to_string(),
            client,
        })
    }

    async fn call(&self, body: Value) -> Result<Value, NanoError> {
        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| NanoError::Rpc(e.to_string()))?;
        let value: Value = resp
            .json()
            .await
            .map_err(|e| NanoError::Rpc(e.to_string()))?;
        if let Some(err) = value.get("error").and_then(Value::as_str) {
            return Err(NanoError::Rpc(err.to_string()));
        }
        Ok(value)
    }

    /// Network identity as reported by the node. The result can only be turned into a signing-capable `NanoNet` when
    /// it is not the live network and is a pinned test network.
    pub async fn network(&self) -> Result<NanoNet, NanoError> {
        let v = self.call(json!({"action": "version"})).await?;
        let name = v
            .get("network")
            .and_then(Value::as_str)
            .ok_or_else(|| NanoError::Rpc("no network name".into()))?;
        let id = v
            .get("network_identifier")
            .and_then(Value::as_str)
            .ok_or_else(|| NanoError::Rpc("no network identifier".into()))?;
        NanoNet::verify(name, id)
    }

    /// Raw identity for read-only display (never grants signing).
    pub async fn identity(&self) -> Result<(String, String), NanoError> {
        let v = self.call(json!({"action": "version"})).await?;
        let s = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Ok((s("network"), s("network_identifier")))
    }

    pub async fn thresholds(&self) -> Result<Thresholds, NanoError> {
        let v = self.call(json!({"action": "active_difficulty"})).await?;
        let get = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .ok_or_else(|| NanoError::Rpc(format!("no {k}")))
        };
        Ok(Thresholds {
            send: Difficulty::from_hex(get("network_minimum")?)?,
            receive: Difficulty::from_hex(get("network_receive_minimum")?)?,
        })
    }

    pub async fn account_state(&self, account: &[u8; 32]) -> Result<AccountState, NanoError> {
        let body = json!({"action": "account_info", "account": encode_address(account), "representative": "true", "include_confirmed": "true"});
        let v = match self.call(body).await {
            Ok(v) => v,
            Err(NanoError::Rpc(m)) if m.contains("Account not found") => {
                return Ok(AccountState::default());
            }
            Err(e) => return Err(e),
        };
        let rep = v
            .get("representative")
            .and_then(Value::as_str)
            .ok_or_else(|| NanoError::Rpc("no representative".into()))?;
        Ok(AccountState {
            exists: true,
            frontier: hex32(&v["frontier"], "frontier")?,
            balance: u128_of(&v["balance"], "balance")?,
            representative: crate::address::decode_address(rep)?,
            confirmed_frontier: v
                .get("confirmed_frontier")
                .map(|f| hex32(f, "confirmed_frontier"))
                .transpose()?
                .unwrap_or([0u8; 32]),
            confirmed_balance: v
                .get("confirmed_balance")
                .map(|b| u128_of(b, "confirmed_balance"))
                .transpose()?
                .unwrap_or(0),
            height: u64_of(&v["block_count"]),
            confirmation_height: u64_of(&v["confirmation_height"]),
        })
    }

    /// Receivable (pending) sends above `threshold_raw`, with the sending account.
    pub async fn receivable(
        &self,
        account: &[u8; 32],
        threshold_raw: u128,
    ) -> Result<Vec<Receivable>, NanoError> {
        let body = json!({"action": "receivable", "account": encode_address(account), "count": "50", "threshold": threshold_raw.to_string(), "source": "true"});
        let v = self.call(body).await?;
        let mut out = Vec::new();
        if let Some(map) = v.get("blocks").and_then(Value::as_object) {
            for (hash, item) in map {
                let mut h = [0u8; 32];
                hex::decode_to_slice(hash, &mut h)
                    .map_err(|_| NanoError::Rpc("bad receivable hash".into()))?;
                out.push(Receivable {
                    hash: h,
                    amount: u128_of(&item["amount"], "amount")?,
                    source: item
                        .get("source")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                });
            }
        }
        out.sort_by_key(|r| r.hash);
        Ok(out)
    }

    pub async fn history(
        &self,
        account: &[u8; 32],
        count: u32,
    ) -> Result<Vec<HistoryItem>, NanoError> {
        let body = json!({"action": "account_history", "account": encode_address(account), "count": count.to_string()});
        let v = match self.call(body).await {
            Ok(v) => v,
            Err(NanoError::Rpc(m)) if m.contains("Account not found") => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        if let Some(list) = v.get("history").and_then(Value::as_array) {
            for h in list {
                out.push(HistoryItem {
                    kind: h["type"].as_str().unwrap_or_default().to_string(),
                    counterparty: h["account"].as_str().unwrap_or_default().to_string(),
                    amount: h["amount"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                    hash: h["hash"].as_str().unwrap_or_default().to_string(),
                    height: u64_of(&h["height"]),
                    confirmed: h["confirmed"].as_str() == Some("true"),
                    timestamp: u64_of(&h["local_timestamp"]),
                });
            }
        }
        Ok(out)
    }

    pub async fn is_confirmed(&self, hash: &[u8; 32]) -> Result<bool, NanoError> {
        let v = self.call(json!({"action": "block_info", "json_block": "true", "hash": hex::encode_upper(hash)})).await?;
        Ok(v.get("confirmed").and_then(Value::as_str) == Some("true"))
    }

    /// Sign, compute proof of work at the node's current threshold, verify both locally and broadcast.
    /// The `NanoNet` argument can only exist for a verified non-live network, so this cannot target mainnet.
    pub async fn submit(
        &self,
        net: &NanoNet,
        prepared: &Prepared,
        private: &[u8; 32],
        threads: usize,
    ) -> Result<[u8; 32], NanoError> {
        // Re-check identity at the moment of broadcast: the node may have changed since the review.
        let live = self.network().await?;
        if live != *net {
            return Err(NanoError::Network(
                "node network identity changed since review".into(),
            ));
        }
        if public_key(private) != prepared.block.account {
            return Err(NanoError::Block(
                "signing key does not belong to the block account".into(),
            ));
        }
        let thresholds = self.thresholds().await?;
        let difficulty = match prepared.kind {
            BlockKind::Open | BlockKind::Receive => thresholds.receive,
            BlockKind::Send | BlockKind::Change => thresholds.send,
        };
        let mut signed = SignedBlock::sign(prepared.block.clone(), private)?;
        let root = signed.block.work_root();
        let work = generate_work(&root, difficulty, threads, 1 << 40)?;
        if !difficulty.is_met(work, &root) {
            return Err(NanoError::Block(
                "generated work does not meet the threshold".into(),
            ));
        }
        signed.work = Some(work);
        signed.verify()?;
        let body = json!({"action": "process", "json_block": "true", "subtype": prepared.kind.subtype(), "block": signed.to_json()});
        let v = self.call(body).await?;
        let returned = hex32(&v["hash"], "hash")?;
        if returned != signed.block.hash() {
            return Err(NanoError::Rpc(
                "node returned a different block hash than the one signed".into(),
            ));
        }
        Ok(returned)
    }
}
