//! Esplora-style REST backend for Litecoin (litecoinspace.org `/testnet/api`, self-hosted electrs/mempool).
//!
//! Only public data crosses this boundary: addresses and transaction ids go out, chain data comes back. No key,
//! seed or xpub is ever sent. The server is untrusted input: UTXO values are re-read from the transaction bytes
//! and checked against the txid before they are used, and a broadcast is accepted only if the returned txid
//! equals the locally computed one.
//!
//! This is NOT a generic Bitcoin Esplora client. Differences handled here: Litecoin address formats (`ltc1`,
//! `tltc1`, `rltc1`), `/v1/fees/recommended` (mempool.space dialect) with `/fee-estimates` (Esplora dialect)
//! as fallback, and the pinned Litecoin genesis hashes checked by the caller.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::LitecoinSdkError;

const MAX_BODY: usize = 4 * 1024 * 1024;
const PAGE: usize = 25;
const MAX_PAGES: usize = 40;
const ATTEMPTS: u32 = 4;

fn fail(msg: impl Into<String>) -> LitecoinSdkError {
    LitecoinSdkError::Transaction(msg.into())
}

/// A transaction as the Esplora JSON describes it (only what the wallet needs).
#[derive(Debug, Clone)]
pub struct EsploraTx {
    pub txid: String,
    pub height: Option<u64>,
    /// Previous outputs: (scriptpubkey hex, value). `None` for a coinbase input.
    pub inputs: Vec<Option<(String, u64)>>,
    /// Outputs: (scriptpubkey hex, value).
    pub outputs: Vec<(String, u64)>,
}

#[derive(Debug, Clone)]
pub struct EsploraUtxo {
    pub txid: String,
    pub vout: u32,
    pub height: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EsploraFees {
    pub economy: u64,
    pub normal: u64,
    pub priority: u64,
    pub source: &'static str,
}

#[derive(Clone)]
pub struct EsploraClient {
    base: String,
    http: reqwest::Client,
    rt: Arc<tokio::runtime::Runtime>,
}

impl std::fmt::Debug for EsploraClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EsploraClient")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl EsploraClient {
    pub fn new(base_url: &str) -> Result<Self, LitecoinSdkError> {
        let base = base_url.trim().trim_end_matches('/').to_owned();
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err(fail("Esplora url must be http or https"));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("shadowallet-chain-litecoin")
            .build()
            .map_err(|e| fail(e.to_string()))?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| fail(e.to_string()))?;
        Ok(Self {
            base,
            http,
            rt: Arc::new(rt),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// GET with bounded retries on rate limiting, server errors and transport errors. 404 is returned as an
    /// error whose text carries the Bitcoin-Core-compatible "No such mempool or blockchain transaction" wording
    /// for the transaction routes, so the reservation recovery classifies it as "not found".
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<Vec<u8>, LitecoinSdkError> {
        let url = format!("{}{}", self.base, path);
        let mut last = String::new();
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(600 * u64::from(attempt)));
            }
            let outcome: Result<(u16, Vec<u8>), String> = self.rt.block_on(async {
                let builder = if method == "POST" {
                    self.http
                        .post(&url)
                        .header("content-type", "text/plain")
                        .body(body.clone().unwrap_or_default())
                } else {
                    self.http.get(&url)
                };
                let response = builder.send().await.map_err(|e| e.to_string())?;
                let status = response.status().as_u16();
                let bytes = response.bytes().await.map_err(|e| e.to_string())?;
                if bytes.len() > MAX_BODY {
                    return Err("response too large".to_owned());
                }
                Ok((status, bytes.to_vec()))
            });
            match outcome {
                Ok((200, bytes)) => return Ok(bytes),
                Ok((404, _)) => {
                    return Err(fail(format!(
                        "No such mempool or blockchain transaction (code -5) [{path}: HTTP 404]"
                    )));
                }
                Ok((code @ (429 | 500 | 502 | 503 | 504), _)) => last = format!("HTTP {code}"),
                Ok((code, bytes)) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let text: String = text.chars().take(200).collect();
                    return Err(fail(format!("{path}: HTTP {code}: {text}")));
                }
                Err(e) => last = e,
            }
        }
        Err(fail(format!("{path}: {last}")))
    }

    fn get_json(&self, path: &str) -> Result<Value, LitecoinSdkError> {
        let bytes = self.request("GET", path, None)?;
        serde_json::from_slice(&bytes).map_err(|e| fail(format!("{path}: bad JSON: {e}")))
    }

    fn get_text(&self, path: &str) -> Result<String, LitecoinSdkError> {
        let bytes = self.request("GET", path, None)?;
        String::from_utf8(bytes)
            .map(|s| s.trim().to_owned())
            .map_err(|_| fail(format!("{path}: not UTF-8")))
    }

    /// Hash of the block at height 0: the network identity the caller compares with its pinned genesis.
    pub fn genesis_hash(&self) -> Result<String, LitecoinSdkError> {
        let h = self.get_text("/block-height/0")?;
        if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(h.to_ascii_lowercase())
        } else {
            Err(fail("backend returned a malformed genesis hash"))
        }
    }

    pub fn tip_height(&self) -> Result<u64, LitecoinSdkError> {
        self.get_text("/blocks/tip/height")?
            .parse()
            .map_err(|_| fail("backend returned a malformed tip height"))
    }

    fn parse_tx(value: &Value) -> Option<EsploraTx> {
        let txid = value.get("txid")?.as_str()?.to_owned();
        let confirmed = value.pointer("/status/confirmed")?.as_bool()?;
        let height = if confirmed {
            value
                .pointer("/status/block_height")
                .and_then(Value::as_u64)
        } else {
            None
        };
        let inputs = value
            .get("vin")?
            .as_array()?
            .iter()
            .map(|i| {
                let p = i.get("prevout")?;
                if p.is_null() {
                    return None;
                }
                Some((
                    p.get("scriptpubkey")?.as_str()?.to_owned(),
                    p.get("value")?.as_u64()?,
                ))
            })
            .collect();
        let outputs = value
            .get("vout")?
            .as_array()?
            .iter()
            .filter_map(|o| {
                Some((
                    o.get("scriptpubkey")?.as_str()?.to_owned(),
                    o.get("value")?.as_u64()?,
                ))
            })
            .collect();
        Some(EsploraTx {
            txid,
            height,
            inputs,
            outputs,
        })
    }

    /// Every transaction that touches `address`: mempool first, then confirmed pages of 25 (`/txs/chain/<last>`).
    pub fn address_txs(&self, address: &str) -> Result<Vec<EsploraTx>, LitecoinSdkError> {
        let mut all: Vec<EsploraTx> = Vec::new();
        let mut path = format!("/address/{address}/txs");
        for _ in 0..MAX_PAGES {
            let page = self.get_json(&path)?;
            let items = page
                .as_array()
                .ok_or_else(|| fail("address txs: not a list"))?;
            let mut confirmed_in_page = 0usize;
            let mut last_confirmed: Option<String> = None;
            for item in items {
                let tx =
                    Self::parse_tx(item).ok_or_else(|| fail("address txs: unexpected shape"))?;
                if tx.height.is_some() {
                    confirmed_in_page += 1;
                    last_confirmed = Some(tx.txid.clone());
                }
                if !all.iter().any(|t| t.txid == tx.txid) {
                    all.push(tx);
                }
            }
            match last_confirmed {
                Some(last) if confirmed_in_page >= PAGE => {
                    path = format!("/address/{address}/txs/chain/{last}");
                }
                _ => return Ok(all),
            }
        }
        Err(fail("address has more history than the page limit allows"))
    }

    pub fn address_utxos(&self, address: &str) -> Result<Vec<EsploraUtxo>, LitecoinSdkError> {
        let list = self.get_json(&format!("/address/{address}/utxo"))?;
        list.as_array()
            .ok_or_else(|| fail("utxo list: not a list"))?
            .iter()
            .map(|u| {
                let confirmed = u.pointer("/status/confirmed").and_then(Value::as_bool)?;
                Some(EsploraUtxo {
                    txid: u.get("txid")?.as_str()?.to_owned(),
                    vout: u32::try_from(u.get("vout")?.as_u64()?).ok()?,
                    height: if confirmed {
                        u.pointer("/status/block_height").and_then(Value::as_u64)
                    } else {
                        None
                    },
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| fail("utxo list: unexpected shape"))
    }

    pub fn tx_hex(&self, txid: &str) -> Result<String, LitecoinSdkError> {
        self.get_text(&format!("/tx/{txid}/hex"))
    }

    /// `Some(height)` once mined, `None` while in the mempool; `Err` (404 wording) when unknown to the server.
    pub fn tx_status(&self, txid: &str) -> Result<Option<u64>, LitecoinSdkError> {
        let status = self.get_json(&format!("/tx/{txid}/status"))?;
        match status.get("confirmed").and_then(Value::as_bool) {
            Some(true) => Ok(Some(
                status
                    .get("block_height")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| fail("tx status: no block height"))?,
            )),
            // litecoinspace answers `{"confirmed":false}` (HTTP 200) for a txid it has never seen, so an
            // unconfirmed answer only counts once the transaction itself is known (404 otherwise).
            Some(false) => {
                self.get_json(&format!("/tx/{txid}"))?;
                Ok(None)
            }
            None => Err(fail("tx status: unexpected shape")),
        }
    }

    /// Is output `vout` of `txid` still unspent (mempool spends included)?
    pub fn output_unspent(&self, txid: &str, vout: u32) -> Result<bool, LitecoinSdkError> {
        // Unknown txids also answer `{"spent":false}` here: prove the transaction exists first.
        self.get_json(&format!("/tx/{txid}"))?;
        let spend = self.get_json(&format!("/tx/{txid}/outspend/{vout}"))?;
        let spent = spend
            .get("spent")
            .and_then(Value::as_bool)
            .ok_or_else(|| fail("outspend: unexpected shape"))?;
        Ok(!spent)
    }

    pub fn broadcast(&self, hex: &str) -> Result<String, LitecoinSdkError> {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(fail("transaction is not hex"));
        }
        let bytes = self.request("POST", "/tx", Some(hex.to_owned()))?;
        String::from_utf8(bytes)
            .map(|s| s.trim().to_ascii_lowercase())
            .map_err(|_| fail("broadcast answer is not UTF-8"))
    }

    /// Fee rates in sat/vB. mempool.space dialect first, plain Esplora second; `None` when neither answers.
    pub fn fees(&self) -> Option<EsploraFees> {
        let ceil = |v: &Value| -> Option<u64> {
            let f = v.as_f64()?;
            (f.is_finite() && f > 0.0).then(|| (f.ceil() as u64).max(1))
        };
        if let Ok(v) = self.get_json("/v1/fees/recommended") {
            let eco = v.get("hourFee").and_then(ceil);
            let normal = v.get("halfHourFee").and_then(ceil);
            let fast = v.get("fastestFee").and_then(ceil);
            if let (Some(e), Some(n), Some(p)) = (eco, normal, fast) {
                let n = n.max(e);
                return Some(EsploraFees {
                    economy: e,
                    normal: n,
                    priority: p.max(n),
                    source: "esplora:/v1/fees/recommended",
                });
            }
        }
        if let Ok(v) = self.get_json("/fee-estimates") {
            let by = |t: &str| v.get(t).and_then(ceil);
            let eco = by("6").or_else(|| by("12"));
            let normal = by("2").or_else(|| by("3")).or(eco);
            let fast = by("1").or(normal);
            if let (Some(e), Some(n), Some(p)) = (eco, normal, fast) {
                let n = n.max(e);
                return Some(EsploraFees {
                    economy: e,
                    normal: n,
                    priority: p.max(n),
                    source: "esplora:/fee-estimates",
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_esplora_transaction_with_prevouts_and_a_coinbase() {
        let v: Value = serde_json::from_str(
            r#"{"txid":"aa","status":{"confirmed":true,"block_height":7},
            "vin":[{"prevout":{"scriptpubkey":"0014ab","value":5}},{"is_coinbase":true,"prevout":null}],
            "vout":[{"scriptpubkey":"0014cd","value":3}]}"#,
        )
        .unwrap_or_default();
        let tx = EsploraClient::parse_tx(&v);
        assert!(tx.is_some());
        let tx = tx.unwrap_or_else(unreachable_tx);
        assert_eq!(tx.height, Some(7));
        assert_eq!(tx.inputs, vec![Some(("0014ab".to_owned(), 5)), None]);
        assert_eq!(tx.outputs, vec![("0014cd".to_owned(), 3)]);
    }

    fn unreachable_tx() -> EsploraTx {
        EsploraTx {
            txid: String::new(),
            height: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    #[test]
    fn refuses_non_http_urls() {
        assert!(EsploraClient::new("file:///etc/passwd").is_err());
        assert!(EsploraClient::new("ftp://x").is_err());
        assert!(EsploraClient::new("https://litecoinspace.org/testnet/api/").is_ok());
    }
}
