//! Dogecoin **testnet** backend built from two public, untrusted services instead of a full node.
//!
//! * SoChain v3 (`DOGETEST`): address UTXOs (with the raw transaction), address history, transaction status.
//! * A Dogecoin Core JSON-RPC gateway (Tatum): genesis identity, block-hash cross-checks, `gettxout` cross-checks
//!   of every UTXO, `estimatesmartfee`, `sendrawtransaction`.
//!
//! Nothing secret ever reaches either service: only public addresses, txids and a finished, signed
//! transaction (which is public by definition). Everything a service says is validated:
//!
//! * identity: both services must report the Dogecoin testnet genesis hash, and must agree on the hash of a
//!   recent block, before anything is read for spending;
//! * every UTXO is checked against its own raw transaction (txid recomputed, output value and script compared
//!   with the claim and with our address) and then against the second service's `gettxout`;
//! * contradictions between the services reject the whole answer; they are never averaged or guessed.
//!
//! Reads are retried a bounded number of times. A broadcast is attempted exactly once: when its outcome is
//! uncertain the error says so and the caller must neither rebroadcast nor release the inputs.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use doge::consensus::encode::deserialize_hex;
use doge::{ScriptBuf, Transaction, Txid};
use serde_json::{Value, json};
use shadowallet_chain_utxo::UtxoHistoryEntry;

use crate::DogecoinSdkError;

/// Dogecoin testnet genesis block hash (identity of the network; the API name is never trusted).
pub const TESTNET_GENESIS: &str =
    "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e";
const SOCHAIN_NETWORK: &str = "DOGETEST";
/// How deep below the tip the two services are made to agree on a block hash.
const CROSS_CHECK_DEPTH: u64 = 12;
/// Spendable UTXOs that are cross-checked per sync (the rest are ignored, never trusted).
pub const MAX_VERIFIED_UTXOS: usize = 5;
/// Coinbase outputs need this many confirmations before they may be spent.
const COINBASE_MATURITY: u32 = 240;
/// The indexer's UTXO page size, and how many pages one address may use (400 outputs).
const UTXO_PAGE_SIZE: usize = 10;
const MAX_UTXO_PAGES: u32 = 40;
const MAX_BODY: usize = 4 * 1024 * 1024;
const FEE_CACHE: Duration = Duration::from_secs(600);
/// Hard ceiling on a believable fee rate (DOGE per kB). Anything above is treated as a bad answer.
const MAX_SANE_FEE_DOGE_PER_KB: f64 = 1.0;
/// Dogecoin's recommended fee when no estimate is available: 0.01 DOGE per kB = 1000 koinu per byte.
const RECOMMENDED_SAT_VB: u64 = 1000;

#[derive(Debug, Clone)]
pub struct IndexerConfig {
    /// e.g. `https://sochain.com/api/v3`
    pub sochain_base: String,
    /// JSON-RPC endpoint of a Dogecoin Core node, e.g. `https://dogecoin-testnet.gateway.tatum.io`
    pub rpc_url: String,
    pub request_timeout: Duration,
    /// Request ceiling per engine instance for each service (protects the free tiers).
    pub max_requests: u32,
    /// JSON-RPC calls allowed per rolling minute (Tatum free tier: 5).
    pub rpc_per_minute: u32,
    /// Retries of a failed READ (never of a broadcast).
    pub read_retries: u32,
}

impl IndexerConfig {
    pub fn public_testnet() -> Self {
        Self {
            sochain_base: "https://sochain.com/api/v3".to_owned(),
            rpc_url: "https://dogecoin-testnet.gateway.tatum.io".to_owned(),
            request_timeout: Duration::from_secs(20),
            max_requests: 400,
            rpc_per_minute: 5,
            read_retries: 2,
        }
    }
}

/// A UTXO that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUtxo {
    pub txid: Txid,
    pub vout: u32,
    pub value_sats: u64,
    pub confirmations: u32,
    /// Taken from the validated raw transaction (its only input is the null outpoint), not from the provider's claim.
    pub coinbase: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxStatus {
    pub confirmations: i64,
}

fn err(kind: &str, detail: impl std::fmt::Display) -> DogecoinSdkError {
    DogecoinSdkError::Transaction(format!("{kind}: {detail}"))
}

/// The text shape of a node's JSON-RPC error answer, so the reservation layer can classify it
/// (`-22/-25/-26` rejected, `-5` unknown transaction) exactly as it does for a local node.
fn node_error(code: i64, message: &str) -> DogecoinSdkError {
    DogecoinSdkError::Transaction(format!(
        "JSON-RPC error: RPC error response: RpcError {{ code: {code}, message: {message:?}, data: None }}"
    ))
}

/// `"10001.51200000"` -> koinu, exactly. No floats.
pub fn parse_amount(text: &str) -> Option<u64> {
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() || frac.len() > 8 {
        return None;
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = whole.parse().ok()?;
    let frac: u64 = format!("{frac:0<8}").parse().ok()?;
    whole.checked_mul(100_000_000)?.checked_add(frac)
}

fn doge_to_sats(value: f64) -> Option<u64> {
    if !value.is_finite() || value < 0.0 || value > 21_000_000_000.0 {
        return None;
    }
    Some((value * 100_000_000.0).round() as u64)
}

fn is_txid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

struct Counters {
    sochain: u32,
    rpc: u32,
    rpc_calls: VecDeque<Instant>,
    identity_ok: bool,
    fee: Option<(Instant, u64)>,
}

pub struct Indexer {
    cfg: IndexerConfig,
    http: reqwest::blocking::Client,
    state: Mutex<Counters>,
}

impl std::fmt::Debug for Indexer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Indexer")
            .field("sochain", &self.cfg.sochain_base)
            .field("rpc", &self.cfg.rpc_url)
            .finish_non_exhaustive()
    }
}

fn check_url(url: &str, what: &str) -> Result<(), DogecoinSdkError> {
    let local = url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost");
    if url.starts_with("https://") || local {
        Ok(())
    } else {
        Err(err("config", format!("{what} must use https")))
    }
}

impl Indexer {
    pub fn new(cfg: IndexerConfig) -> Result<Self, DogecoinSdkError> {
        check_url(&cfg.sochain_base, "indexer url")?;
        check_url(&cfg.rpc_url, "rpc url")?;
        let http = reqwest::blocking::Client::builder()
            .timeout(cfg.request_timeout)
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("shadowallet-testnet-wallet")
            .build()
            .map_err(|e| err("config", e))?;
        Ok(Self {
            cfg,
            http,
            state: Mutex::new(Counters {
                sochain: 0,
                rpc: 0,
                rpc_calls: VecDeque::new(),
                identity_ok: false,
                fee: None,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Counters> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    // ------------------------------------------------------------------ SoChain
    fn sochain_get(&self, path: &str) -> Result<Value, DogecoinSdkError> {
        let url = format!("{}/{path}", self.cfg.sochain_base.trim_end_matches('/'));
        let mut last = String::new();
        for attempt in 0..=self.cfg.read_retries {
            {
                let mut s = self.lock();
                if s.sochain >= self.cfg.max_requests {
                    return Err(err(
                        "budget",
                        "indexer request budget exhausted for this session",
                    ));
                }
                s.sochain += 1;
            }
            match self.http.get(&url).send() {
                Ok(resp) => {
                    let code = resp.status();
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok());
                    let body = match resp.bytes() {
                        Ok(b) if b.len() <= MAX_BODY => b,
                        Ok(_) => return Err(err("malformed", "indexer answer too large")),
                        Err(e) => {
                            last = format!("transport: {e}");
                            std::thread::sleep(Duration::from_millis(400 * (attempt as u64 + 1)));
                            continue;
                        }
                    };
                    if code.as_u16() == 429 || code.is_server_error() {
                        last = format!("indexer http {}", code.as_u16());
                        let wait = retry_after.unwrap_or(2 * (attempt as u64 + 1)).min(20);
                        if attempt < self.cfg.read_retries {
                            std::thread::sleep(Duration::from_secs(wait));
                        }
                        continue;
                    }
                    let value: Value = serde_json::from_slice(&body)
                        .map_err(|_| err("malformed", "indexer answer is not JSON"))?;
                    if value.get("status").and_then(Value::as_str) != Some("success") {
                        let msg = value
                            .pointer("/data/error_message")
                            .and_then(Value::as_str)
                            .unwrap_or("unspecified");
                        return Err(err("indexer", msg));
                    }
                    return value
                        .get("data")
                        .cloned()
                        .ok_or_else(|| err("malformed", "indexer answer has no data"));
                }
                Err(e) => {
                    last = if e.is_timeout() {
                        "timeout".to_owned()
                    } else {
                        format!("transport: {e}")
                    };
                    if attempt < self.cfg.read_retries {
                        std::thread::sleep(Duration::from_millis(400 * (attempt as u64 + 1)));
                    }
                }
            }
        }
        Err(err("indexer unavailable", last))
    }

    // ---------------------------------------------------------------------- RPC
    /// Wait for a slot in the rolling per-minute window (bounded), or fail when `wait` is false.
    fn rpc_slot(&self, wait: bool) -> Result<(), DogecoinSdkError> {
        loop {
            let delay = {
                let mut s = self.lock();
                let now = Instant::now();
                while s
                    .rpc_calls
                    .front()
                    .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(61))
                {
                    s.rpc_calls.pop_front();
                }
                if s.rpc >= self.cfg.max_requests {
                    return Err(err(
                        "budget",
                        "rpc request budget exhausted for this session",
                    ));
                }
                if (s.rpc_calls.len() as u32) < self.cfg.rpc_per_minute {
                    s.rpc_calls.push_back(now);
                    s.rpc += 1;
                    return Ok(());
                }
                s.rpc_calls
                    .front()
                    .map(|t| Duration::from_secs(61).saturating_sub(now.duration_since(*t)))
                    .unwrap_or_default()
            };
            if !wait {
                return Err(err("rate limited", "rpc quota for this minute is used"));
            }
            std::thread::sleep(delay.min(Duration::from_secs(62)));
        }
    }

    /// One JSON-RPC call. `read` calls are retried a bounded number of times; a write is sent once.
    fn rpc(
        &self,
        method: &str,
        params: Value,
        read: bool,
        wait: bool,
    ) -> Result<Value, DogecoinSdkError> {
        let tries = if read { self.cfg.read_retries + 1 } else { 1 };
        let mut last = String::new();
        for attempt in 0..tries {
            self.rpc_slot(wait)?;
            let body = json!({"jsonrpc": "1.0", "id": "sw", "method": method, "params": params});
            match self.http.post(&self.cfg.rpc_url).json(&body).send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let bytes = match resp.bytes() {
                        Ok(b) if b.len() <= MAX_BODY => b,
                        Ok(_) => return Err(err("malformed", "rpc answer too large")),
                        Err(e) => {
                            if !read {
                                return Err(err("transport (outcome unknown)", e));
                            }
                            last = format!("transport: {e}");
                            continue;
                        }
                    };
                    if status == 429 {
                        if !read {
                            return Err(err("rate limited (not processed by the gateway)", status));
                        }
                        last = "rate limited".to_owned();
                        if attempt + 1 < tries {
                            std::thread::sleep(Duration::from_secs(15));
                        }
                        continue;
                    }
                    let value: Value = match serde_json::from_slice(&bytes) {
                        Ok(v) => v,
                        Err(_) if !read => {
                            return Err(err(
                                "malformed answer (outcome unknown)",
                                format!("http {status}"),
                            ));
                        }
                        Err(_) => {
                            last = format!("malformed answer, http {status}");
                            continue;
                        }
                    };
                    if let Some(e) = value.get("error").filter(|e| !e.is_null()) {
                        let code = e.get("code").and_then(Value::as_i64).unwrap_or(0);
                        let message = e
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("unspecified");
                        return Err(node_error(code, message));
                    }
                    return value
                        .get("result")
                        .cloned()
                        .ok_or_else(|| err("malformed", "rpc answer has no result"));
                }
                Err(e) => {
                    if !read {
                        // The request may have reached the node: the outcome is UNKNOWN, never "failed".
                        let kind = if e.is_timeout() {
                            "timeout (outcome unknown)"
                        } else {
                            "transport (outcome unknown)"
                        };
                        return Err(err(kind, e));
                    }
                    last = format!("transport: {e}");
                }
            }
        }
        Err(err("rpc unavailable", last))
    }

    // ----------------------------------------------------------------- identity
    /// Both services must be the Dogecoin testnet (genesis) and agree on a recent block. Memoised.
    pub fn ensure_identity(&self) -> Result<(), DogecoinSdkError> {
        if self.lock().identity_ok {
            return Ok(());
        }
        let genesis = self.sochain_get(&format!("block/{SOCHAIN_NETWORK}/0"))?;
        if genesis.get("hash").and_then(Value::as_str) != Some(TESTNET_GENESIS) {
            return Err(err(
                "identity mismatch",
                "the indexer's block 0 is not the Dogecoin testnet genesis",
            ));
        }
        let node_genesis = self.rpc("getblockhash", json!([0]), true, true)?;
        if node_genesis.as_str() != Some(TESTNET_GENESIS) {
            return Err(err(
                "identity mismatch",
                "the RPC node's block 0 is not the Dogecoin testnet genesis",
            ));
        }
        let (tip, _) = self.tip()?;
        let probe = tip.saturating_sub(CROSS_CHECK_DEPTH);
        let theirs = self.sochain_get(&format!("block/{SOCHAIN_NETWORK}/{probe}"))?;
        let theirs = theirs
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let ours = self.rpc("getblockhash", json!([probe]), true, true)?;
        if !is_txid(&theirs) || ours.as_str() != Some(theirs.as_str()) {
            return Err(err(
                "contradiction",
                format!("the services disagree about the hash of block {probe}"),
            ));
        }
        self.lock().identity_ok = true;
        Ok(())
    }

    /// `(height, best block hash)` according to the indexer.
    pub fn tip(&self) -> Result<(u64, String), DogecoinSdkError> {
        let info = self.sochain_get(&format!("network_info/{SOCHAIN_NETWORK}"))?;
        let height = info
            .get("block_count")
            .and_then(Value::as_u64)
            .filter(|h| *h > 0);
        let hash = info
            .get("best_block_hash")
            .and_then(Value::as_str)
            .filter(|h| is_txid(h));
        match (height, hash) {
            (Some(h), Some(hash)) => Ok((h, hash.to_owned())),
            _ => Err(err("malformed", "network info lacks a tip")),
        }
    }

    // -------------------------------------------------------------------- UTXOs
    /// UTXOs of one address, every entry validated against its own raw transaction.
    pub fn unspent(
        &self,
        address: &str,
        script: &ScriptBuf,
        tip: u64,
    ) -> Result<Vec<VerifiedUtxo>, DogecoinSdkError> {
        // The indexer pages its answer (10 per page). A silently truncated list would understate the
        // balance, so every page is read and an answer that may still be incomplete is refused.
        let mut outputs: Vec<Value> = Vec::new();
        for page in 1..=MAX_UTXO_PAGES {
            let data = self.sochain_get(&format!(
                "unspent_outputs/{SOCHAIN_NETWORK}/{address}/{page}"
            ))?;
            let list = data
                .get("outputs")
                .and_then(Value::as_array)
                .ok_or_else(|| err("malformed", "unspent outputs are not a list"))?;
            outputs.extend(list.iter().cloned());
            if list.len() < UTXO_PAGE_SIZE {
                break;
            }
            if page == MAX_UTXO_PAGES {
                return Err(err(
                    "incomplete",
                    "this address holds more outputs than the indexer backend reads; consolidate them",
                ));
            }
        }
        let want_script = hex::encode(script.as_bytes());
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for o in outputs {
            let hash = o.get("hash").and_then(Value::as_str).unwrap_or_default();
            let index = o
                .get("index")
                .and_then(Value::as_u64)
                .filter(|i| *i <= u32::MAX as u64);
            let (Some(index), true) = (index, is_txid(hash)) else {
                return Err(err("malformed", "unspent output without a valid outpoint"));
            };
            if o.get("address").and_then(Value::as_str) != Some(address) {
                return Err(err(
                    "contradiction",
                    "an output for another address was returned",
                ));
            }
            if o.get("script").and_then(Value::as_str) != Some(want_script.as_str()) {
                return Err(err(
                    "contradiction",
                    "output script is not this address's script",
                ));
            }
            let claimed = o
                .get("value")
                .and_then(Value::as_str)
                .and_then(parse_amount)
                .ok_or_else(|| err("malformed", "unparsable output value"))?;
            let tx_hex = o.get("tx_hex").and_then(Value::as_str).unwrap_or_default();
            let tx: Transaction = deserialize_hex(tx_hex)
                .map_err(|_| err("malformed", "raw transaction does not decode"))?;
            if tx.compute_txid().to_string() != hash {
                return Err(err(
                    "contradiction",
                    "raw transaction does not hash to the claimed txid",
                ));
            }
            let real = tx
                .output
                .get(index as usize)
                .ok_or_else(|| err("contradiction", "output index is outside the transaction"))?;
            if real.script_pubkey != *script || real.value.to_sat() != claimed {
                return Err(err(
                    "contradiction",
                    "claimed value or script differs from the transaction",
                ));
            }
            if !seen.insert((hash.to_owned(), index)) {
                return Err(err("contradiction", "duplicate outpoint"));
            }
            let confirmations = match o.get("block").and_then(Value::as_u64) {
                Some(b) if b <= tip => (tip - b + 1).min(u32::MAX as u64) as u32,
                Some(b) if b <= tip + 2 => 1,
                Some(_) => return Err(err("contradiction", "output is in a block above the tip")),
                None => 0,
            };
            let txid = hash.parse::<Txid>().map_err(|_| err("malformed", "txid"))?;
            out.push(VerifiedUtxo {
                txid,
                vout: index as u32,
                value_sats: claimed,
                confirmations,
                coinbase: tx.is_coinbase(),
            });
        }
        Ok(out)
    }

    /// Ask the RPC node (second opinion) whether the output is unspent and identical. Returns `Ok(coinbase)`.
    pub fn cross_check(
        &self,
        utxo: &VerifiedUtxo,
        script: &ScriptBuf,
        tip_age: Duration,
    ) -> Result<bool, DogecoinSdkError> {
        let answer = self.rpc(
            "gettxout",
            json!([utxo.txid.to_string(), utxo.vout, true]),
            true,
            true,
        )?;
        if answer.is_null() {
            return Err(err(
                "contradiction",
                "the indexer lists an output the node says is spent or unknown",
            ));
        }
        let value = answer
            .get("value")
            .and_then(Value::as_f64)
            .and_then(doge_to_sats);
        if value != Some(utxo.value_sats) {
            return Err(err(
                "contradiction",
                "the node reports another value for the output",
            ));
        }
        let script_hex = answer.pointer("/scriptPubKey/hex").and_then(Value::as_str);
        if script_hex != Some(hex::encode(script.as_bytes()).as_str()) {
            return Err(err(
                "contradiction",
                "the node reports another script for the output",
            ));
        }
        let node_conf = answer
            .get("confirmations")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            .max(0);
        // New blocks keep arriving while the rate-limited node is being asked: the node may be ahead by
        // about one block per 30 s since the tip was read (and a load-balanced node may lag a few blocks).
        let ahead = node_conf - utxo.confirmations as i64;
        if ahead < -10 || ahead > 10 + (tip_age.as_secs() / 30) as i64 {
            return Err(err(
                "contradiction",
                format!(
                    "the services disagree about the output's confirmations (indexer {}, node {node_conf}, tip read {}s ago)",
                    utxo.confirmations,
                    tip_age.as_secs()
                ),
            ));
        }
        Ok(answer
            .get("coinbase")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    }

    /// All verified, spendable UTXOs of `addresses` (script per address), largest first, at most
    /// [`MAX_VERIFIED_UTXOS`], every one confirmed by both services.
    pub fn verified_utxos(
        &self,
        addresses: &[(String, ScriptBuf)],
        tip: u64,
    ) -> Result<Vec<(usize, VerifiedUtxo)>, DogecoinSdkError> {
        let started = Instant::now();
        let mut all = Vec::new();
        for (i, (addr, script)) in addresses.iter().enumerate() {
            for u in self.unspent(addr, script, tip)? {
                all.push((i, u));
            }
        }
        // A coinbase output younger than the maturity cannot be spent: drop it BEFORE spending the scarce
        // cross-check budget on it (otherwise a few fresh block rewards would starve the mature coins). The raw
        // transaction was validated against its txid, and the node's own coinbase flag is still checked below.
        all.retain(|(_, u)| !(u.coinbase && u.confirmations < COINBASE_MATURITY));
        all.sort_by_key(|entry| std::cmp::Reverse(entry.1.value_sats));
        let mut spendable = Vec::new();
        for (i, u) in all.into_iter().take(MAX_VERIFIED_UTXOS) {
            let coinbase = self.cross_check(&u, &addresses[i].1, started.elapsed())?;
            if coinbase && u.confirmations < COINBASE_MATURITY {
                continue; // immature coinbase output: not spendable yet
            }
            spendable.push((i, u));
        }
        Ok(spendable)
    }

    // ------------------------------------------------------------------ history
    /// Display-only history (never used to select inputs). Provider figures are format-validated.
    pub fn history(
        &self,
        addresses: &[String],
        tip: u64,
    ) -> Result<Vec<UtxoHistoryEntry>, DogecoinSdkError> {
        self.history_with_used(addresses, tip).map(|(h, _)| h)
    }

    /// Like [`Indexer::history`], also returning the positions (in `addresses`) of every address that
    /// appears in at least one transaction. Used to keep change addresses from being handed out twice.
    pub fn history_with_used(
        &self,
        addresses: &[String],
        tip: u64,
    ) -> Result<(Vec<UtxoHistoryEntry>, Vec<usize>), DogecoinSdkError> {
        let mut merged: Vec<UtxoHistoryEntry> = Vec::new();
        let mut used: Vec<usize> = Vec::new();
        for (position, address) in addresses.iter().enumerate() {
            let data = self.sochain_get(&format!("transactions/{SOCHAIN_NETWORK}/{address}/1"))?;
            let list = data
                .get("transactions")
                .and_then(Value::as_array)
                .ok_or_else(|| err("malformed", "history is not a list"))?;
            if !list.is_empty() {
                used.push(position);
            }
            for t in list {
                let hash = t.get("hash").and_then(Value::as_str).unwrap_or_default();
                let received = t
                    .get("value_received")
                    .and_then(Value::as_str)
                    .and_then(parse_amount);
                let sent = t
                    .get("value_sent")
                    .and_then(Value::as_str)
                    .and_then(parse_amount);
                let (true, Some(received), Some(sent)) = (is_txid(hash), received, sent) else {
                    return Err(err("malformed", "history entry is not valid"));
                };
                let height = t
                    .get("block")
                    .and_then(Value::as_u64)
                    .filter(|b| *b <= tip + 2);
                if let Some(existing) = merged.iter_mut().find(|e| e.txid == hash) {
                    existing.received_sats = existing.received_sats.saturating_add(received);
                    existing.sent_sats = existing.sent_sats.saturating_add(sent);
                } else {
                    merged.push(UtxoHistoryEntry {
                        txid: hash.to_owned(),
                        received_sats: received,
                        sent_sats: sent,
                        confirmation_height: height,
                    });
                }
            }
        }
        Ok((merged, used))
    }

    // --------------------------------------------------------------------- fees
    /// `(sat/vB, source)`. One RPC estimate, cached for ten minutes; a sane recommended fee otherwise.
    pub fn fee_rate(&self) -> (u64, &'static str) {
        if let Some((at, rate)) = self.lock().fee
            && at.elapsed() < FEE_CACHE
        {
            return (rate, "estimatesmartfee");
        }
        let estimate = self
            .rpc("estimatesmartfee", json!([2]), true, true)
            .ok()
            .and_then(|v| v.get("feerate").and_then(Value::as_f64))
            .filter(|f| f.is_finite() && *f > 0.0 && *f <= MAX_SANE_FEE_DOGE_PER_KB);
        match estimate {
            Some(doge_per_kb) => {
                let rate = ((doge_per_kb * 100_000_000.0 / 1000.0).ceil() as u64).max(1);
                self.lock().fee = Some((Instant::now(), rate));
                (rate, "estimatesmartfee")
            }
            None => (RECOMMENDED_SAT_VB, "policy-recommended"),
        }
    }

    // ---------------------------------------------------------------- broadcast
    /// Send a signed transaction ONCE. The txid is recomputed locally and the node's answer must match.
    pub fn broadcast(&self, hex_tx: &str) -> Result<String, DogecoinSdkError> {
        let tx: Transaction =
            deserialize_hex(hex_tx).map_err(|_| err("invalid", "transaction does not decode"))?;
        let txid = tx.compute_txid().to_string();
        let answer = self.rpc("sendrawtransaction", json!([hex_tx]), false, true)?;
        match answer.as_str() {
            Some(t) if t == txid => Ok(txid),
            _ => Err(err(
                "outcome unknown",
                "the node answered with a different transaction id; do not rebroadcast",
            )),
        }
    }

    // ------------------------------------------------------------------- status
    /// Status from the indexer, cross-checked by the node when its quota allows (never waits for it).
    pub fn transaction_status(
        &self,
        txid: &str,
    ) -> Result<(TxStatus, Option<String>), DogecoinSdkError> {
        if !is_txid(txid) {
            return Err(err("invalid", "txid"));
        }
        match self.sochain_get(&format!("transaction/{SOCHAIN_NETWORK}/{txid}")) {
            Ok(data) => {
                if data.get("hash").and_then(Value::as_str) != Some(txid) {
                    return Err(err(
                        "contradiction",
                        "the indexer answered for another transaction",
                    ));
                }
                let confirmations = data
                    .get("confirmations")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    .max(0);
                let block_hash = data
                    .get("block_hash")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if let Ok(node) = self.rpc("getrawtransaction", json!([txid, true]), false, false) {
                    let node_conf = node
                        .get("confirmations")
                        .and_then(Value::as_i64)
                        .unwrap_or(0)
                        .max(0);
                    if (node_conf - confirmations).abs() > 3 && node_conf.min(confirmations) > 0 {
                        return Err(err(
                            "contradiction",
                            "the services disagree about the confirmations",
                        ));
                    }
                }
                Ok((TxStatus { confirmations }, block_hash))
            }
            Err(indexer_error) => {
                // The indexer does not know it (or is down): ask the node, which also sees its mempool.
                match self.rpc("getrawtransaction", json!([txid, true]), true, true) {
                    Ok(node) => {
                        let confirmations = node
                            .get("confirmations")
                            .and_then(Value::as_i64)
                            .unwrap_or(0)
                            .max(0);
                        let block_hash = node
                            .get("blockhash")
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                        Ok((TxStatus { confirmations }, block_hash))
                    }
                    Err(node_error) => {
                        let text = node_error.to_string();
                        if text.contains("code: -5") {
                            Err(node_error) // a node's definite "unknown transaction"
                        } else {
                            Err(err(
                                "status unavailable",
                                format!("{indexer_error}; {text}"),
                            ))
                        }
                    }
                }
            }
        }
    }

    /// Is this output still unspent according to the node (mempool included)?
    pub fn input_unspent(&self, txid: &str, vout: u32) -> Result<bool, DogecoinSdkError> {
        let answer = self.rpc("gettxout", json!([txid, vout, true]), true, true)?;
        Ok(!answer.is_null())
    }

    /// Is the transaction in the node's mempool right now?
    pub fn in_mempool(&self, txid: &str) -> Result<bool, DogecoinSdkError> {
        match self.rpc("getrawtransaction", json!([txid, true]), true, true) {
            Ok(node) => Ok(node.get("blockhash").and_then(Value::as_str).is_none()),
            Err(e) if e.to_string().contains("code: -5") => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_parsed_exactly() {
        assert_eq!(parse_amount("10001.51200000"), Some(1_000_151_200_000));
        assert_eq!(parse_amount("0.00000001"), Some(1));
        assert_eq!(parse_amount("5"), Some(500_000_000));
        assert_eq!(parse_amount("1.123456789"), None);
        assert_eq!(parse_amount("-1"), None);
        assert_eq!(parse_amount(".5"), None);
        assert_eq!(parse_amount("1e3"), None);
        assert_eq!(parse_amount("99999999999999999999.0"), None);
    }

    #[test]
    fn insecure_urls_are_refused() {
        let mut cfg = IndexerConfig::public_testnet();
        cfg.rpc_url = "http://example.com/rpc".to_owned();
        assert!(Indexer::new(cfg).is_err());
    }

    #[test]
    fn a_real_testnet_transaction_hashes_to_its_published_txid() {
        // Coinbase transaction 00fdbd1e... of Dogecoin testnet block 68061214, as served by SoChain and
        // decoded by an independent Dogecoin Core node (decoderawtransaction).
        let hex_tx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07041e880e040102ffffffff010031a8dde80000001976a91402d572eb59063071b8d068238ffef13f83d4809288ac00000000";
        let tx: Transaction = deserialize_hex(hex_tx).unwrap();
        assert_eq!(
            tx.compute_txid().to_string(),
            "00fdbd1ec7b9eb3b2535102390c1a8e8620a57277f3b3db4fdb602c87f2445fd"
        );
        assert_eq!(tx.output[0].value.to_sat(), 1_000_151_200_000);
    }
}
