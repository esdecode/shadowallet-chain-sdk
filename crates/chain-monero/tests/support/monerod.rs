//! A real `monerod` in `--regtest --offline` mode as the isolated chain for lifecycle tests.
//!
//! Regtest here shares the mainnet genesis block, the mainnet address prefixes and enforces hard fork 16 (CLSAG, Bulletproofs+,
//! ring size 16), so the production wallet connects to it as "monero-mainnet" without any change, and `monerod` itself validates
//! every submitted transaction (rings, signatures, range proofs, fee, key images) with its own consensus code. Nothing here
//! touches a public network: the daemon runs offline on 127.0.0.1 with a throw-away data directory.
//!
//! Tests that need it are skipped (reported as such) unless `SHADOWALLET_MONEROD` names the `monerod` executable.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct Monerod {
    child: Child,
    pub rpc_port: u16,
    pub url: String,
    _dir: tempfile::TempDir,
    http: reqwest::Client,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The executable named by `SHADOWALLET_MONEROD`, or `None` (the caller skips).
pub fn monerod_path() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("SHADOWALLET_MONEROD")?);
    p.is_file().then_some(p)
}

impl Monerod {
    pub async fn start() -> Option<Monerod> {
        let exe = monerod_path()?;
        let dir = tempfile::tempdir().unwrap();
        let rpc_port = free_port();
        let p2p_port = free_port();
        let child = Command::new(exe)
            .args([
                "--regtest",
                "--offline",
                "--fixed-difficulty",
                "1",
                "--non-interactive",
                "--no-zmq",
                "--rpc-bind-ip",
                "127.0.0.1",
                "--p2p-bind-ip",
                "127.0.0.1",
                "--p2p-bind-port",
                &p2p_port.to_string(),
                "--rpc-bind-port",
                &rpc_port.to_string(),
                "--data-dir",
            ])
            .arg(dir.path())
            .args(["--log-level", "0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start monerod");
        let me = Monerod {
            child,
            rpc_port,
            url: format!("http://127.0.0.1:{rpc_port}"),
            _dir: dir,
            http: reqwest::Client::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if me.get_height().await.is_some() {
                return Some(me);
            }
            assert!(Instant::now() < deadline, "monerod did not come up");
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    async fn post(&self, route: &str, body: String) -> Option<serde_json::Value> {
        let r = self
            .http
            .post(format!("{}/{route}", self.url))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .ok()?;
        serde_json::from_str(&r.text().await.ok()?).ok()
    }

    pub async fn get_height(&self) -> Option<u64> {
        self.post("get_height", String::new())
            .await?
            .get("height")?
            .as_u64()
    }

    pub async fn json_rpc(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let body = serde_json::json!({"jsonrpc":"2.0","id":"0","method":method,"params":params});
        self.post("json_rpc", body.to_string())
            .await
            .expect("json_rpc")
    }

    /// Mine `n` blocks whose coinbase pays `address` (regtest `generateblocks`, difficulty 1).
    pub async fn generate(&self, address: &str, n: u64) {
        let r = self
            .json_rpc(
                "generateblocks",
                serde_json::json!({"amount_of_blocks": n, "wallet_address": address}),
            )
            .await;
        assert!(r.get("error").is_none(), "generateblocks: {r}");
    }

    /// The transaction as the daemon itself decodes it (`get_transactions`, `decode_as_json`).
    pub async fn transaction(&self, txid: &[u8; 32]) -> Option<serde_json::Value> {
        let r = self
            .post(
                "get_transactions",
                serde_json::json!({"txs_hashes":[hex::encode(txid)],"decode_as_json":true})
                    .to_string(),
            )
            .await?;
        r.get("txs")?.as_array()?.first().cloned()
    }

    /// Regtest only: drop the newest `n` blocks (a chain reorganisation); their transactions go back to the pool.
    pub async fn pop_blocks(&self, n: u64) -> u64 {
        self.post(
            "pop_blocks",
            serde_json::json!({ "nblocks": n }).to_string(),
        )
        .await
        .and_then(|v| v["height"].as_u64())
        .expect("pop_blocks")
    }

    pub async fn pool_size(&self) -> u64 {
        self.post("get_transaction_pool_stats", String::new())
            .await
            .and_then(|v| v["pool_stats"]["txs_total"].as_u64())
            .unwrap_or(0)
    }

    pub async fn key_image_spent(&self, key_images: &[[u8; 32]]) -> Vec<u64> {
        let kis: Vec<String> = key_images.iter().map(hex::encode).collect();
        self.post(
            "is_key_image_spent",
            serde_json::json!({ "key_images": kis }).to_string(),
        )
        .await
        .and_then(|v| v["spent_status"].as_array().cloned())
        .map(|a| a.iter().filter_map(serde_json::Value::as_u64).collect())
        .unwrap_or_default()
    }

    /// Submit raw bytes to the daemon's own consensus validation, without going through the wallet.
    pub async fn send_raw(&self, raw: &[u8]) -> serde_json::Value {
        self.post(
            "send_raw_transaction",
            serde_json::json!({"tx_as_hex": hex::encode(raw), "do_not_relay": true}).to_string(),
        )
        .await
        .expect("send_raw_transaction")
    }
}

impl Drop for Monerod {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
