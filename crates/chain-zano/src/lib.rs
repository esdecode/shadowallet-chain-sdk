//! Zano (read-only node access and an honest capability report).
//!
//! # What this crate is, and is not
//!
//! Zano transactions use the Zarcanum confidential-asset construction. The only maintained implementation is the upstream C++ code
//! (`hyle-team/zano`, MIT; `hyle-team/zano_native_lib`, MIT, a prebuilt `plain_wallet` library with JSON-RPC style calls). There is no
//! Rust or WASM implementation. This crate therefore does **not** derive keys, build or sign transactions and contains no privacy
//! cryptography of its own: inventing any of it would be unsafe. What it does:
//!
//! * a minimal, validated JSON-RPC client for the public **daemon** API (`getinfo`) so a node can be checked and a chain height shown;
//! * a [`capabilities`] report that states, per feature, whether it is implemented, so a UI cannot present a placeholder as a wallet.
//!
//! Signing and broadcasting are not implemented on any network; [`ZanoNet::signing_enabled`] is `false` for all of them.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

/// Zano networks. Mainnet is read-only here like every other network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZanoNet {
    pub name: &'static str,
    pub mainnet: bool,
}

pub const MAINNET: ZanoNet = ZanoNet {
    name: "zano-mainnet",
    mainnet: true,
};
pub const TESTNET: ZanoNet = ZanoNet {
    name: "zano-testnet",
    mainnet: false,
};

impl ZanoNet {
    /// There is no signing code in this crate, so this is `false` everywhere. It exists so callers ask rather than assume.
    pub const fn signing_enabled(&self) -> bool {
        false
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ZanoError {
    #[error("invalid node url: {0}")]
    InvalidUrl(String),
    #[error("node request failed: {0}")]
    Rpc(String),
    #[error("unexpected node response: {0}")]
    Response(String),
}

/// The part of `getinfo` the wallet shows. Everything is as the node reported it; nothing is estimated.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NodeInfo {
    pub height: u64,
    pub last_block_hash: String,
    pub last_block_timestamp: u64,
    /// Atomic units (1 ZANO = 10^12).
    pub default_fee: u64,
    pub tx_count: u64,
    pub tx_pool_size: u64,
    /// Highest height this node has seen from its peers.
    pub max_net_seen_height: u64,
    pub daemon_network_state: u64,
}

impl NodeInfo {
    /// `daemon_network_state == 2` is the node's "online" state; any lag behind the network is reported, not hidden.
    pub fn is_synchronized(&self) -> bool {
        self.daemon_network_state == 2 && self.height + 2 >= self.max_net_seen_height
    }
}

/// Parses a `getinfo` JSON-RPC response. Pure; the only place node data enters.
pub fn parse_info(body: &str) -> Result<NodeInfo, ZanoError> {
    let value: Value =
        serde_json::from_str(body).map_err(|e| ZanoError::Response(e.to_string()))?;
    if let Some(error) = value.get("error") {
        return Err(ZanoError::Rpc(error.to_string()));
    }
    let result = value
        .get("result")
        .ok_or_else(|| ZanoError::Response("no result".to_owned()))?;
    if result.get("status").and_then(Value::as_str) != Some("OK") {
        return Err(ZanoError::Response(format!(
            "node status is not OK: {}",
            result.get("status").unwrap_or(&Value::Null)
        )));
    }
    let info: NodeInfo =
        serde_json::from_value(result.clone()).map_err(|e| ZanoError::Response(e.to_string()))?;
    if info.height == 0 || info.last_block_hash.len() != 64 {
        return Err(ZanoError::Response("implausible chain tip".to_owned()));
    }
    Ok(info)
}

/// Validates a daemon URL: http(s) only, a host, no embedded credentials, no query or fragment.
pub fn validate_node_url(url: &str) -> Result<String, ZanoError> {
    let bad = |why: &str| ZanoError::InvalidUrl(why.to_owned());
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| bad("only http:// or https:// is accepted"))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(bad("missing host"));
    }
    if authority.contains('@') {
        return Err(bad("credentials in the url are not accepted"));
    }
    if url.contains('?') || url.contains('#') {
        return Err(bad("query and fragment are not accepted"));
    }
    Ok(url.trim_end_matches('/').to_owned())
}

/// Read-only daemon client.
pub struct Daemon {
    url: String,
    client: reqwest::Client,
}

impl Daemon {
    /// `url` is the node base, for example `https://node.zano.org:443`; `/json_rpc` is appended.
    pub fn new(url: &str) -> Result<Self, ZanoError> {
        let base = validate_node_url(url)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| ZanoError::Rpc(e.to_string()))?;
        Ok(Self {
            url: format!("{base}/json_rpc"),
            client,
        })
    }

    pub async fn info(&self) -> Result<NodeInfo, ZanoError> {
        let body = json!({"jsonrpc": "2.0", "id": "0", "method": "getinfo", "params": {"flags": 1_048_575}});
        let text = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ZanoError::Rpc(e.to_string()))?
            .text()
            .await
            .map_err(|e| ZanoError::Rpc(e.to_string()))?;
        parse_info(&text)
    }
}

/// Implementation status of a Zano feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Implemented,
    NotImplemented,
}

#[derive(Debug, Clone, Copy)]
pub struct Capability {
    pub feature: &'static str,
    pub status: Status,
    pub reason: &'static str,
}

const UPSTREAM: &str = "needs the upstream C++ Zarcanum implementation (hyle-team/zano_native_lib); no Rust/WASM port exists and none is invented here";

/// The complete feature list with its real status. A UI must derive any "supported" claim from this, not from the crate's existence.
const fn c(feature: &'static str, status: Status, reason: &'static str) -> Capability {
    Capability {
        feature,
        status,
        reason,
    }
}

pub const fn capabilities() -> [Capability; 15] {
    use Status::{Implemented, NotImplemented};
    [
        c(
            "node info (daemon getinfo)",
            Implemented,
            "read-only JSON-RPC, validated URL",
        ),
        c("wallet creation", NotImplemented, UPSTREAM),
        c("wallet recovery from seed", NotImplemented, UPSTREAM),
        c("address derivation", NotImplemented, UPSTREAM),
        c(
            "balance retrieval",
            NotImplemented,
            "outputs are confidential: needs the view key and the upstream scanner",
        ),
        c(
            "transaction history",
            NotImplemented,
            "same as balance retrieval",
        ),
        c("receive", NotImplemented, "needs address derivation"),
        c(
            "fee estimation",
            NotImplemented,
            "the daemon reports a default fee (see NodeInfo); a per-transaction estimate needs the upstream builder",
        ),
        c("transaction preparation", NotImplemented, UPSTREAM),
        c(
            "exact recipient/amount authorization",
            NotImplemented,
            "authorization must bind to a prepared transaction, which does not exist",
        ),
        c("local signing", NotImplemented, UPSTREAM),
        c(
            "broadcast",
            NotImplemented,
            "nothing to broadcast without signing; no mainnet broadcast is ever enabled",
        ),
        c("confidential assets", NotImplemented, UPSTREAM),
        c(
            "persistent synchronization and cancel/resume",
            NotImplemented,
            "needs the upstream scanner",
        ),
        c(
            "android integration",
            NotImplemented,
            "upstream ships Android libraries (4 ABIs) but they are not linked into this project",
        ),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A real `getinfo` response captured from the public mainnet node (read-only, public chain data).
    const REAL: &str = include_str!("../tests/fixtures/getinfo_mainnet.json");

    #[test]
    fn a_real_node_response_parses() {
        let info = parse_info(REAL).unwrap();
        assert!(info.height > 3_000_000, "{info:?}");
        assert_eq!(info.last_block_hash.len(), 64);
        assert_eq!(info.default_fee, 10_000_000_000);
        assert!(info.is_synchronized());
    }

    #[test]
    fn node_errors_and_implausible_answers_are_refused() {
        assert!(parse_info("not json").is_err());
        assert!(parse_info(r#"{"jsonrpc":"2.0","error":{"code":-1,"message":"x"}}"#).is_err());
        assert!(parse_info(r#"{"result":{"status":"BUSY"}}"#).is_err());
        let zero = REAL.replace("\"height\": 3907848", "\"height\": 0");
        assert!(
            parse_info(&zero).is_err(),
            "a zero-height tip is not believed"
        );
    }

    #[test]
    fn a_lagging_node_is_not_reported_as_synchronized() {
        let mut info = parse_info(REAL).unwrap();
        info.max_net_seen_height = info.height + 500;
        assert!(!info.is_synchronized());
    }

    #[test]
    fn node_urls_are_validated() {
        assert_eq!(
            validate_node_url("https://node.zano.org:443/").unwrap(),
            "https://node.zano.org:443"
        );
        for bad in [
            "ftp://x",
            "node.zano.org",
            "https://",
            "https://user:pw@node.zano.org",
            "https://node.zano.org/?a=b",
            "javascript:alert(1)",
        ] {
            assert!(validate_node_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn nothing_here_can_sign_and_the_capability_report_does_not_overclaim() {
        assert!(!MAINNET.signing_enabled() && !TESTNET.signing_enabled());
        let caps = capabilities();
        let implemented: Vec<_> = caps
            .iter()
            .filter(|c| c.status == Status::Implemented)
            .collect();
        assert_eq!(implemented.len(), 1, "only the node query is implemented");
        assert!(
            caps.iter()
                .any(|c| c.feature == "local signing" && c.status == Status::NotImplemented)
        );
        assert!(caps.iter().all(|c| !c.reason.is_empty()));
    }

    /// Read-only query of the public mainnet node (no funds, no keys, no transaction).
    #[tokio::test]
    #[ignore = "network"]
    async fn the_public_node_answers() {
        let info = Daemon::new("https://node.zano.org:443")
            .unwrap()
            .info()
            .await
            .unwrap();
        println!(
            "zano mainnet height {} synchronized {}",
            info.height,
            info.is_synchronized()
        );
        assert!(info.height > 3_000_000 && info.is_synchronized());
    }
}
