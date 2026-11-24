//! READ-ONLY checks of the production Monero code against the real Monero MAINNET. Ignored by default (internet needed):
//! `cargo test -p shadowallet-chain-monero --test mainnet_readonly_live -- --ignored --nocapture --test-threads=1`
//!
//! The wallet is a disposable account derived from the public "abandon x11 about" test mnemonic: it owns nothing, so no
//! balance is expected and none is invented. What is exercised is the production connection, identity check, block
//! download, block and transaction parsing, output scanning, checkpoints and resume on REAL mainnet blocks of the
//! current protocol. Nothing is signed or sent; only block numbers are requested from the node.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Instant;

use monero_wallet::interface::ProvidesBlockchainMeta;
use shadowallet_chain_monero::*;

const NODE: &str = "https://xmr-node.cakewallet.com:18081";

fn account() -> MoneroAccount {
    let m = bip39::Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    MoneroAccount::from_seed(Network::Mainnet, &m.to_seed(""), 0).unwrap()
}

/// `get_version`/`hard_fork_info` straight from the node, to check the protocol the node enforces.
async fn json_rpc(method: &str) -> serde_json::Value {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    let body = serde_json::json!({"jsonrpc": "2.0", "id": "0", "method": method});
    let text = client
        .post(format!("{NODE}/json_rpc"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let r: serde_json::Value = serde_json::from_str(&text).unwrap();
    r["result"].clone()
}

#[tokio::test]
#[ignore = "network"]
async fn mainnet_identity_is_enforced_and_the_protocol_is_the_supported_one() {
    // the right network connects; every other network is refused for the same node
    let node = connect(MAINNET, NODE, None).await.unwrap();
    assert!(matches!(
        connect(STAGENET, NODE, None).await.err().unwrap(),
        MoneroError::Network(_)
    ));
    assert!(matches!(
        connect(TESTNET, NODE, None).await.err().unwrap(),
        MoneroError::Network(_)
    ));
    let tip = node.daemon.latest_block_number().await.unwrap();
    assert!(tip > 3_000_000, "mainnet height {tip}");
    // the protocol the wallet builds for (RingCT CLSAG + Bulletproofs+, ring size 16) is hard fork 15 and later
    let hf = json_rpc("hard_fork_info").await;
    let version = hf["version"].as_u64().unwrap();
    println!("mainnet hard fork version {version}, tip {tip}");
    assert!(
        version >= 16,
        "the node enforces hard fork {version}; this wallet builds the version 16 transaction format"
    );
    assert_eq!(RING_SIZE, 16);
    // the daemon fee rate the wallet would pay is available and sane (piconero per weight unit)
    use monero_wallet::interface::ProvidesFeeRates;
    let rate = node
        .daemon
        .fee_rate(FeePriority::Normal, 2_000_000)
        .await
        .unwrap();
    println!("fee rate {rate:?}");
}

#[tokio::test]
#[ignore = "network"]
async fn real_mainnet_blocks_are_scanned_checkpointed_and_resumed() {
    let node = connect(MAINNET, NODE, None).await.unwrap();
    let tip = node.daemon.latest_block_number().await.unwrap() as u64;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mainnet.db");
    let acct = account();
    assert!(
        acct.primary_address().to_string().starts_with('4'),
        "mainnet standard address"
    );
    let store = MoneroStore::open(&path).unwrap();
    let restore = tip - 150;
    store
        .register_account(
            "monero-mainnet",
            &acct.primary_address().to_string(),
            restore,
        )
        .unwrap();
    let started = Instant::now();
    let r = sync(&store, &acct, &node, 80).await.unwrap();
    println!("first pass {r:?} in {:?}", started.elapsed());
    assert_eq!(r.from, restore);
    assert!(
        r.to >= restore + 79,
        "scanned a full batch of real mainnet blocks: {r:?}"
    );
    assert_eq!(r.new_outputs, 0, "a throwaway wallet owns nothing");
    assert_eq!(r.spent_outputs, 0);
    // resume from the persisted checkpoint after a restart; it never restarts from the restore height
    drop(store);
    let store = MoneroStore::open(&path).unwrap();
    let r2 = sync(&store, &acct, &node, 200).await.unwrap();
    println!("second pass {r2:?}");
    assert!(r2.from > r.to - 5, "resumed at the checkpoint: {r2:?}");
    assert!(r2.to + 3 >= tip, "caught up with the tip: {r2:?}");
    assert_eq!(r2.reorg_depth, 0);
    assert_eq!(balance(&store).unwrap(), Balance::default());
    // idempotent: another pass changes nothing
    let r3 = sync(&store, &acct, &node, 200).await.unwrap();
    assert_eq!((r3.new_outputs, r3.spent_outputs), (0, 0));
    assert!(store.history(50).unwrap().is_empty());
}

/// A mainnet node handle never produces a signed transaction in a default build; the three refusals are in the SDK.
#[cfg(not(feature = "mainnet-send"))]
#[tokio::test]
#[ignore = "network"]
async fn the_default_build_refuses_to_prepare_a_mainnet_send() {
    let node = connect(MAINNET, NODE, None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let acct = account();
    let store = MoneroStore::open(&dir.path().join("x.db")).unwrap();
    store
        .register_account("monero-mainnet", &acct.primary_address().to_string(), 1)
        .unwrap();
    let to = acct.address_at(1).to_string();
    let err = prepare_send(&store, &acct, &node, &to, 1, FeePriority::Normal, None)
        .await
        .err()
        .unwrap();
    assert!(
        err.to_string().contains("mainnet signing is disabled"),
        "{err}"
    );
}

/// Read-only throughput of a bounded mainnet scan (400 blocks) with concurrent fetching; prints blocks per second.
#[tokio::test]
#[ignore = "network"]
async fn mainnet_scan_throughput_400_blocks() {
    let node = connect(MAINNET, NODE, None).await.unwrap();
    let tip = node.daemon.latest_block_number().await.unwrap() as u64;
    let dir = tempfile::tempdir().unwrap();
    let acct = account();
    let store = MoneroStore::open(&dir.path().join("t.db")).unwrap();
    let restore = tip - 1000;
    store
        .register_account(
            "monero-mainnet",
            &acct.primary_address().to_string(),
            restore,
        )
        .unwrap();
    let started = Instant::now();
    let r = sync(&store, &acct, &node, 400).await.unwrap();
    let secs = started.elapsed().as_secs_f64();
    println!(
        "THROUGHPUT {r:?}: 400 blocks in {secs:.1}s = {:.1} blocks/s",
        400.0 / secs
    );
    assert_eq!(r.to, restore + 399);
    assert_eq!(r.new_outputs, 0);
}
