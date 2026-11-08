#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Full BCH watch-only engine E2E against Bitcoin Cash Node regtest.

use std::env;
use std::path::PathBuf;

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::json;
use shadowallet_chain_bitcoin_cash::engine::BchEngine;
use shadowallet_chain_bitcoin_cash::{BchAccount, BchNetwork, finalize_transfer, signing_request};

fn rpc() -> Client {
    let base = env::var("BCH_RPC_URL").expect("BCH_RPC_URL must point at BCHN regtest");
    let url = format!("{base}/wallet/uw-bch");
    let user = env::var("RPC_USER").unwrap_or_else(|_| "uw".to_owned());
    let pass = env::var("RPC_PASS").unwrap_or_else(|_| "uw".to_owned());
    Client::new(&url, Auth::UserPass(user, pass)).expect("rpc client")
}

fn rpc_url() -> String {
    format!(
        "{}/wallet/uw-bch",
        env::var("BCH_RPC_URL").expect("BCH_RPC_URL")
    )
}

fn temp_db(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = env::temp_dir().join(format!("bch-engine-{tag}-{nanos}.sqlite"));
    let _ = std::fs::remove_file(&path);
    path
}

fn mine(rpc: &Client, address: &str, blocks: u64) {
    rpc.call::<serde_json::Value>("generatetoaddress", &[json!(blocks), json!(address)])
        .expect("mine");
}

#[test]
#[ignore = "requires Bitcoin Cash Node regtest"]
fn bch_engine_end_to_end() {
    let base = env::var("BCH_RPC_URL").unwrap();
    let user = env::var("RPC_USER").unwrap_or_else(|_| "uw".to_owned());
    let pass = env::var("RPC_PASS").unwrap_or_else(|_| "uw".to_owned());
    let base_rpc = Client::new(&base, Auth::UserPass(user, pass)).expect("base rpc");
    let _ = base_rpc.call::<serde_json::Value>("createwallet", &[json!("uw-bch")]);
    let rpc = rpc();
    let node_address: String = rpc.call("getnewaddress", &[]).expect("node address");
    mine(&rpc, &node_address, 101);

    let seed = [0x77u8; 32];
    let account = BchAccount::from_seed(BchNetwork::Regtest, &seed).expect("account");
    let xpub = account.account_xpub().to_string();
    let db = temp_db("main");
    let mut engine = BchEngine::open(
        BchNetwork::Regtest,
        &xpub,
        account.fingerprint_raw,
        &rpc_url(),
        "uw",
        "uw",
        &db,
        20,
    )
    .expect("open engine");

    let receive = engine.next_receive_address().expect("receive");
    rpc.call::<String>("sendtoaddress", &[json!(receive.encode()), json!(1.0)])
        .expect("fund");
    mine(&rpc, &node_address, 1);

    let report = engine.sync().expect("sync");
    assert!(report.tip_height >= 102);
    assert_eq!(engine.balance().confirmed_sats, 100_000_000);
    assert!(!engine.history().is_empty());

    let destination = account.address(0, 9).expect("destination").encode();
    let unsigned = engine
        .prepare_transfer(&destination, 50_000_000, 1)
        .expect("prepare");
    let request = signing_request(&engine_account(&seed), &unsigned).expect("request");
    let mut signatures = Vec::new();
    for (index, utxo) in unsigned.selected.iter().enumerate() {
        let digest: [u8; 32] = hex_decode(&request.digests[index]).try_into().unwrap();
        signatures.push(
            account
                .sign_digest(utxo.keychain, utxo.index, digest)
                .expect("sign"),
        );
    }
    let signed =
        finalize_transfer(&engine_account(&seed), &unsigned, &signatures).expect("finalize");
    let signed_hex = hex_encode(&shadowallet_chain_bitcoin_cash::serialize_transaction(
        &signed,
    ));
    let accepted: String = rpc
        .call("sendrawtransaction", &[json!(signed_hex)])
        .expect("BCHN accept");
    assert_eq!(accepted, signed.compute_txid().to_string());

    mine(&rpc, &node_address, 1);
    engine.sync().expect("resync");
    assert!(engine.balance().confirmed_sats < 100_000_000);

    drop(engine);
    let mut reopened = BchEngine::open(
        BchNetwork::Regtest,
        &xpub,
        account.fingerprint_raw,
        &rpc_url(),
        "uw",
        "uw",
        &db,
        20,
    )
    .expect("reopen");
    reopened.sync().expect("resync restart");
    assert!(!reopened.history().is_empty());

    let fresh = temp_db("restore");
    let mut restored = BchEngine::open(
        BchNetwork::Regtest,
        &xpub,
        account.fingerprint_raw,
        &rpc_url(),
        "uw",
        "uw",
        &fresh,
        20,
    )
    .expect("restore");
    restored.rescan().expect("rescan");
    restored.sync().expect("sync restore");
    assert!(restored.balance().confirmed_sats > 0);

    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(&fresh);
}

fn engine_account(seed: &[u8; 32]) -> BchAccount {
    BchAccount::from_seed(BchNetwork::Regtest, seed).expect("account")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect()
}
