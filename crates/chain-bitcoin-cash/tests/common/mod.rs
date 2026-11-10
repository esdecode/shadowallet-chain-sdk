#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

//! Shared Bitcoin Cash Node regtest helpers.

use std::env;

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::{Value, json};

pub fn base_url() -> String {
    env::var("BCH_RPC_URL").expect("BCH_RPC_URL must point at BCHN regtest")
}

fn auth() -> Auth {
    let user = env::var("RPC_USER").unwrap_or_else(|_| "uw".to_owned());
    let pass = env::var("RPC_PASS").unwrap_or_else(|_| "uw".to_owned());
    Auth::UserPass(user, pass)
}

pub fn wallet_client(name: &str) -> Client {
    Client::new(&format!("{}/wallet/{name}", base_url()), auth()).expect("rpc client")
}

/// Create the wallet if it is missing and load it. Returns a client bound to
/// the wallet, which is required once any wallet is loaded on the node.
pub fn ensure_wallet(name: &str) -> Client {
    let base = Client::new(&base_url(), auth()).expect("rpc client");
    let _ = base.call::<Value>("createwallet", &[json!(name)]);
    let _ = base.call::<Value>("loadwallet", &[json!(name)]);
    let loaded: Vec<String> = base.call("listwallets", &[]).expect("listwallets");
    assert!(
        loaded.iter().any(|wallet| wallet == name),
        "bitcoind wallet {name} is not loaded"
    );
    wallet_client(name)
}

pub fn mine(rpc: &Client, address: &str, blocks: u64) {
    rpc.call::<Value>("generatetoaddress", &[json!(blocks), json!(address)])
        .expect("mine");
}
