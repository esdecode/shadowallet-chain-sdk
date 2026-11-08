#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Bitcoin Cash Node regtest acceptance test.
//!
//! Run with:
//!   docker run -d --name uw-bch-regtest -p 18443:18443 \
//!     -v "$PWD/infrastructure/docker/bchn.Dockerfile:/tmp/Dockerfile" \
//!     universal-wallet/bchn-regtest:29.2.0 \
//!     -regtest=1 -server=1 -txindex=1 -rpcuser=uw -rpcpassword=uw \
//!     -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 -printtoconsole=0
//!   BCH_RPC_URL=http://127.0.0.1:18443 \
//!     cargo test -p adapter-bitcoin-cash --test bch_regtest -- --ignored

use std::env;

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::{Value, json};
use shadowallet_chain_bitcoin_cash::{
    BchAccount, BchNetwork, Utxo, build_unsigned, sign_transfer, verify_transfer,
};

#[test]
#[ignore = "requires Bitcoin Cash Node regtest"]
fn bch_node_accepts_a_locally_signed_transaction() {
    let url = env::var("BCH_RPC_URL").expect("BCH_RPC_URL must point at BCHN regtest");
    let user = env::var("RPC_USER").unwrap_or_else(|_| "uw".to_owned());
    let pass = env::var("RPC_PASS").unwrap_or_else(|_| "uw".to_owned());
    let rpc = Client::new(&url, Auth::UserPass(user, pass)).expect("rpc client");

    let node_address: String = rpc.call("getnewaddress", &[]).expect("node address");
    rpc.call::<Value>("generatetoaddress", &[json!(101), json!(node_address)])
        .expect("maturity");

    let account = BchAccount::from_seed(BchNetwork::Regtest, &[0x6b; 32]).expect("account");
    let receive = account.address(0, 0).expect("receive address");
    let txid: String = rpc
        .call("sendtoaddress", &[json!(receive.encode()), json!(1.0)])
        .expect("fund");
    rpc.call::<Value>("generatetoaddress", &[json!(1), json!(node_address)])
        .expect("mine funding");

    let raw: String = rpc
        .call("getrawtransaction", &[json!(txid)])
        .expect("raw funding transaction");
    let funding = shadowallet_chain_bitcoin_cash::deserialize_transaction(&hex_decode(&raw))
        .expect("parse funding transaction");
    let script = receive.script_pubkey().expect("script");
    let (vout, output) = funding
        .output
        .iter()
        .enumerate()
        .find(|(_, output)| output.script_pubkey == script)
        .expect("funded output");

    let utxo = Utxo {
        outpoint: bitcoin::OutPoint {
            txid: funding.compute_txid(),
            vout: vout as u32,
        },
        value_sats: output.value.to_sat(),
        keychain: 0,
        index: 0,
    };
    let destination = account.address(0, 1).expect("destination").encode();
    let unsigned =
        build_unsigned(&account, &[utxo], &destination, 50_000_000, 1, 0).expect("build");
    let signed = sign_transfer(&account, &unsigned).expect("sign");
    verify_transfer(&unsigned, &signed).expect("local verify");

    let signed_hex = hex_encode(&shadowallet_chain_bitcoin_cash::serialize_transaction(
        &signed,
    ));
    let accepted: String = rpc
        .call("sendrawtransaction", &[json!(signed_hex)])
        .expect("BCHN must accept the signed transaction");
    assert_eq!(accepted, signed.compute_txid().to_string());

    rpc.call::<Value>("generatetoaddress", &[json!(1), json!(node_address)])
        .expect("mine spend");
    let confirmed = rpc
        .call::<Value>("getrawtransaction", &[json!(accepted), json!(1)])
        .expect("confirmed transaction");
    assert!(confirmed["confirmations"].as_i64().unwrap_or(0) >= 1);
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
