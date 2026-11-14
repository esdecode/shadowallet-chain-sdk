//! Read-only checks against the public Nile testnet. Ignored by default (needs the internet):
//! `cargo test -p shadowallet-chain-tron --test nile_live -- --ignored --test-threads=1`
//! Nothing here signs or spends: the only broadcast is a transaction from an unfunded random key,
//! which the node must refuse (this proves the `broadcasthex` request shape and the rejection path).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};
use shadowallet_chain_tron::*;

const NILE_URL: &str = "https://nile.trongrid.io";
const NILE_USDT: &str = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf";

async fn post(path: &str, body: Value) -> Value {
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    reqwest::Client::new()
        .post(format!("{NILE_URL}{path}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "network"]
async fn identity_is_enforced() {
    TronProvider::connect(NILE, NILE_URL).await.unwrap();
    // a Nile node must be refused when the wallet expects another network
    let err = TronProvider::connect(MAINNET, NILE_URL)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, TronError::Network(_)), "{err}");
}

#[tokio::test]
#[ignore = "network"]
async fn nile_usdt_is_verified_and_a_lookalike_is_not() {
    let p = TronProvider::connect(NILE, NILE_URL).await.unwrap();
    let probe = TronAddress::from_evm_bytes(&[0x22; 20]);
    let meta = p
        .token_meta(&TronAddress::parse(NILE_USDT).unwrap(), &probe)
        .await
        .unwrap();
    assert_eq!(
        (meta.symbol.as_str(), meta.decimals, meta.trust.clone()),
        ("USDT", 6, TokenTrust::Verified)
    );
    // a plain account is not a token contract
    assert!(p.token_meta(&probe, &probe).await.is_err());
}

/// The locally built protobuf must equal what the node itself builds for the same inputs.
#[tokio::test]
#[ignore = "network"]
async fn local_encoding_equals_the_nodes_encoding() {
    let now = post("/wallet/getnowblock", json!({})).await;
    let witness = now["block_header"]["raw_data"]["witness_address"]
        .as_str()
        .unwrap()
        .to_owned();
    let owner = TronAddress::parse(&witness).unwrap();
    let to = TronAddress::from_evm_bytes(&[0x11; 20]);

    let tx = post(
        "/wallet/createtransaction",
        json!({"owner_address": witness, "to_address": hex::encode(to.0), "amount": 1_234_567}),
    )
    .await;
    let node_raw = hex::decode(tx["raw_data_hex"].as_str().unwrap()).unwrap();
    let d = describe_raw_data(&node_raw).unwrap();
    assert_eq!(
        (d.owner.clone(), d.to.clone(), d.amount_sun),
        (owner.0.to_vec(), to.0.to_vec(), 1_234_567)
    );
    let mine = rebuild(
        &node_raw,
        &d,
        owner,
        Action::Trx {
            to,
            amount_sun: 1_234_567,
        },
        0,
    );
    assert_eq!(
        mine.raw_data().unwrap(),
        node_raw,
        "TRX transfer encoding differs from the node's"
    );
    assert_eq!(
        hex::encode(mine.txid().unwrap()),
        tx["txID"].as_str().unwrap()
    );

    let usdt = TronAddress::parse(NILE_USDT).unwrap();
    let word = amount_word("1500000").unwrap();
    let call = post(
        "/wallet/triggersmartcontract",
        json!({"owner_address": witness, "contract_address": hex::encode(usdt.0),
               "function_selector": "transfer(address,uint256)",
               "parameter": hex::encode(&trc20_transfer_data(&to, &word)[4..]),
               "fee_limit": 30_000_000, "call_value": 0}),
    )
    .await;
    let node_raw = hex::decode(call["transaction"]["raw_data_hex"].as_str().unwrap()).unwrap();
    let d = describe_raw_data(&node_raw).unwrap();
    let mine = rebuild(
        &node_raw,
        &d,
        owner,
        Action::Trc20 {
            contract: usdt,
            to,
            amount: word,
        },
        30_000_000,
    );
    assert_eq!(
        mine.raw_data().unwrap(),
        node_raw,
        "TRC-20 transfer encoding differs from the node's"
    );
    assert_eq!(
        hex::encode(mine.txid().unwrap()),
        call["transaction"]["txID"].as_str().unwrap()
    );
}

/// Take the reference block, timestamp and expiration the node chose and rebuild the transaction.
fn rebuild(
    node_raw: &[u8],
    d: &DecodedTransaction,
    owner: TronAddress,
    action: Action,
    fee_limit: u64,
) -> UnsignedTronTransaction {
    // field 1 (2 bytes) and field 4 (8 bytes) are the first two entries of raw_data
    assert_eq!(node_raw[0], 0x0a);
    assert_eq!(node_raw[1], 2);
    let ref_bytes = &node_raw[2..4];
    assert_eq!(node_raw[4], 0x22);
    assert_eq!(node_raw[5], 8);
    let ref_hash = &node_raw[6..14];
    let mut id = [0u8; 32];
    id[6..8].copy_from_slice(ref_bytes);
    id[8..16].copy_from_slice(ref_hash);
    UnsignedTronTransaction {
        owner,
        action,
        block: BlockRef {
            number: 0,
            block_id: id,
        },
        timestamp_ms: d.timestamp_ms,
        expiration_ms: d.expiration_ms,
        fee_limit_sun: fee_limit,
    }
}

/// Fees, resources and the unfunded-account path against the live node.
#[tokio::test]
#[ignore = "network"]
async fn chain_state_reads_and_unfunded_broadcast_is_rejected() {
    let p = TronProvider::connect(NILE, NILE_URL).await.unwrap();
    let params = p.chain_params().await.unwrap();
    assert!(
        params.bandwidth_fee_sun > 0 && params.energy_fee_sun > 0 && params.new_account_fee_sun > 0
    );
    let now = p.now_block().await.unwrap();
    assert!(now.block.number > 1_000_000);

    // a random key that has never received anything
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut key = [0x42u8; 32];
    key[..16].copy_from_slice(&nanos.to_be_bytes());
    let acct = TronAccount::from_private_key(&key).unwrap();
    assert_eq!(p.balance_sun(&acct.address).await.unwrap(), None);
    let to = TronAddress::from_evm_bytes(&[0x11; 20]);
    let unsigned = UnsignedTronTransaction {
        owner: acct.address,
        action: Action::Trx { to, amount_sun: 1 },
        block: now.block,
        timestamp_ms: now.timestamp_ms,
        expiration_ms: now.timestamp_ms + EXPIRATION_MS,
        fee_limit_sun: 0,
    };
    // preparing fails closed before anything is signed
    assert!(prepare_trx_transfer(&p, acct.address, to, 1).await.is_err());
    let sig = acct.sign_txid(unsigned.txid().unwrap());
    assert_eq!(
        recover_signer(unsigned.txid().unwrap(), &sig).unwrap(),
        acct.address
    );
    let raw = unsigned.finalize(&sig).unwrap();
    match p.broadcast_hex(&raw).await {
        Err(TronError::Rejected(m)) => eprintln!("node refused as expected: {m}"),
        other => panic!("expected a definitive rejection, got {other:?}"),
    }
}
