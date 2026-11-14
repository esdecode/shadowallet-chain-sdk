//! Read-only checks against a public Monero stagenet node. Ignored by default (internet needed):
//! `cargo test -p shadowallet-chain-monero --test stagenet_live -- --ignored --nocapture --test-threads=1`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_monero::*;

const NODE: &str = "http://node.sethforprivacy.com:38089";
const NODE2: &str = "http://stagenet.xmr-tw.org:38081";

fn account() -> MoneroAccount {
    let m = bip39::Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    MoneroAccount::from_seed(Network::Stagenet, &m.to_seed(""), 0).unwrap()
}

#[tokio::test]
#[ignore = "network"]
async fn identity_is_enforced() {
    connect(STAGENET, NODE).await.unwrap();
    let err = connect(MAINNET, NODE).await.err().unwrap();
    assert!(matches!(err, MoneroError::Network(_)), "{err}");
    assert!(connect(TESTNET, NODE2).await.is_err());
}

#[tokio::test]
#[ignore = "network"]
async fn scans_real_stagenet_blocks_and_survives_restart() {
    let node = connect(STAGENET, NODE).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.db");
    let acct = account();
    let store = MoneroStore::open(&path).unwrap();
    let tip = {
        use monero_wallet::interface::ProvidesBlockchainMeta;
        node.daemon.latest_block_number().await.unwrap() as u64
    };
    let restore = tip - 40;
    store.register_account("monero-stagenet", &acct.primary_address().to_string(), restore).unwrap();
    let r = sync(&store, &acct, &node, 100).await.unwrap();
    println!("sync {r:?}");
    assert_eq!(r.from, restore);
    assert!(r.to >= tip - 1, "scanned up to the tip");
    assert_eq!(r.new_outputs, 0, "a throwaway wallet owns nothing");
    assert_eq!(balance(&store).unwrap(), Balance::default());
    // checkpoint persisted: reopening continues, does not restart
    drop(store);
    let store = MoneroStore::open(&path).unwrap();
    let r2 = sync(&store, &acct, &node, 100).await.unwrap();
    assert!(r2.from > r.to - 5, "resumed from the checkpoint, got {r2:?}");
    assert_eq!(r2.reorg_depth, 0);
}

#[tokio::test]
#[ignore = "network"]
async fn unfunded_send_fails_closed_and_mainnet_never_signs() {
    let node = connect(STAGENET, NODE).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let acct = account();
    let store = MoneroStore::open(&dir.path().join("x.db")).unwrap();
    store.register_account("monero-stagenet", &acct.primary_address().to_string(), 1).unwrap();
    let to = acct.address_at(1).to_string();
    let err = prepare_send(&store, &acct, &node, &to, 1_000_000_000, FeePriority::Normal).await.err().unwrap();
    assert!(err.to_string().contains("insufficient"), "{err}");
    // a mainnet node handle is refused before any key is touched
    let main_node = Node { net: MAINNET, daemon: node.daemon };
    let err = prepare_send(&store, &acct, &main_node, &to, 1, FeePriority::Normal).await.err().unwrap();
    assert!(err.to_string().contains("mainnet signing is disabled"), "{err}");
}
