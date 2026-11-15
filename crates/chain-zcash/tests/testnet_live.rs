//! Read-only checks against a public Zcash testnet lightwalletd. Ignored by default (internet needed):
//! `cargo test -p shadowallet-chain-zcash --test testnet_live -- --ignored --nocapture --test-threads=1`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_zcash::*;

const SERVER: &str = "https://testnet.zec.rocks:443";

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        .unwrap()
        .to_seed("")
        .to_vec()
}

#[tokio::test]
#[ignore = "network"]
async fn identity_is_enforced() {
    let (_c, info) = connect(TESTNET, SERVER).await.unwrap();
    println!("server: {info:?}");
    assert_eq!(info.chain_name, "test");
    let err = connect(MAINNET, SERVER).await.err().unwrap();
    assert!(matches!(err, ZcashError::Network(_)), "{err}");
}

#[tokio::test]
#[ignore = "network"]
async fn creates_a_wallet_syncs_and_survives_a_restart() {
    let (mut client, info) = connect(TESTNET, SERVER).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zec.sqlite");
    let mut w = open_wallet(
        TESTNET,
        &path,
        &seed(),
        0,
        &mut client,
        Some(info.block_height.saturating_sub(10)),
    )
    .await
    .unwrap();
    update_tip(&mut w, &mut client).await.unwrap();
    sync(&mut w, &mut client, 100).await.unwrap();
    let b = balances(&w).unwrap();
    println!("balances {b:?}");
    assert!(b.chain_tip >= info.block_height.saturating_sub(5));
    assert!(
        b.fully_scanned + 50 >= b.chain_tip,
        "scanned to near the tip: {b:?}"
    );
    assert_eq!(
        b.orchard_spendable + b.transparent_spendable + b.sapling_total,
        0,
        "a throwaway wallet owns nothing"
    );
    let addr = current_address(&mut w).unwrap();
    assert!(addr.starts_with("utest1"), "{addr}");
    assert_eq!(
        addr,
        current_address(&mut w).unwrap(),
        "the current address is stable"
    );
    let fresh = new_address(&mut w).unwrap();
    assert_ne!(addr, fresh);
    assert!(transparent_address_of(&w).unwrap().starts_with("tm"));
    assert!(history(&w, 10).unwrap().is_empty());
    drop(w);
    // reopen: the same account, the same address, the checkpoint is kept
    let mut w2 = open_wallet(
        TESTNET,
        &path,
        &seed(),
        0,
        &mut client,
        Some(info.block_height.saturating_sub(10)),
    )
    .await
    .unwrap();
    assert_eq!(
        current_address(&mut w2).unwrap(),
        fresh,
        "the most recently generated address is the current one"
    );
    sync(&mut w2, &mut client, 100).await.unwrap();
    assert!(balances(&w2).unwrap().fully_scanned >= b.fully_scanned);
}
