//! Where does Monero mainnet scanning time go? Read-only, ignored (internet):
//! `cargo test -p shadowallet-chain-monero --test sync_profile_live -- --ignored --nocapture --test-threads=1`
//!
//! Measures, on the same real mainnet blocks: fetching them from the node (network + parsing), scanning them locally with a
//! view key, and the node round-trip time of one trivial request. Nothing is written, nothing is signed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Instant;

use monero_wallet::{Scanner, interface::ProvidesBlockchainMeta, interface::ProvidesScannableBlocks};
use shadowallet_chain_monero::*;

const NODE: &str = "https://xmr-node.cakewallet.com:18081";

fn account() -> MoneroAccount {
    let m = bip39::Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    MoneroAccount::from_seed(Network::Mainnet, &m.to_seed(""), 0).unwrap()
}

#[tokio::test]
#[ignore = "network"]
async fn where_the_time_goes() {
    let node = connect(MAINNET, NODE, None).await.unwrap();
    let tip = node.daemon.latest_block_number().await.unwrap();
    // round trip of the cheapest request
    let t = Instant::now();
    for _ in 0..5 {
        node.daemon.latest_block_number().await.unwrap();
    }
    println!("RTT latest_block_number: {:?} each", t.elapsed() / 5);

    let acct = account();
    let mut scanner = Scanner::new(acct.view_pair().clone());
    let start = tip - 300;
    for (label, size) in [("1 block", 1usize), ("5 blocks", 5), ("20 blocks", 20), ("40 blocks", 40)] {
        let from = start + (size * 7);
        let t = Instant::now();
        let blocks = node
            .daemon
            .contiguous_scannable_blocks(from..=from + size - 1)
            .await
            .unwrap();
        let fetch = t.elapsed();
        let txs: usize = blocks.iter().map(|b| b.transactions.len()).sum();
        let t2 = Instant::now();
        let mut found = 0;
        for b in blocks {
            found += scanner.scan(b).unwrap().ignore_additional_timelock().len();
        }
        let scan = t2.elapsed();
        println!(
            "{label}: fetch {fetch:?} ({:?} per block, {txs} txs), scan {scan:?} ({:?} per block), outputs found {found}",
            fetch / size as u32,
            scan / size as u32
        );
    }
}
