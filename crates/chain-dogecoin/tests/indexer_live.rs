#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Read-only checks of the indexer backend against the REAL public services (SoChain `DOGETEST` and the Tatum
//! Dogecoin testnet RPC gateway). Nothing is signed or broadcast and no funds are needed. The RPC free tier
//! allows 5 calls a minute, so this test takes a few minutes.
//!
//!   cargo test -p shadowallet-chain-dogecoin --test indexer_live -- --ignored --nocapture

use std::str::FromStr;

use doge::dogecoin::Address;
use shadowallet_chain_dogecoin::indexer::{Indexer, IndexerConfig};

#[test]
#[ignore = "needs internet access to the public Dogecoin testnet services"]
fn real_services_agree_and_a_real_utxo_verifies() {
    let ix = Indexer::new(IndexerConfig::public_testnet()).unwrap();
    ix.ensure_identity()
        .expect("both services are the Dogecoin testnet and agree on a recent block");
    let (tip, hash) = ix.tip().unwrap();
    println!("tip {tip} {hash}");
    assert!(tip > 1_000_000);

    // Public testnet addresses that received block rewards (public data, not ours).
    let parse = |a: &str| {
        Address::from_str(a)
            .unwrap()
            .assume_checked()
            .script_pubkey()
    };
    // One holds hundreds of outputs: a possibly truncated answer must be refused, never understated.
    let big = "nUT9KLwkq1EmR64AS23nogoD8vGfafSxaP";
    match ix.unspent(big, &parse(big), tip) {
        Ok(all) => println!("big address -> {} outputs, every page validated", all.len()),
        Err(e) => {
            let msg = e.to_string();
            println!("big address -> {msg}");
            assert!(msg.contains("incomplete"), "{msg}");
        }
    }

    let small = "nmJAjmUzuyhR6hMMkmVZQj9D6VApP2pcwK";
    let all = ix
        .unspent(small, &parse(small), tip)
        .expect("every page validated against its raw transaction");
    println!("small address: {} outputs", all.len());
    assert!(!all.is_empty());
    let utxos = ix
        .verified_utxos(&[(small.to_owned(), parse(small))], tip)
        .expect("verified against the second service");
    println!("verified spendable UTXOs: {}", utxos.len());
    assert!(utxos.len() <= 10);
    let probe = all[0].txid;

    let (rate, source) = ix.fee_rate();
    println!("fee {rate} sat/vB from {source}");
    assert!(rate >= 1);

    let (status, block) = ix.transaction_status(&probe.to_string()).unwrap();
    println!("status {status:?} in {block:?}");
    assert!(status.confirmations >= 1);

    let unknown = format!("{:064x}", 12345);
    let msg = ix.transaction_status(&unknown).unwrap_err().to_string();
    println!("unknown tx -> {msg}");
    assert!(msg.contains("code: -5"), "{msg}");
}
