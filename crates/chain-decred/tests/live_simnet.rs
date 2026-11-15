#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End-to-end spend against a REAL dcrd node on a private simnet (not a public network).
//!
//! docker run -d --name dcrdsim --user 0 -p 127.0.0.1:19556:19556 decred/dcrd:release-v2.1.5 --simnet --rpcuser=u \
//!   --rpcpass=p --rpclisten=0.0.0.0:19556 --txindex --miningaddr=<account 0 external 0 address> --nodnsseed --nolisten
//! DCRD_URL=https://localhost:19556 DCRD_CERT=C:\w_dcrd\rpc.cert DCRD_SEED=<64-byte bip39 seed hex> \
//!   cargo test -p shadowallet-chain-decred --test live_simnet -- --ignored --nocapture

use shadowallet_chain_decred::*;

fn rpc() -> DcrdRpc {
    let cert = std::fs::read(std::env::var("DCRD_CERT").unwrap()).unwrap();
    DcrdRpc::new(&std::env::var("DCRD_URL").unwrap(), "u", "p", Some(&cert)).unwrap()
}

async fn generate(blocks: u32) {
    let r = rpc().raw("generate", serde_json::json!([blocks])).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test]
#[ignore = "needs a dcrd simnet node"]
async fn simnet_spend_confirm_and_double_spend_refused() {
    let seed = hex::decode(std::env::var("DCRD_SEED").unwrap()).unwrap();
    let rpc = rpc();
    // Identity: simnet verifies; testnet and mainnet claims about this node are refused.
    let net = rpc.verify_network(SIMNET).await.unwrap();
    assert!(rpc.verify_network(TESTNET).await.is_err());
    assert!(
        rpc.verify_network(shadowallet_chain_decred::NETS[0])
            .await
            .is_err()
    );

    let sender = Account::from_seed(&seed, SIMNET, 0).unwrap();
    let recipient = Account::from_seed(&seed, SIMNET, 1).unwrap();
    generate(20).await; // coinbases of the early blocks mature after 16 confirmations
    let before = scan(&rpc, &sender, 1).await.unwrap();
    assert!(before.spendable() > 0, "mature coinbase must be spendable");
    println!(
        "sender spendable={} immature={} tip={}",
        before.spendable(),
        before.immature(),
        before.tip
    );

    let to = recipient.address(0, 0).unwrap();
    let amount = 150_000_000;
    let prepared = prepare_send(&before, &sender, &to, amount, DEFAULT_FEE_RATE).unwrap();
    println!(
        "review: to={} amount={} fee={} change={:?} inputs={}",
        prepared.to,
        prepared.amount,
        prepared.fee,
        prepared.change,
        prepared.inputs.len()
    );
    assert!(
        prepared.fee >= 1_000 && prepared.fee < 100_000,
        "fee at 10000 atoms/kB for a small tx"
    );
    let again = prepared.clone();
    let txid = sign_and_broadcast(&rpc, &net, &sender, prepared)
        .await
        .unwrap();
    println!("broadcast {txid}");

    // Pending in the mempool for both sides.
    let r0 = scan(&rpc, &recipient, 1).await.unwrap();
    assert_eq!(r0.pending(), amount);
    assert_eq!(r0.spendable(), 0);
    // The CPU miner may build a block from a template made before the transaction arrived: mine until it is included.
    let mut r1 = r0;
    for _ in 0..5 {
        generate(1).await;
        r1 = scan(&rpc, &recipient, 1).await.unwrap();
        if r1.spendable() == amount {
            break;
        }
    }
    assert_eq!(
        r1.spendable(),
        amount,
        "recipient sees the confirmed payment"
    );
    let s1 = scan(&rpc, &sender, 1).await.unwrap();
    let row = s1
        .history
        .iter()
        .find(|h| h.txid == txid)
        .expect("sender history has the spend");
    assert!(row.height.is_some() && row.confirmations >= 1);
    // delta = received (change) - spent (inputs) = -(amount + fee)
    assert_eq!(row.delta, -(amount + again.fee));
    assert_eq!(row.fee, Some(again.fee));
    assert_eq!(r1.history[0].delta, amount);

    // Replaying the identical reviewed transaction cannot spend the same outputs twice.
    assert!(
        sign_and_broadcast(&rpc, &net, &sender, again)
            .await
            .is_err(),
        "double spend must be rejected by dcrd"
    );

    // The recipient can spend what it received (change-less path and recipient-derived keys).
    let back = sender.address(0, 1).unwrap();
    generate(1).await;
    let r2 = scan(&rpc, &recipient, 1).await.unwrap();
    let p2 = prepare_send(&r2, &recipient, &back, 100_000_000, DEFAULT_FEE_RATE).unwrap();
    let txid2 = sign_and_broadcast(&rpc, &net, &recipient, p2)
        .await
        .unwrap();
    generate(1).await;
    let s2 = scan(&rpc, &sender, 1).await.unwrap();
    assert!(
        s2.history
            .iter()
            .any(|h| h.txid == txid2 && h.delta == 100_000_000)
    );
    println!("round trip ok {txid2}");

    // Below dust, malformed address, wrong-network address.
    assert!(prepare_send(&s2, &sender, &to, 100, DEFAULT_FEE_RATE).is_err());
    assert!(prepare_send(&s2, &sender, "TsnotAnAddress", 10_000_000, DEFAULT_FEE_RATE).is_err());
    let testnet_addr = Account::from_seed(&seed, TESTNET, 0)
        .unwrap()
        .address(0, 0)
        .unwrap();
    assert!(prepare_send(&s2, &sender, &testnet_addr, 10_000_000, DEFAULT_FEE_RATE).is_err());
}
