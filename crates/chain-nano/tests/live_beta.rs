#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Read-only checks against a real Nano node on the public beta network.
//! Run with: NANO_BETA_RPC=http://127.0.0.1:55000 cargo test -p shadowallet-chain-nano --test live_beta -- --ignored --nocapture

use shadowallet_chain_nano::*;

fn rpc() -> NanoRpc {
    NanoRpc::new(&std::env::var("NANO_BETA_RPC").expect("set NANO_BETA_RPC")).unwrap()
}

#[tokio::test]
#[ignore = "needs a beta node"]
async fn beta_identity_thresholds_and_empty_account() {
    let r = rpc();
    let net = r.network().await.expect("beta identity must be pinned");
    assert_eq!(net.name, "beta");
    let t = r.thresholds().await.unwrap();
    println!(
        "beta thresholds send={:016x} receive={:016x}",
        t.send.0, t.receive.0
    );
    let seed = Seed::from_hex(&"ab".repeat(32)).unwrap();
    let account = public_key(&derive_private_key(&seed, 0));
    let state = r.account_state(&account).await.unwrap();
    assert!(!state.exists);
    assert!(r.receivable(&account, 1).await.unwrap().is_empty());
    assert!(r.history(&account, 5).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "needs a beta node"]
async fn live_network_identity_is_never_accepted() {
    assert!(NanoNet::verify("live", LIVE_NETWORK_ID).is_err());
}
