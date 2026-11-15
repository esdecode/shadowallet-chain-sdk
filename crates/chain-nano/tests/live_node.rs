#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Read-only (and one negative signing) checks against a REAL Nano node of any network.
//! NANO_RPC=http://127.0.0.1:17076 NANO_NET=test cargo test -p shadowallet-chain-nano --test live_node -- --ignored --nocapture
//! NANO_NET is one of live | test | beta and must match what the node reports.

use shadowallet_chain_nano::*;

fn rpc() -> NanoRpc {
    NanoRpc::new(&std::env::var("NANO_RPC").unwrap()).unwrap()
}

fn expected() -> NetworkKind {
    match std::env::var("NANO_NET").unwrap().as_str() {
        "live" => NetworkKind::Live,
        "test" => NetworkKind::Test,
        "beta" => NetworkKind::Beta,
        "dev" => NetworkKind::Dev,
        other => panic!("bad NANO_NET {other}"),
    }
}

#[tokio::test]
#[ignore = "needs a node"]
async fn identity_thresholds_and_read_only_account_state() {
    let r = rpc();
    let net = r.network_any().await.unwrap();
    assert_eq!(
        net.kind,
        expected(),
        "node serves {} / {}",
        net.name,
        net.network_identifier
    );
    assert_eq!(net.can_sign(), expected() != NetworkKind::Live);
    // Signing identity: refused for the live network, accepted for pinned test/beta.
    assert_eq!(r.network().await.is_ok(), expected() != NetworkKind::Live);
    let t = r.thresholds().await.unwrap();
    println!(
        "{} thresholds send={:016x} receive={:016x}",
        net.name, t.send.0, t.receive.0
    );
    // A fresh derived account is unopened on every network.
    let seed = Seed::from_hex(&"ab".repeat(32)).unwrap();
    let account = public_key(&derive_private_key(&seed, 0));
    let state = r.account_state(&account).await.unwrap();
    assert!(!state.exists);
    assert!(r.receivable(&account, 1).await.unwrap().is_empty());
    assert!(r.history(&account, 5).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "needs the live network"]
async fn live_genesis_account_is_readable_but_never_signable() {
    let r = rpc();
    let genesis =
        decode_address("nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3")
            .unwrap();
    let state = r.account_state(&genesis).await.unwrap();
    println!(
        "live genesis account exists={} height={} balance={}",
        state.exists, state.height, state.balance
    );
    assert!(state.exists);
    let history = r.history(&genesis, 3).await.unwrap();
    assert!(!history.is_empty());
    // Even a perfectly valid block cannot be submitted for the live network.
    let live = NanoNet::identify("live", LIVE_NETWORK_ID).unwrap();
    let seed = Seed::from_hex(&"cd".repeat(32)).unwrap();
    let key = derive_private_key(&seed, 0);
    let account = public_key(&key);
    let prepared = prepare_receive(
        &AccountState::default(),
        account,
        account,
        &Receivable {
            hash: [9; 32],
            amount: 1,
            source: None,
        },
    )
    .unwrap();
    assert!(r.submit(&live, &prepared, &key, 1).await.is_err());
}

#[tokio::test]
#[ignore = "needs a test or beta node"]
async fn node_rejects_an_unfunded_open_block_for_a_missing_source_not_for_bad_format() {
    let r = rpc();
    let net = r.network().await.unwrap();
    let seed = Seed::from_hex(&"ef".repeat(32)).unwrap();
    let key = derive_private_key(&seed, 0);
    let account = public_key(&key);
    let prepared = prepare_receive(
        &AccountState::default(),
        account,
        account,
        &Receivable {
            hash: [7; 32],
            amount: 1,
            source: None,
        },
    )
    .unwrap();
    let err = r
        .submit(&net, &prepared, &key, 8)
        .await
        .unwrap_err()
        .to_string();
    println!("node answer: {err}");
    // A correctly formed, correctly signed, work-valid block fails only because its source block does not exist.
    assert!(
        err.contains("Gap source") || err.contains("Gap"),
        "unexpected rejection: {err}"
    );
}
