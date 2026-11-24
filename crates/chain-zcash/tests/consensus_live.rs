//! Does the consensus the SDK assumes equal the consensus the live networks run? READ ONLY, ignored (internet needed):
//! `cargo test -p shadowallet-chain-zcash --test consensus_live -- --ignored --nocapture --test-threads=1`
//!
//! For each network the lightwalletd server reports its tip height and the consensus branch ID of the NEXT block. The SDK
//! (librustzcash) derives the branch ID from the height with its compiled-in activation heights. They must be equal: a
//! transaction signed with the wrong branch ID is rejected by every node. The test prints the active upgrades so the
//! release record states what is known, not assumed. Nothing is signed or sent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_zcash::*;
use zcash_client_backend::proto::service::Empty;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters};

const UPGRADES: [(NetworkUpgrade, &str); 7] = [
    (NetworkUpgrade::Sapling, "Sapling"),
    (NetworkUpgrade::Canopy, "Canopy"),
    (NetworkUpgrade::Nu5, "NU5 (Orchard)"),
    (NetworkUpgrade::Nu6, "NU6"),
    (NetworkUpgrade::Nu6_1, "NU6.1"),
    (NetworkUpgrade::Nu6_2, "NU6.2"),
    (NetworkUpgrade::Nu6_3, "NU6.3"),
];

async fn check(net: ZcashNet, server: &str) {
    let (mut client, _) = connect(net, server).await.unwrap();
    let info = client.get_lightd_info(Empty {}).await.unwrap().into_inner();
    let tip = u32::try_from(info.block_height).unwrap();
    // the server's branch ID applies to the block AFTER its tip
    let next = BlockHeight::from_u32(tip + 1);
    let params = net.params();
    let ours = BranchId::for_height(&params, next);
    let theirs =
        u32::from_str_radix(info.consensus_branch_id.trim_start_matches("0x"), 16).unwrap();
    println!("== {} via {server}", net.name);
    println!(
        "   tip {tip}, server software {} {}",
        info.vendor, info.version
    );
    println!(
        "   server consensus branch id {:08x}; SDK derives {:08x} ({ours:?})",
        theirs,
        u32::from(ours)
    );
    for (nu, name) in UPGRADES {
        let at = params.activation_height(nu).map(u32::from);
        println!(
            "   {name:<14} activation {at:?}  active at next block: {}",
            params.is_nu_active(nu, next)
        );
    }
    assert_eq!(
        theirs,
        u32::from(ours),
        "{}: the SDK's compiled-in consensus rules differ from the live network's (branch id)",
        net.name
    );
}

#[tokio::test]
#[ignore = "network"]
async fn the_sdk_consensus_rules_equal_the_live_testnet() {
    check(TESTNET, "https://testnet.zec.rocks:443").await;
}

#[tokio::test]
#[ignore = "network"]
async fn the_sdk_consensus_rules_equal_the_live_mainnet() {
    check(MAINNET, "https://zec.rocks:443").await;
}
