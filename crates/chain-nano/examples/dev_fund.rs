//! Fund an address on a PRIVATE Nano dev network from the dev genesis account, whose private key is published in
//! nano-node's source (`dev_private_key_data`). Refuses any node that is not a pinned dev network.
//!
//! usage: cargo run -p shadowallet-chain-nano --example dev_fund -- <rpc_url> <destination nano_ address> <amount XNO>

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_nano::*;

const DEV_GENESIS_PRIVATE_KEY: &str =
    "34F0A37AAD20F4A260F0A5B3CB3D7FB50673212263E58A380BC10474BB039CE4";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rpc = NanoRpc::new(&args[1]).unwrap();
    let to = decode_address(&args[2]).unwrap();
    let amount = parse_xno(&args[3]).unwrap();
    let net = rpc.network().await.unwrap();
    assert_eq!(
        net.kind,
        NetworkKind::Dev,
        "refusing: the node is not a private dev network"
    );
    let mut key = [0u8; 32];
    hex::decode_to_slice(DEV_GENESIS_PRIVATE_KEY, &mut key).unwrap();
    let genesis = public_key(&key);
    let state = rpc.account_state(&genesis).await.unwrap();
    let prepared = prepare_send(&state, genesis, to, amount).unwrap();
    let hash = rpc.submit(&net, &prepared, &key, 4).await.unwrap();
    println!(
        "funded {} with {} XNO, block {}",
        args[2],
        args[3],
        hex::encode_upper(hash)
    );
}
