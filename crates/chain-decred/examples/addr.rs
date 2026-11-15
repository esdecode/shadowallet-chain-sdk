//! Prints the first receive/change addresses of a BIP-39 seed given as a hex string (64 bytes), for local test setup.
//! usage: cargo run -p shadowallet-chain-decred --example addr -- <simnet|testnet> <bip39_seed_hex>

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_decred::{Account, SIMNET, TESTNET};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let net = if args[1] == "simnet" { SIMNET } else { TESTNET };
    let seed = hex::decode(&args[2]).unwrap();
    let account = Account::from_seed(&seed, net, 0).unwrap();
    for (branch, index) in [(0, 0), (0, 1), (1, 0)] {
        println!(
            "{branch}/{index} {}",
            account.address(branch, index).unwrap()
        );
    }
}
