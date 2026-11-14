//! Prints the stagenet primary address of the BIP-39 seed (hex) read from stdin. Used by the E2E tooling so the
//! recovery phrase never appears on a command line or in a log.
use std::io::Read;

use shadowallet_chain_monero::{MoneroAccount, Network};

fn main() {
    let mut hex_seed = String::new();
    std::io::stdin().read_to_string(&mut hex_seed).expect("stdin");
    let seed = hex::decode(hex_seed.trim()).expect("hex seed");
    let acct = MoneroAccount::from_seed(Network::Stagenet, &seed, 0).expect("derive");
    println!("{}", acct.primary_address());
}
