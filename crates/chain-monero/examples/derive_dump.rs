#![allow(clippy::expect_used)]
//! Dumps the keys and addresses of the PUBLIC "abandon x11 about" test mnemonic as JSON so that an independent
//! implementation can be compared (`scripts/verify_monero_derivation.py compare`). Only this public test vector is ever
//! used here; the output contains its (worthless) private keys by design. Never feed a real phrase to this example.

use shadowallet_chain_monero::{MoneroAccount, Network};

fn main() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::Mnemonic::parse(phrase)
        .expect("mnemonic")
        .to_seed("");
    let net = |n: Network| {
        let a = MoneroAccount::from_seed(n, &seed, 0).expect("derive");
        let subs: Vec<String> = (1..=5).map(|i| a.address_at(i).to_string()).collect();
        serde_json::json!({"primary": a.primary_address().to_string(), "subaddresses": subs})
    };
    let main = MoneroAccount::from_seed(Network::Mainnet, &seed, 0).expect("derive");
    let out = serde_json::json!({
        "mainnet": net(Network::Mainnet),
        "stagenet": net(Network::Stagenet),
        "spend_key_hex": main.spend_key_hex().as_str(),
        "view_key_hex": main.view_key_hex().as_str(),
    });
    println!("{out}");
}
