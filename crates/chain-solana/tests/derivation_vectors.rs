#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Derivation vectors produced by an independent implementation
//! (Python `hmac`/`hashlib` SLIP-0010 + `cryptography` Ed25519) for the
//! standard BIP-39 test mnemonic and passphrase "". The first address is also
//! the widely published Phantom/Solflare address for this mnemonic.

use shadowallet_chain_solana::{Pubkey, SolanaAccount};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn matches_independent_derivation() {
    let seed = bip39::Mnemonic::parse(MNEMONIC).unwrap().to_seed("");
    for (index, expected) in [
        (0u32, "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"),
        (1, "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb"),
        (2, "7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm"),
    ] {
        let account = SolanaAccount::from_seed(&seed, index).unwrap();
        assert_eq!(account.address(), expected, "account {index}");
        assert_eq!(Pubkey::from_base58(expected).unwrap(), account.public());
    }
}

#[test]
fn passphrase_changes_the_account() {
    let a = bip39::Mnemonic::parse(MNEMONIC).unwrap().to_seed("");
    let b = bip39::Mnemonic::parse(MNEMONIC).unwrap().to_seed("x");
    assert_ne!(
        SolanaAccount::from_seed(&a, 0).unwrap().public(),
        SolanaAccount::from_seed(&b, 0).unwrap().public()
    );
}
