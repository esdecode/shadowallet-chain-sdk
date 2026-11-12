#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Account-index derivation: account 0 is unchanged, other accounts are distinct and bounded.
use shadowallet_chain_bitcoin_cash::{BchAccount, BchNetwork};

#[test]
fn account_zero_matches_the_default_and_other_accounts_differ() {
    let seed = [0x5a; 32];
    let default = BchAccount::from_seed(BchNetwork::Regtest, &seed).unwrap();
    let zero = BchAccount::from_seed_account(BchNetwork::Regtest, &seed, 0).unwrap();
    let one = BchAccount::from_seed_account(BchNetwork::Regtest, &seed, 1).unwrap();
    assert_eq!(
        default.account_xpub().to_string(),
        zero.account_xpub().to_string()
    );
    assert_ne!(
        zero.account_xpub().to_string(),
        one.account_xpub().to_string()
    );
    assert_eq!(zero.fingerprint, one.fingerprint, "same master key");
}

#[test]
fn non_hardenable_index_is_rejected() {
    assert!(BchAccount::from_seed_account(BchNetwork::Regtest, &[1; 32], 0x8000_0000).is_err());
}
