#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Offline checks: known-answer vectors from dcrd's own test suites and the spend-construction rules.

use dcr_rs::hd::ExtPrivKey;
use dcr_rs::network::Network;
use shadowallet_chain_decred::*;

fn seed() -> Vec<u8> {
    // BIP-39 seed of the 24-word "abandon ... art" test phrase (PBKDF2-HMAC-SHA512, 2048 rounds), hex.
    hex::decode("408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840").unwrap()
}

#[test]
fn blake256_known_answer() {
    // BLAKE-256 of the empty string from the SHA-3 finalist specification.
    assert_eq!(
        hex::encode(dcr_rs::blake256::sum256(b"")),
        "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a"
    );
}

#[test]
fn dcrd_hdkeychain_bip32_vector_1_master_key() {
    // dcrd hdkeychain test vector 1 (seed 000102..0f): the master extended private key on mainnet.
    let master = ExtPrivKey::master_from_seed(
        &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(
        master.to_base58(),
        "dprv3hCznBesA6jBtmoyVFPfyMSZ1qYZ3WdjdebquvkEfmRfxC9VFEFi2YDaJqHnx7uGe75eGSa3Mn3oHK11hBW7KZUrPxwbCPBmuCi1nwm182s"
    );
}

#[test]
fn derivation_is_per_network_and_per_account() {
    let a0 = Account::from_seed(&seed(), SIMNET, 0).unwrap();
    let a1 = Account::from_seed(&seed(), SIMNET, 1).unwrap();
    let t0 = Account::from_seed(&seed(), TESTNET, 0).unwrap();
    assert!(a0.address(0, 0).unwrap().starts_with("Ss"));
    assert!(t0.address(0, 0).unwrap().starts_with("Ts"));
    assert_ne!(a0.address(0, 0).unwrap(), a1.address(0, 0).unwrap());
    assert_ne!(a0.address(0, 0).unwrap(), a0.address(1, 0).unwrap());
    assert_ne!(a0.address(0, 0).unwrap(), a0.address(0, 1).unwrap());
    assert!(
        a0.address(2, 0).is_err(),
        "only external and internal branches exist"
    );
    assert!(Account::from_seed(&seed(), SIMNET, 0x8000_0000).is_err());
}

fn utxo(txid: &str, value: i64, confirmations: u64, coinbase: bool) -> Utxo {
    Utxo {
        txid: txid.into(),
        vout: 0,
        tree: 0,
        value,
        script: vec![],
        confirmations,
        coinbase,
        branch: 0,
        index: 0,
        address: String::new(),
    }
}

#[test]
fn only_confirmed_mature_outputs_are_spent_and_dust_is_refused() {
    let account = Account::from_seed(&seed(), SIMNET, 0).unwrap();
    let to = Account::from_seed(&seed(), SIMNET, 1)
        .unwrap()
        .address(0, 0)
        .unwrap();
    let id = |n: u8| format!("{n:02x}").repeat(32);
    let scan = Scan {
        utxos: vec![
            utxo(&id(1), 900_000_000, 0, false),
            utxo(&id(2), 900_000_000, 5, true),
            utxo(&id(3), 100_000_000, 3, false),
        ],
        coinbase_maturity: 16,
        ..Scan::default()
    };
    assert_eq!(scan.spendable(), 100_000_000);
    assert_eq!(scan.pending(), 900_000_000);
    assert_eq!(scan.immature(), 900_000_000);
    // 5 DCR cannot be paid: the large outputs are unconfirmed or immature.
    assert!(prepare_send(&scan, &account, &to, 500_000_000, DEFAULT_FEE_RATE).is_err());
    let p = prepare_send(&scan, &account, &to, 50_000_000, DEFAULT_FEE_RATE).unwrap();
    assert_eq!(p.inputs.len(), 1);
    assert_eq!(p.inputs[0].txid, id(3));
    assert_eq!(p.amount + p.fee + p.change.as_ref().unwrap().1, 100_000_000);
    assert!(prepare_send(&scan, &account, &to, DUST - 1, DEFAULT_FEE_RATE).is_err());
    assert!(
        prepare_send(&scan, &account, &to, 10_000_000, 999).is_err(),
        "fee rate floor"
    );
    // Change that would be dust goes to the fee instead of creating an unrelayable output.
    let exact = prepare_send(&scan, &account, &to, 100_000_000 - 3_000, DEFAULT_FEE_RATE).unwrap();
    assert!(exact.change.is_none());
    assert_eq!(exact.amount + exact.fee, 100_000_000);
    // Wrong network and garbage addresses are refused.
    let testnet = Account::from_seed(&seed(), TESTNET, 0)
        .unwrap()
        .address(0, 0)
        .unwrap();
    assert!(prepare_send(&scan, &account, &testnet, 10_000_000, DEFAULT_FEE_RATE).is_err());
    assert!(
        prepare_send(
            &scan,
            &account,
            "not-an-address",
            10_000_000,
            DEFAULT_FEE_RATE
        )
        .is_err()
    );
}

#[test]
fn mainnet_never_signs_and_identity_must_match() {
    let mainnet = NETS[0];
    assert!(mainnet.is_mainnet);
    assert!(VerifiedNet::verify(mainnet, mainnet.chain, mainnet.genesis_hash).is_err());
    assert!(VerifiedNet::verify(TESTNET, "mainnet", TESTNET.genesis_hash).is_err());
    assert!(VerifiedNet::verify(TESTNET, TESTNET.chain, &"00".repeat(32)).is_err());
    assert!(VerifiedNet::verify(SIMNET, SIMNET.chain, SIMNET.genesis_hash).is_ok());
    let account = Account::from_seed(&seed(), mainnet, 0).unwrap();
    let to = account.address(0, 1).unwrap();
    let scan = Scan {
        utxos: vec![utxo(&"ab".repeat(32), 900_000_000, 50, false)],
        coinbase_maturity: 256,
        ..Scan::default()
    };
    assert!(
        prepare_send(&scan, &account, &to, 10_000_000, DEFAULT_FEE_RATE).is_err(),
        "mainnet spends cannot even be prepared"
    );
}
