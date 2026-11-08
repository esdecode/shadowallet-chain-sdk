#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, ScriptBuf};
use shadowallet_chain_bitcoin_cash::{
    AddressKind, BCH_FORK_ID, BchAccount, BchError, BchNetwork, CashAddress, Utxo, build_unsigned,
    deserialize_transaction, serialize_transaction, sighash_all_forkid, sign_transfer,
    transaction_commitment, verify_transfer,
};

fn account(network: BchNetwork) -> BchAccount {
    BchAccount::from_seed(network, &[0x5a; 32]).expect("derivation")
}

#[test]
fn cashaddr_spec_vectors_roundtrip() {
    // From the CashAddr specification's larger test vector table.
    let vector = (
        "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    );
    let decoded = CashAddress::decode(vector.0).expect("decode");
    assert_eq!(decoded.network, BchNetwork::Mainnet);
    assert_eq!(decoded.kind, AddressKind::P2pkh);
    assert_eq!(hex(&decoded.hash), vector.1);
    assert_eq!(decoded.encode(), vector.0);

    let testnet = (
        "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
        "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    );
    let decoded = CashAddress::decode(testnet.0).expect("decode testnet");
    assert_eq!(decoded.network, BchNetwork::Testnet);
    assert_eq!(decoded.kind, AddressKind::P2sh);
    assert_eq!(hex(&decoded.hash), testnet.1);
    assert_eq!(decoded.encode(), testnet.0);

    // Regtest uses its own prefix; the checksum binds the prefix, so the same
    // hash must encode differently.
    let regtest = CashAddress::new(BchNetwork::Regtest, AddressKind::P2pkh, hex_bytes(vector.1))
        .expect("regtest address");
    let encoded = regtest.encode();
    assert!(encoded.starts_with("bchreg:"));
    assert_eq!(
        CashAddress::decode(&encoded).expect("decode regtest"),
        regtest
    );
}

fn hex_bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn cashaddr_legacy_translation_vector() {
    let address = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";
    let decoded = CashAddress::decode(address).expect("decode");
    assert_eq!(
        hex(&decoded.hash),
        "76a04053bda0a88bda5177b86a15c3b29f559873"
    );
    assert_eq!(decoded.encode(), address);
}

#[test]
fn cashaddr_rejects_bad_checksum_and_mixed_case() {
    let mut broken = b"bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2".to_vec();
    let last = broken.len() - 1;
    broken[last] = if broken[last] == b'q' { b'p' } else { b'q' };
    let broken = String::from_utf8(broken).expect("utf8");
    assert!(CashAddress::decode(&broken).is_err());

    assert!(CashAddress::decode("BitcoinCash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2").is_err());
    assert!(CashAddress::decode("BITCOINCASH:QR6M7J9NJLDWWZLG9V7V53UNLR4JKMX6EYLEP8EKG2").is_ok());
}

#[test]
fn derivation_is_deterministic_and_network_scoped() {
    let mainnet = account(BchNetwork::Mainnet);
    let again = account(BchNetwork::Mainnet);
    assert_eq!(mainnet.address(0, 0).unwrap(), again.address(0, 0).unwrap());
    let address = mainnet.address(0, 0).unwrap().encode();
    assert!(address.starts_with("bitcoincash:q"));
    assert!(mainnet.validate_address(&address).is_ok());
    assert_eq!(
        mainnet
            .validate_address(&account(BchNetwork::Testnet).address(0, 0).unwrap().encode())
            .unwrap_err(),
        BchError::WrongNetwork
    );
    assert!(
        account(BchNetwork::Regtest)
            .address(0, 0)
            .unwrap()
            .encode()
            .starts_with("bchreg:")
    );
}

#[test]
fn build_sign_and_independently_verify() {
    let account = account(BchNetwork::Regtest);
    let destination = account.address(0, 7).unwrap().encode();
    let utxo = Utxo {
        outpoint: OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x11; 32]),
            vout: 1,
        },
        value_sats: 100_000_000,
        keychain: 0,
        index: 0,
    };
    let unsigned =
        build_unsigned(&account, &[utxo], &destination, 50_000_000, 2, 0).expect("build");
    assert_eq!(unsigned.fee_sats, 452); // (10 + 148 + 2*34) bytes * 2 sat/vB
    assert_eq!(unsigned.change_sats, 100_000_000 - 50_000_000 - 452);
    assert!(
        unsigned
            .transaction
            .input
            .iter()
            .all(|i| i.script_sig.is_empty())
    );

    let signed = sign_transfer(&account, &unsigned).expect("sign");
    verify_transfer(&unsigned, &signed).expect("verify");

    // Serialization preserves the exact signed transaction.
    let roundtrip = deserialize_transaction(&serialize_transaction(&signed)).expect("roundtrip");
    assert_eq!(roundtrip, signed);
    assert_eq!(
        transaction_commitment(&signed),
        transaction_commitment(&roundtrip)
    );
    assert!(!serialize_transaction(&signed).is_empty());
}

#[test]
fn modified_output_invalidates_the_signature() {
    let account = account(BchNetwork::Regtest);
    let destination = account.address(0, 7).unwrap().encode();
    let utxo = Utxo {
        outpoint: OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
            vout: 0,
        },
        value_sats: 100_000_000,
        keychain: 0,
        index: 3,
    };
    let unsigned =
        build_unsigned(&account, &[utxo], &destination, 50_000_000, 1, 0).expect("build");
    let mut signed = sign_transfer(&account, &unsigned).expect("sign");
    signed.output[0].value = bitcoin::Amount::from_sat(signed.output[0].value.to_sat() + 1);
    assert_eq!(
        verify_transfer(&unsigned, &signed).unwrap_err(),
        BchError::InvalidSignature
    );
}

#[test]
fn fork_id_changes_the_digest_and_wrong_network_is_rejected() {
    let account = account(BchNetwork::Regtest);
    let destination = account.address(0, 2).unwrap().encode();
    let utxo = Utxo {
        outpoint: OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x33; 32]),
            vout: 0,
        },
        value_sats: 10_000,
        keychain: 0,
        index: 0,
    };
    let unsigned = build_unsigned(&account, &[utxo], &destination, 5_000, 1, 0).expect("build");
    let script = ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array(
        account.pubkey_hash(0, 0).unwrap(),
    ));
    let digest =
        sighash_all_forkid(&unsigned.transaction, 0, &script, 10_000, BCH_FORK_ID).unwrap();
    let other_fork = sighash_all_forkid(&unsigned.transaction, 0, &script, 10_000, 1).unwrap();
    assert_ne!(digest, other_fork);

    let testnet_destination = account_for(BchNetwork::Testnet)
        .address(0, 1)
        .unwrap()
        .encode();
    assert_eq!(
        build_unsigned(&account, &[utxo], &testnet_destination, 1_000, 1, 0).unwrap_err(),
        BchError::WrongNetwork
    );
}

fn account_for(network: BchNetwork) -> BchAccount {
    BchAccount::from_seed(network, &[0x99; 32]).expect("derivation")
}

#[test]
fn fee_policy_and_insufficient_funds_fail_closed() {
    let account = account(BchNetwork::Regtest);
    let destination = account.address(0, 1).unwrap().encode();
    let utxo = Utxo {
        outpoint: OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x44; 32]),
            vout: 0,
        },
        value_sats: 10_000,
        keychain: 0,
        index: 0,
    };
    assert_eq!(
        build_unsigned(&account, &[utxo], &destination, 500, 100, 0).unwrap_err(),
        BchError::InsufficientFunds
    );
    assert!(matches!(
        build_unsigned(&account, &[utxo], &destination, 500, 0, 0).unwrap_err(),
        BchError::Fee(_)
    ));
    assert!(matches!(
        build_unsigned(&account, &[utxo], &destination, 500, 10_001, 0).unwrap_err(),
        BchError::Fee(_)
    ));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
