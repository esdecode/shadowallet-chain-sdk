//! Spending policy: coinbase maturity (consensus: 100 confirmations) and the unconfirmed-output rule.
//! Offline and deterministic (synthetic transactions from the `test-support` fixtures; the policy code is the production code).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::str::FromStr;

use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use shadowallet_chain_bitcoin::{
    AddressKind, BitcoinEngine, BitcoinError, BtcNetwork, COINBASE_MATURITY, WatchDescriptors,
};

fn descriptors(seed: u8) -> WatchDescriptors {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Regtest, &[seed; 32]).expect("master");
    let account = master
        .derive_priv(&secp, &DerivationPath::from_str("m/84'/1'/0'").unwrap())
        .unwrap();
    let xpub = Xpub::from_priv(&secp, &account);
    let fp = master.fingerprint(&secp);
    WatchDescriptors {
        network: BtcNetwork::Regtest,
        kind: AddressKind::P2wpkh,
        external: format!("wpkh([{fp}/84'/1'/0']{xpub}/0/*)"),
        internal: format!("wpkh([{fp}/84'/1'/0']{xpub}/1/*)"),
        fingerprint: fp.to_string(),
    }
}

struct F {
    e: BitcoinEngine,
    to: String,
    _d: tempfile::TempDir,
}

fn fixture() -> F {
    let d = tempfile::tempdir().unwrap();
    let e = BitcoinEngine::create(&d.path().join("a.sqlite"), descriptors(7)).unwrap();
    let mut other = BitcoinEngine::create(&d.path().join("b.sqlite"), descriptors(9)).unwrap();
    let to = other.next_receive_address().unwrap();
    F { e, to, _d: d }
}

/// A coinbase transaction (single input spending the null outpoint) paying the wallet's external address 0.
fn coinbase_raw(e: &mut BitcoinEngine, value: u64) -> Vec<u8> {
    let spk = {
        let a = e.next_receive_address().unwrap();
        e.validate_address(&a).unwrap().script_pubkey()
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x07]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        }],
    };
    bdk_wallet::bitcoin::consensus::serialize(&tx)
}

#[test]
fn coinbase_maturity_boundary_is_100_confirmations() {
    assert_eq!(COINBASE_MATURITY, 100);
    let mut f = fixture();
    let raw = coinbase_raw(&mut f.e, 5_000_000_000);
    f.e.ingest_for_test(&raw, true).unwrap();
    let u = f.e.list_utxos();
    assert_eq!(u.len(), 1);
    assert!(u[0].is_coinbase);
    assert_eq!(u[0].confirmations, 1);
    assert!(!u[0].spendable);
    assert_eq!(u[0].unspendable_reason, Some("immature coinbase"));
    assert_eq!(f.e.balance().immature_sats, 5_000_000_000);
    assert_eq!(f.e.balance().confirmed_sats, 0);
    let out = (u[0].txid.clone(), u[0].vout);
    // automatic selection cannot use it, explicit selection refuses it
    assert!(f.e.build_transfer(&f.to, 100_000, 2, false).is_err());
    let err =
        f.e.build_transfer_selected(&f.to, 100_000, 2, false, std::slice::from_ref(&out), &[])
            .unwrap_err();
    assert!(
        matches!(&err, BitcoinError::Engine(m) if m.contains("immature coinbase")),
        "{err:?}"
    );
    // 99 confirmations: still immature (the next block would be at height h + 99 < h + 100)
    f.e.mine_for_test(98);
    assert_eq!(f.e.list_utxos()[0].confirmations, 99);
    assert!(!f.e.list_utxos()[0].spendable);
    assert!(f.e.build_transfer(&f.to, 100_000, 2, false).is_err());
    // 100 confirmations: spendable by both paths
    f.e.mine_for_test(1);
    assert_eq!(f.e.list_utxos()[0].confirmations, 100);
    assert!(f.e.list_utxos()[0].spendable);
    assert_eq!(f.e.balance().immature_sats, 0);
    assert_eq!(f.e.balance().confirmed_sats, 5_000_000_000);
    assert!(f.e.build_transfer(&f.to, 100_000, 2, false).is_ok());
    assert!(
        f.e.build_transfer_selected(&f.to, 100_000, 2, false, &[out], &[])
            .is_ok()
    );
}

#[test]
fn an_ordinary_output_is_not_a_coinbase_and_is_not_confused_with_an_immature_one() {
    let mut f = fixture();
    f.e.fund_for_test(1, &[200_000], true);
    let u = f.e.list_utxos();
    assert!(!u[0].is_coinbase);
    assert!(u[0].spendable);
    assert!(f.e.build_transfer(&f.to, 50_000, 2, false).is_ok());
}

#[test]
fn unconfirmed_incoming_is_excluded_from_automatic_selection_but_an_explicit_choice_is_allowed() {
    let mut f = fixture();
    f.e.fund_for_test(1, &[200_000], false);
    let u = f.e.list_utxos();
    assert_eq!(u[0].confirmations, 0);
    assert!(!u[0].spendable);
    assert_eq!(u[0].unspendable_reason, Some("unconfirmed incoming"));
    // automatic selection: nothing to spend
    assert!(f.e.build_transfer(&f.to, 50_000, 2, false).is_err());
    // explicit selection (what CPFP relies on) is still possible and builds exactly that input
    let out = (u[0].txid.clone(), u[0].vout);
    assert!(
        f.e.build_transfer_selected(&f.to, 50_000, 2, false, &[out], &[])
            .is_ok()
    );
    // a confirmed incoming output is spendable by automatic selection
    f.e.fund_for_test(2, &[200_000], true);
    assert!(f.e.build_transfer(&f.to, 50_000, 2, false).is_ok());
}

/// With the compile-time `mainnet-send` feature the engine may BUILD (never sign) a mainnet transaction; without it,
/// building is refused. Both builds are covered by this test.
#[test]
fn mainnet_building_follows_the_compile_time_feature() {
    let d = WatchDescriptors::from_extended_pubkey(
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        BtcNetwork::Mainnet,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut e = BitcoinEngine::create(&dir.path().join("m.sqlite"), d).unwrap();
    e.fund_for_test(1, &[200_000], true);
    let r = e.build_transfer(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        50_000,
        2,
        false,
    );
    if cfg!(feature = "mainnet-send") {
        let plan = r.unwrap();
        let psbt = bdk_wallet::bitcoin::psbt::Psbt::deserialize(&plan.psbt).unwrap();
        assert!(
            psbt.inputs.iter().all(|i| i.partial_sigs.is_empty()),
            "building never signs"
        );
    } else {
        assert!(matches!(r, Err(BitcoinError::MainnetDisabled)));
    }
}
