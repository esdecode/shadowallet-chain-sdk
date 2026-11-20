//! Coin Control at the engine level: listing, explicit input selection, PSBT summary.
//! Offline and deterministic: UTXOs come from the `test-support` synthetic-transaction fixtures.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::str::FromStr;

use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use shadowallet_chain_bitcoin::{
    AddressKind, BitcoinEngine, BitcoinError, BtcNetwork, UtxoInfo, WatchDescriptors,
};

fn descriptors(seed: u8) -> WatchDescriptors {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Regtest, &[seed; 32]).expect("master");
    let path = DerivationPath::from_str("m/84'/1'/0'").expect("path");
    let account = master.derive_priv(&secp, &path).expect("account");
    let xpub = Xpub::from_priv(&secp, &account);
    let fingerprint = master.fingerprint(&secp);
    WatchDescriptors {
        network: BtcNetwork::Regtest,
        kind: AddressKind::P2wpkh,
        external: format!("wpkh([{fingerprint}/84'/1'/0']{xpub}/0/*)"),
        internal: format!("wpkh([{fingerprint}/84'/1'/0']{xpub}/1/*)"),
        fingerprint: fingerprint.to_string(),
    }
}

struct Fixture {
    engine: BitcoinEngine,
    recipient: String,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let engine = BitcoinEngine::create(&dir.path().join("a.sqlite"), descriptors(7)).unwrap();
    let mut other = BitcoinEngine::create(&dir.path().join("b.sqlite"), descriptors(9)).unwrap();
    let recipient = other.next_receive_address().unwrap();
    Fixture {
        engine,
        recipient,
        _dir: dir,
    }
}

fn out(u: &UtxoInfo) -> (String, u32) {
    (u.txid.clone(), u.vout)
}

/// Funds: A=100_000 (confirmed), B=50_000 (confirmed), C=20_000 (confirmed), D=7_000 (unconfirmed).
fn funded() -> (Fixture, Vec<UtxoInfo>) {
    let mut f = fixture();
    f.engine.fund_for_test(1, &[100_000, 50_000, 20_000], true);
    f.engine.fund_for_test(2, &[7_000], false);
    let mut utxos = f.engine.list_utxos();
    utxos.sort_by_key(|u| std::cmp::Reverse(u.value_sats));
    (f, utxos)
}

#[test]
fn lists_every_unspent_output_with_its_facts() {
    let (mut f, utxos) = funded();
    assert_eq!(
        utxos.iter().map(|u| u.value_sats).collect::<Vec<_>>(),
        vec![100_000, 50_000, 20_000, 7_000]
    );
    assert_eq!(
        utxos.iter().map(|u| u.confirmations).collect::<Vec<_>>(),
        vec![1, 1, 1, 0]
    );
    assert!(utxos[3].confirmation_height.is_none());
    assert!(utxos.iter().all(|u| u.address.is_some() && !u.is_change));
    assert!(
        utxos
            .iter()
            .all(|u| u.script_pubkey_hex.starts_with("0014"))
    );
    f.engine.mine_for_test(2);
    let again = f.engine.list_utxos();
    let a = again.iter().find(|u| u.value_sats == 100_000).unwrap();
    assert_eq!(a.confirmations, 3);
}

#[test]
fn selecting_one_utxo_spends_exactly_that_one() {
    let (mut f, utxos) = funded();
    let pick = out(&utxos[1]); // 50_000
    let plan = f
        .engine
        .build_transfer_selected(
            &f.recipient,
            30_000,
            2,
            false,
            std::slice::from_ref(&pick),
            &[],
        )
        .unwrap();
    let s = f.engine.describe_psbt(&plan.psbt).unwrap();
    assert_eq!(s.inputs.len(), 1);
    assert_eq!((s.inputs[0].txid.clone(), s.inputs[0].vout), pick);
    assert_eq!(s.total_in_sats, 50_000);
    assert_eq!(s.fee_sats, plan.fee_sats);
    assert_eq!(s.total_in_sats, s.total_out_sats + s.fee_sats);
    let recipient_out: Vec<_> = s.outputs.iter().filter(|o| !o.is_mine).collect();
    assert_eq!(recipient_out.len(), 1);
    assert_eq!(recipient_out[0].value_sats, 30_000);
    assert_eq!(
        recipient_out[0].address.as_deref(),
        Some(f.recipient.as_str())
    );
    let change: Vec<_> = s.outputs.iter().filter(|o| o.is_change).collect();
    assert_eq!(
        change.len(),
        1,
        "change goes to the wallet's internal keychain"
    );
    assert_eq!(change[0].value_sats, 50_000 - 30_000 - plan.fee_sats);
}

#[test]
fn several_and_all_utxos_are_used_in_full() {
    let (mut f, utxos) = funded();
    let two = vec![out(&utxos[0]), out(&utxos[2])];
    let plan = f
        .engine
        .build_transfer_selected(&f.recipient, 90_000, 2, false, &two, &[])
        .unwrap();
    let s = f.engine.describe_psbt(&plan.psbt).unwrap();
    let mut got: Vec<_> = s.inputs.iter().map(|i| (i.txid.clone(), i.vout)).collect();
    let mut want = two.clone();
    got.sort();
    want.sort();
    assert_eq!(got, want);
    assert_eq!(s.total_in_sats, 120_000);

    let all: Vec<_> = utxos.iter().map(out).collect();
    let plan = f
        .engine
        .build_transfer_selected(&f.recipient, 150_000, 2, false, &all, &[])
        .unwrap();
    let s = f.engine.describe_psbt(&plan.psbt).unwrap();
    assert_eq!(s.inputs.len(), 4);
    assert_eq!(s.total_in_sats, 177_000);
}

#[test]
fn insufficient_selection_fails_and_never_falls_back_to_other_coins() {
    let (mut f, utxos) = funded();
    // The wallet holds 177_000 in total; the selection (20_000) cannot pay 30_000.
    let err = f
        .engine
        .build_transfer_selected(&f.recipient, 30_000, 2, false, &[out(&utxos[2])], &[])
        .unwrap_err();
    assert!(matches!(err, BitcoinError::InsufficientFunds), "{err:?}");
    // Automatic selection with the very same request succeeds: the refusal is the selection's.
    assert!(
        f.engine
            .build_transfer(&f.recipient, 30_000, 2, false)
            .is_ok()
    );
}

#[test]
fn bad_selections_are_refused_before_anything_is_built() {
    let (mut f, utxos) = funded();
    let a = out(&utxos[0]);
    // empty
    assert!(
        f.engine
            .build_transfer_selected(&f.recipient, 1_000, 2, false, &[], &[])
            .is_err()
    );
    // duplicate
    let e = f
        .engine
        .build_transfer_selected(&f.recipient, 1_000, 2, false, &[a.clone(), a.clone()], &[])
        .unwrap_err();
    assert!(e.to_string().contains("duplicate"), "{e}");
    // an outpoint this wallet does not own (foreign, or from another network: indistinguishable)
    let foreign = ("ab".repeat(32), 0);
    let e = f
        .engine
        .build_transfer_selected(&f.recipient, 1_000, 2, false, &[foreign], &[])
        .unwrap_err();
    assert!(e.to_string().contains("not an unspent output"), "{e}");
    // right txid, wrong vout
    let e = f
        .engine
        .build_transfer_selected(&f.recipient, 1_000, 2, false, &[(a.0.clone(), 99)], &[])
        .unwrap_err();
    assert!(e.to_string().contains("not an unspent output"), "{e}");
    // malformed txid
    assert!(
        f.engine
            .build_transfer_selected(&f.recipient, 1_000, 2, false, &[("zz".into(), 0)], &[])
            .is_err()
    );
    // frozen or reserved by the caller
    let e = f
        .engine
        .build_transfer_selected(
            &f.recipient,
            1_000,
            2,
            false,
            std::slice::from_ref(&a),
            std::slice::from_ref(&a),
        )
        .unwrap_err();
    assert!(e.to_string().contains("frozen or reserved"), "{e}");
    // a zero amount is not a payment
    assert!(
        f.engine
            .build_transfer_selected(&f.recipient, 0, 2, false, &[a], &[])
            .is_err()
    );
}

#[test]
fn a_spent_output_cannot_be_selected() {
    let (mut f, utxos) = funded();
    let a = out(&utxos[0]);
    f.engine.spend_for_test(std::slice::from_ref(&a), true);
    assert!(f.engine.list_utxos().iter().all(|u| out(u) != a));
    let e = f
        .engine
        .build_transfer_selected(&f.recipient, 1_000, 2, false, &[a], &[])
        .unwrap_err();
    assert!(e.to_string().contains("not an unspent output"), "{e}");
}

#[test]
fn sweeping_the_selection_has_no_change_output() {
    let (mut f, utxos) = funded();
    let sel = vec![out(&utxos[1]), out(&utxos[2])]; // 50_000 + 20_000
    let plan = f
        .engine
        .build_transfer_selected(&f.recipient, 0, 2, true, &sel, &[])
        .unwrap();
    let s = f.engine.describe_psbt(&plan.psbt).unwrap();
    assert_eq!(s.inputs.len(), 2);
    assert_eq!(s.outputs.len(), 1, "exact spend: no change output");
    assert_eq!(s.outputs[0].value_sats + s.fee_sats, 70_000);
    assert!(!s.outputs[0].is_mine);
}

#[test]
fn dust_change_goes_to_the_fee_and_is_visible_as_the_effective_fee() {
    let (mut f, utxos) = funded();
    // Input 20_000. Pay 19_700: the remainder after the fee is below the dust limit.
    let plan = f
        .engine
        .build_transfer_selected(&f.recipient, 19_700, 1, false, &[out(&utxos[2])], &[])
        .unwrap();
    let s = f.engine.describe_psbt(&plan.psbt).unwrap();
    assert_eq!(s.outputs.len(), 1, "dust change is not created");
    assert_eq!(
        s.fee_sats,
        20_000 - 19_700,
        "the leftover is the effective fee"
    );
    assert!(
        s.fee_sats > 150,
        "more than the bare fee at 1 sat/vB: the dust was absorbed"
    );
    assert_eq!(s.fee_sats, plan.fee_sats);
}

#[test]
fn an_altered_psbt_is_visible_in_its_summary() {
    let (mut f, utxos) = funded();
    let plan = f
        .engine
        .build_transfer_selected(&f.recipient, 30_000, 2, false, &[out(&utxos[1])], &[])
        .unwrap();
    let honest = f.engine.describe_psbt(&plan.psbt).unwrap();
    let mut psbt = bdk_wallet::bitcoin::psbt::Psbt::deserialize(&plan.psbt).unwrap();
    // Steal the change: pay it to the recipient's script instead.
    let recipient_hex = honest
        .outputs
        .iter()
        .find(|o| !o.is_mine)
        .unwrap()
        .script_pubkey_hex
        .clone();
    let recipient_spk = psbt
        .unsigned_tx
        .output
        .iter()
        .find(|o| o.script_pubkey.to_hex_string() == recipient_hex)
        .unwrap()
        .script_pubkey
        .clone();
    for o in &mut psbt.unsigned_tx.output {
        if honest
            .outputs
            .iter()
            .any(|h| h.is_change && h.script_pubkey_hex == o.script_pubkey.to_hex_string())
        {
            o.script_pubkey = recipient_spk.clone();
        }
    }
    let changed = f.engine.describe_psbt(&psbt.serialize()).unwrap();
    assert_ne!(honest, changed);
    assert!(changed.outputs.iter().all(|o| !o.is_change));
    // A hidden extra input is visible too.
    let mut psbt = bdk_wallet::bitcoin::psbt::Psbt::deserialize(&plan.psbt).unwrap();
    psbt.unsigned_tx
        .input
        .push(psbt.unsigned_tx.input[0].clone());
    psbt.inputs.push(psbt.inputs[0].clone());
    let more = f.engine.describe_psbt(&psbt.serialize()).unwrap();
    assert_eq!(more.inputs.len(), 2);
}
