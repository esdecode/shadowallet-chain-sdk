//! Watch-only import from an account-level SLIP-0132 extended public key (zpub/vpub). Offline and deterministic.
//! Vector: the public BIP-84 specification account 0 of the "abandon x11 about" mnemonic.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use shadowallet_chain_bitcoin::{BitcoinEngine, BtcNetwork, WatchDescriptors};

const BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

fn engine(dir: &std::path::Path, text: &str) -> BitcoinEngine {
    let d = WatchDescriptors::from_extended_pubkey(text, BtcNetwork::Mainnet).unwrap();
    BitcoinEngine::create(&dir.join("w.sqlite"), d).unwrap()
}

#[test]
fn the_bip84_zpub_derives_the_published_mainnet_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = engine(dir.path(), BIP84_ZPUB);
    // BIP-84 specification: first and second receive address of account 0
    assert_eq!(
        e.next_receive_address().unwrap(),
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
    assert_eq!(
        e.next_receive_address().unwrap(),
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
    );
    assert_eq!(e.network(), BtcNetwork::Mainnet);
    // nothing scanned yet; two receive addresses were handed out (indexes 0 and 1), no change address
    assert_eq!(e.revealed_indexes(), (Some(1), None));
    // surrounding whitespace (a copied file) is tolerated
    let d =
        WatchDescriptors::from_extended_pubkey(&format!(" {BIP84_ZPUB}\r\n"), BtcNetwork::Mainnet)
            .unwrap();
    assert!(d.external.starts_with("wpkh(xpub") && d.external.ends_with("/0/*)"));
    assert!(d.internal.ends_with("/1/*)"));
    // the Debug form never prints the key
    assert!(!format!("{d:?}").contains("xpub"));
}

#[test]
fn private_wrong_network_master_and_corrupt_keys_are_refused_without_echoing_them() {
    let m = BtcNetwork::Mainnet;
    let flip = |s: &str| {
        let mut c: Vec<char> = s.chars().collect();
        c[20] = if c[20] == 'a' { 'b' } else { 'a' };
        c.into_iter().collect::<String>()
    };
    let corrupt = flip(BIP84_ZPUB);
    for (name, bad) in [
        ("corrupt checksum", corrupt.as_str()),
        ("empty", ""),
        ("garbage", "not a key"),
        // plain xpub and ypub/legacy versions are not native SegWit account keys
        (
            "xpub",
            "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V",
        ),
        // the same key with the test-network version, and with the master (depth 0) marker
        (
            "vpub on mainnet",
            "vpub5YvMuJNjRSYon44z9QmCfdf8SqJRVNvz6m55Qy5iVjZQxDfUgtiQjnc7CC1fAbED2tAGCZRERUfvtn2DstZGU6HMns6dXXH2wujSc2wfi2x",
        ),
        (
            "master key",
            "zpub6kc1YcWLPFhjbvx4NsXQZak7k39P9gZdZWmkQy3FzwzDst5xafrdrzVs2J2UwQdVqML3HFvLV1TwPW1Z9bvSUnhy2GQYnAfNZcyg1DeYset",
        ),
        // the BIP-32 test vector 1 master xprv
        (
            "xprv",
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        ),
    ] {
        let err = WatchDescriptors::from_extended_pubkey(bad, m)
            .unwrap_err()
            .to_string();
        assert!(err.contains("refused"), "{name}: {err}");
        if !bad.is_empty() {
            assert!(
                !err.contains(bad),
                "{name}: the error must not echo the key"
            );
        }
    }
    // a mainnet zpub is not accepted on a test network and a vpub is not accepted on mainnet
    assert!(WatchDescriptors::from_extended_pubkey(BIP84_ZPUB, BtcNetwork::Signet).is_err());
    let vpub = "vpub5YvMuJNjRSYon44z9QmCfdf8SqJRVNvz6m55Qy5iVjZQxDfUgtiQjnc7CC1fAbED2tAGCZRERUfvtn2DstZGU6HMns6dXXH2wujSc2wfi2x";
    assert!(WatchDescriptors::from_extended_pubkey(vpub, BtcNetwork::Signet).is_ok());
}

#[test]
fn a_watch_only_engine_builds_unsigned_transactions_only_and_never_on_mainnet() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = engine(dir.path(), BIP84_ZPUB);
    // mainnet building is refused outright
    let err = e.build_transfer(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        1_000,
        2,
        false,
    );
    assert!(err.is_err());
}

/// On a test network a watch-only engine can build a PSBT, and that PSBT carries no signature at all: the engine holds
/// no private key and offers no signing method, so a watch-only account cannot become spend-capable.
#[test]
fn a_watch_only_psbt_carries_no_signature() {
    let vpub = "vpub5YvMuJNjRSYon44z9QmCfdf8SqJRVNvz6m55Qy5iVjZQxDfUgtiQjnc7CC1fAbED2tAGCZRERUfvtn2DstZGU6HMns6dXXH2wujSc2wfi2x";
    let d = WatchDescriptors::from_extended_pubkey(vpub, BtcNetwork::Signet).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut e = BitcoinEngine::create(&dir.path().join("w.sqlite"), d).unwrap();
    e.fund_for_test(1, &[200_000], true);
    let mut other = BitcoinEngine::create(
        &dir.path().join("o.sqlite"),
        WatchDescriptors::from_extended_pubkey(vpub, BtcNetwork::Signet).unwrap(),
    )
    .unwrap();
    let to = other.next_receive_address().unwrap();
    let plan = e.build_transfer(&to, 50_000, 2, false).unwrap();
    let psbt = bdk_wallet::bitcoin::psbt::Psbt::deserialize(&plan.psbt).unwrap();
    assert!(!psbt.inputs.is_empty());
    for i in &psbt.inputs {
        assert!(
            i.partial_sigs.is_empty()
                && i.final_script_witness.is_none()
                && i.final_script_sig.is_none()
        );
    }
    assert!(
        psbt.unsigned_tx
            .input
            .iter()
            .all(|i| i.witness.is_empty() && i.script_sig.is_empty())
    );
}
