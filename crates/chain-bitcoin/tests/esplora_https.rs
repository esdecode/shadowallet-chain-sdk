#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_bitcoin::{AddressKind, BitcoinEngine, BtcNetwork, WatchDescriptors};

#[test]
#[ignore = "requires public HTTPS Esplora network access; read-only"]
fn esplora_https_fee_estimates_verify_tls() {
    let estimates = BitcoinEngine::estimate_fees_esplora("https://blockstream.info/api")
        .expect("HTTPS Esplora fee estimates");
    assert!(estimates.economy_sat_vb >= 1);
    assert!(estimates.normal_sat_vb >= 1);
    assert!(estimates.priority_sat_vb >= 1);
}

#[test]
#[ignore = "requires public HTTPS Esplora network access; read-only"]
fn esplora_full_scan_reaches_tip() {
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let descriptors = WatchDescriptors {
        network: BtcNetwork::Mainnet,
        kind: AddressKind::P2wpkh,
        external: format!("wpkh([00000000/84'/0'/0']{xpub}/0/*)"),
        internal: format!("wpkh([00000000/84'/0'/0']{xpub}/1/*)"),
        fingerprint: "00000000".to_owned(),
    };
    let dir = tempfile::tempdir().unwrap();
    let mut engine = BitcoinEngine::create(&dir.path().join("btc.sqlite"), descriptors).unwrap();
    let report = engine.sync_esplora("https://blockstream.info/api").unwrap();
    assert!(report.tip_height > 0);
}
