#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Read-only checks against the public Litecoin testnet Esplora (litecoinspace.org). No keys involved.

use litecoin::consensus::encode::deserialize_hex;
use shadowallet_chain_litecoin::esplora::EsploraClient;

const BASE: &str = "https://litecoinspace.org/testnet/api";
const LTC_TESTNET_GENESIS: &str =
    "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0";
// A public testnet address that appears in recent blocks (read-only lookups).
const ADDRESS: &str = "tltc1qlvjdqnn4a2vr3p7fkrg9cx05utj4t3g4389kws";

#[test]
#[ignore = "requires public HTTPS access to litecoinspace.org; read-only"]
fn litecoin_testnet_identity_tip_fees() {
    let es = EsploraClient::new(BASE).unwrap();
    assert_eq!(es.genesis_hash().unwrap(), LTC_TESTNET_GENESIS);
    assert!(es.tip_height().unwrap() > 4_000_000);
    let fees = es.fees().expect("fee estimates");
    assert!(fees.economy >= 1 && fees.economy <= fees.normal && fees.normal <= fees.priority);
}

#[test]
#[ignore = "requires public HTTPS access to litecoinspace.org; read-only"]
fn litecoin_testnet_history_utxos_and_transaction_bytes_agree() {
    let es = EsploraClient::new(BASE).unwrap();
    let txs = es.address_txs(ADDRESS).unwrap();
    assert!(!txs.is_empty());
    let first = &txs[0];
    // The server's raw bytes must hash to the txid it listed.
    let raw = es.tx_hex(&first.txid).unwrap();
    let tx: litecoin::Transaction = deserialize_hex(&raw).unwrap();
    assert_eq!(tx.compute_txid().to_string(), first.txid);
    assert_eq!(tx.output.len(), first.outputs.len());
    for utxo in es.address_utxos(ADDRESS).unwrap() {
        assert!(es.output_unspent(&utxo.txid, utxo.vout).unwrap());
    }
    // An unknown txid is reported as not found with the wording the reservation recovery understands.
    let unknown = "00".repeat(32);
    let err = es.tx_status(&unknown).unwrap_err().to_string();
    assert!(
        err.contains("No such mempool") && err.contains("-5"),
        "{err}"
    );
}

#[test]
#[ignore = "requires public HTTPS access to litecoinspace.org; read-only"]
fn engine_syncs_an_unused_testnet_account_through_esplora() {
    use litecoin::bip32::{DerivationPath, Xpriv, Xpub};
    use litecoin::secp256k1::Secp256k1;
    use shadowallet_chain_litecoin::LtcNetwork;
    use shadowallet_chain_litecoin::engine::LtcEngine;
    use std::str::FromStr;
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(LtcNetwork::Testnet.network(), &[7u8; 64]).unwrap();
    let path = DerivationPath::from_str("m/84'/1'/0'").unwrap();
    let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap());
    let fingerprint = master.fingerprint(&secp).to_bytes();
    let dir = std::env::temp_dir().join(format!("ltc-esplora-{}", std::process::id()));
    let mut engine = LtcEngine::open_esplora(
        LtcNetwork::Testnet,
        &xpub.to_string(),
        fingerprint,
        BASE,
        &dir.join("ltc.sqlite"),
        20,
    )
    .unwrap();
    let report = engine.sync().unwrap();
    assert!(report.tip_height > 4_000_000);
    assert_eq!((report.utxos, report.history), (0, 0));
    assert_eq!(engine.balance().confirmed_sats, 0);
    let fees = engine.fee_estimates();
    assert!(fees.source.starts_with("esplora:"), "{}", fees.source);
    assert!(
        engine
            .next_receive_address()
            .unwrap()
            .to_string()
            .starts_with("tltc1q")
    );
    let _ = std::fs::remove_dir_all(dir);
}
