#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The Litecoin UTXO cache holds the wallet's addresses, UTXOs and history. Under a vault that protects its path it must be
//! encrypted at rest, a cache an older build left as plaintext must be migrated, and a locked vault must not read it.

use std::str::FromStr;
use std::sync::Arc;

use litecoin::bip32::{DerivationPath, Xpriv, Xpub};
use litecoin::secp256k1::Secp256k1;
use shadowallet_chain_litecoin::LtcNetwork;
use shadowallet_chain_litecoin::engine::LtcEngine;
use shadowallet_chain_securedb as sdb;

fn open(path: &std::path::Path) -> Result<LtcEngine, shadowallet_chain_litecoin::LitecoinSdkError> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(LtcNetwork::Mainnet.kind(), &[9u8; 32]).unwrap();
    let account = master
        .derive_priv(&secp, &DerivationPath::from_str("m/84'/2'/0'").unwrap())
        .unwrap();
    let xpub = Xpub::from_priv(&secp, &account).to_string();
    LtcEngine::open_esplora(
        LtcNetwork::Mainnet,
        &xpub,
        master.fingerprint(&secp).to_bytes(),
        "http://127.0.0.1:9/api",
        path,
        5,
    )
}

#[test]
fn the_cache_is_encrypted_when_the_vault_protects_it_and_an_old_plaintext_cache_is_migrated() {
    let dir = std::env::temp_dir().join(format!("uw-ltc-enc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let vault = dir.join("w.uwv");
    let cache = dir.join("w.uwv.utxo").join("litecoin-mainnet.sqlite");

    // an older build (no vault key registered yet) wrote a plaintext cache
    drop(open(&cache).unwrap());
    assert_eq!(sdb::detect(&cache).unwrap(), sdb::Format::Plaintext);

    // the vault is unlocked: opening migrates it, and it reopens with the key
    let prefix = vault.to_string_lossy().into_owned();
    sdb::register_resolver(
        &prefix,
        7301,
        Arc::new(|info: &str, salt: &[u8; 32]| {
            sdb::derive_db_key(b"test vault secret", salt, info).map_err(|e| e.to_string())
        }),
    );
    drop(open(&cache).unwrap());
    assert_eq!(sdb::detect(&cache).unwrap(), sdb::Format::NotPlaintext);
    assert!(
        !std::fs::read(&cache)
            .unwrap()
            .starts_with(b"SQLite format 3")
    );
    drop(open(&cache).unwrap());

    // locked: the protected path is refused, never opened as plaintext
    sdb::unregister_resolver(7301);
    assert!(
        open(&cache).is_err(),
        "a locked vault must not open the cache"
    );
    assert_eq!(sdb::detect(&cache).unwrap(), sdb::Format::NotPlaintext);
    let _ = std::fs::remove_dir_all(&dir);
}
