#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The Dogecoin UTXO cache holds the wallet's addresses, UTXOs and history. When the vault protects the path it must be
//! encrypted at rest, a cache created earlier as plaintext must be migrated, and a locked vault must not read it.

use std::str::FromStr;
use std::sync::Arc;

use doge::bip32::{DerivationPath, Xpriv, Xpub};
use doge::secp256k1::Secp256k1;
use shadowallet_chain_dogecoin::DogeNetwork;
use shadowallet_chain_dogecoin::engine::DogeEngine;
use shadowallet_chain_dogecoin::indexer::IndexerConfig;
use shadowallet_chain_securedb as sdb;

fn xpub() -> (String, [u8; 4]) {
    let secp = Secp256k1::new();
    let root = Xpriv::new_master(doge::Network::Testnet, &[7u8; 32]).unwrap();
    let path = DerivationPath::from_str("m/44'/3'/0'").unwrap();
    let account = root.derive_priv(&secp, &path).unwrap();
    let fp = root.fingerprint(&secp);
    (Xpub::from_priv(&secp, &account).to_string(), fp.to_bytes())
}

fn open(
    path: &std::path::Path,
) -> Result<DogeEngine, shadowallet_chain_dogecoin::DogecoinSdkError> {
    let (x, fp) = xpub();
    DogeEngine::open_indexer(
        DogeNetwork::Testnet,
        &x,
        fp,
        IndexerConfig::public_testnet(),
        path,
    )
}

#[test]
fn the_cache_is_encrypted_when_the_vault_protects_it_and_an_old_plaintext_cache_is_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("w.uwv");
    let cache = dir
        .path()
        .join("w.uwv.utxo")
        .join("dogecoin-testnet.sqlite");

    // 1. a cache created by an older build (no vault key was registered yet) is plaintext
    drop(open(&cache).unwrap());
    assert_eq!(sdb::detect(&cache).unwrap(), sdb::Format::Plaintext);

    // 2. the vault is unlocked: opening migrates it, the file is no longer readable as SQLite and reopens with the key
    let prefix = vault.to_string_lossy().into_owned();
    sdb::register_resolver(
        &prefix,
        4242,
        Arc::new(|info: &str, salt: &[u8; 32]| {
            sdb::derive_db_key(b"test vault secret", salt, info).map_err(|e| e.to_string())
        }),
    );
    drop(open(&cache).unwrap());
    assert_eq!(sdb::detect(&cache).unwrap(), sdb::Format::NotPlaintext);
    let bytes = std::fs::read(&cache).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3"));
    drop(open(&cache).unwrap());

    // 3. the vault is locked: the protected path is refused, never opened as plaintext
    sdb::unregister_resolver(4242);
    assert!(
        open(&cache).is_err(),
        "a locked vault must not open the cache"
    );
    assert_eq!(sdb::detect(&cache).unwrap(), sdb::Format::NotPlaintext);
}
