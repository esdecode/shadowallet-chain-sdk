#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The Bitcoin Cash UTXO cache holds the wallet's addresses, UTXOs and history. Under a vault that protects its path it must
//! be encrypted at rest, a cache an older build left as plaintext must be migrated, and a locked vault must not read it.
//! The engine opens (and migrates) its database BEFORE it talks to the node, so no node is needed: the open then fails on the
//! refused connection, which these tests ignore, and what is checked is the file and, when locked, WHERE the failure comes from.

use std::sync::Arc;

use shadowallet_chain_bitcoin_cash::engine::BchEngine;
use shadowallet_chain_bitcoin_cash::{BchAccount, BchNetwork};
use shadowallet_chain_securedb as sdb;

fn open(path: &std::path::Path) -> Result<BchEngine, shadowallet_chain_bitcoin_cash::BchError> {
    let account = BchAccount::from_seed(BchNetwork::Regtest, &[0x33; 32]).unwrap();
    BchEngine::open(
        BchNetwork::Regtest,
        &account.account_xpub().to_string(),
        account.fingerprint_raw,
        "http://127.0.0.1:9",
        "user",
        "password",
        path,
        5,
    )
}

#[test]
fn the_cache_is_encrypted_when_the_vault_protects_it_and_an_old_plaintext_cache_is_migrated() {
    let dir = std::env::temp_dir().join(format!("uw-bch-enc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let vault = dir.join("w.uwv");
    let cache = dir.join("w.uwv.utxo").join("bch-regtest.sqlite");

    let rpc_refused = |r: Result<BchEngine, shadowallet_chain_bitcoin_cash::BchError>| matches!(r, Err(shadowallet_chain_bitcoin_cash::BchError::Transaction(m)) if m.contains("JSON-RPC"));

    // an older build (no vault key registered yet) wrote a plaintext cache; the open then stops at the missing node
    assert!(rpc_refused(open(&cache)));
    assert_eq!(sdb::detect(&cache).unwrap(), sdb::Format::Plaintext);

    // the vault is unlocked: opening migrates it
    let prefix = vault.to_string_lossy().into_owned();
    sdb::register_resolver(
        &prefix,
        7302,
        Arc::new(|info: &str, salt: &[u8; 32]| {
            sdb::derive_db_key(b"test vault secret", salt, info).map_err(|e| e.to_string())
        }),
    );
    assert!(
        rpc_refused(open(&cache)),
        "the storage opened with the key; only the node is missing"
    );
    assert_eq!(sdb::detect(&cache).unwrap(), sdb::Format::NotPlaintext);
    assert!(
        !std::fs::read(&cache)
            .unwrap()
            .starts_with(b"SQLite format 3")
    );
    assert!(rpc_refused(open(&cache)), "reopens with the key");

    // locked: the failure is the STORAGE refusing (no key), not the node, and the file stays encrypted
    sdb::unregister_resolver(7302);
    let locked = open(&cache);
    assert!(
        matches!(&locked, Err(shadowallet_chain_bitcoin_cash::BchError::Transaction(m)) if !m.contains("JSON-RPC")),
        "a locked vault must not open the cache: {:?}",
        locked.err()
    );
    assert_eq!(sdb::detect(&cache).unwrap(), sdb::Format::NotPlaintext);
    let _ = std::fs::remove_dir_all(&dir);
}
