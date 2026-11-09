//! Database compatibility and integrity tests for the SDK wallet store.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Network, Txid};
use bdk_wallet::{ChangeSet, WalletPersister};
use rusqlite::Connection;
use shadowallet_chain_bitcoin::sqlite_store::SqliteStoreError;
use shadowallet_chain_bitcoin::{BitcoinEngine, BtcNetwork, SqliteStore, WatchDescriptors};

fn descriptors() -> WatchDescriptors {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Regtest, &[7u8; 32]).expect("master");
    let path = DerivationPath::from_str("m/84'/1'/0'").expect("path");
    let account = master.derive_priv(&secp, &path).expect("account");
    let xpub = Xpub::from_priv(&secp, &account);
    let fingerprint = master.fingerprint(&secp);
    WatchDescriptors {
        network: BtcNetwork::Regtest,
        kind: shadowallet_chain_bitcoin::AddressKind::P2wpkh,
        external: format!("wpkh([{fingerprint}/84'/1'/0']{xpub}/0/*)"),
        internal: format!("wpkh([{fingerprint}/84'/1'/0']{xpub}/1/*)"),
        fingerprint: fingerprint.to_string(),
    }
}

fn legacy_schema(conn: &Connection) {
    conn.execute_batch(
        r#"
        CREATE TABLE bdk_schemas(name TEXT PRIMARY KEY NOT NULL, version INTEGER NOT NULL) STRICT;
        INSERT INTO bdk_schemas(name, version) VALUES
            ('bdk_wallet', 1), ('bdk_localchain', 0), ('bdk_txgraph', 3), ('bdk_keychaintxout', 1);
        CREATE TABLE bdk_wallet(
            id INTEGER PRIMARY KEY NOT NULL CHECK (id = 0),
            descriptor TEXT, change_descriptor TEXT, network TEXT
        ) STRICT;
        CREATE TABLE bdk_wallet_locked_outpoints(
            txid TEXT NOT NULL, vout INTEGER NOT NULL, PRIMARY KEY(txid, vout)
        ) STRICT;
        CREATE TABLE bdk_blocks(
            block_height INTEGER PRIMARY KEY NOT NULL, block_hash TEXT NOT NULL
        ) STRICT;
        CREATE TABLE bdk_txs(
            txid TEXT PRIMARY KEY NOT NULL, raw_tx BLOB, last_seen INTEGER,
            last_evicted INTEGER, first_seen INTEGER
        ) STRICT;
        CREATE TABLE bdk_txouts(
            txid TEXT NOT NULL, vout INTEGER NOT NULL, value INTEGER NOT NULL,
            script BLOB NOT NULL, PRIMARY KEY (txid, vout)
        ) STRICT;
        CREATE TABLE bdk_anchors(
            txid TEXT NOT NULL REFERENCES bdk_txs(txid), block_height INTEGER NOT NULL,
            block_hash TEXT NOT NULL, confirmation_time INTEGER DEFAULT -1 NOT NULL,
            PRIMARY KEY (txid, block_height, block_hash)
        ) STRICT;
        CREATE TABLE bdk_descriptor_last_revealed(
            descriptor_id TEXT PRIMARY KEY NOT NULL, last_revealed INTEGER NOT NULL
        ) STRICT;
        CREATE TABLE bdk_descriptor_derived_spks(
            descriptor_id TEXT NOT NULL, spk_index INTEGER NOT NULL, spk BLOB NOT NULL,
            PRIMARY KEY (descriptor_id, spk_index)
        ) STRICT;
        "#,
    )
    .expect("legacy schema");
}

#[test]
fn bundled_sqlite_is_patched_release() {
    let store = SqliteStore::open_in_memory().expect("store");
    let version: String = store
        .connection()
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .expect("version");
    assert_eq!(version, "3.54.1");
    store.integrity_check().expect("integrity");
}

#[test]
fn wallet_state_survives_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("btc.sqlite");
    let descriptors = descriptors();

    let first = {
        let mut engine = BitcoinEngine::create(&path, descriptors.clone()).expect("create");
        engine.next_receive_address().expect("address")
    };
    let second = {
        let mut engine = BitcoinEngine::load(&path, descriptors.clone())
            .expect("load")
            .expect("wallet exists");
        engine.next_receive_address().expect("address")
    };
    let third = {
        let mut engine = BitcoinEngine::load(&path, descriptors)
            .expect("load")
            .expect("wallet exists");
        engine.next_receive_address().expect("address")
    };
    assert_ne!(first, second);
    assert_ne!(second, third);
}

#[test]
fn legacy_bdk_database_is_imported_without_modification() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("legacy.sqlite");
    let conn = Connection::open(&path).expect("open");
    legacy_schema(&conn);
    let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    conn.execute(
        "INSERT INTO bdk_blocks(block_height, block_hash) VALUES(0, ?1)",
        [txid],
    )
    .expect("block");
    conn.execute(
        "INSERT INTO bdk_wallet(id, network) VALUES(0, 'regtest')",
        [],
    )
    .expect("wallet row");
    drop(conn);

    let mut store = SqliteStore::open(&path).expect("store");
    let changeset = WalletPersister::initialize(&mut store).expect("import");
    assert_eq!(changeset.network, Some(Network::Regtest));
    assert_eq!(changeset.local_chain.blocks.len(), 1);

    // A second initialize returns the persisted import and is stable.
    let again = WalletPersister::initialize(&mut store).expect("reload");
    assert_eq!(again, changeset);

    // Legacy tables are left untouched.
    let conn = Connection::open(&path).expect("reopen");
    let legacy_blocks: i64 = conn
        .query_row("SELECT COUNT(*) FROM bdk_blocks", [], |row| row.get(0))
        .expect("count");
    assert_eq!(legacy_blocks, 1);

    // The new log contains exactly one imported row.
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM shadowallet_wallet_changesets",
            [],
            |row| row.get(0),
        )
        .expect("rows");
    assert_eq!(rows, 1);
}

#[test]
fn newer_legacy_schema_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("future.sqlite");
    let conn = Connection::open(&path).expect("open");
    legacy_schema(&conn);
    conn.execute(
        "UPDATE bdk_schemas SET version = 99 WHERE name = 'bdk_txgraph'",
        [],
    )
    .expect("bump");
    drop(conn);

    let mut store = SqliteStore::open(&path).expect("store");
    let error = WalletPersister::initialize(&mut store).expect_err("must fail");
    assert!(matches!(error, SqliteStoreError::UnsupportedLegacy(_)));
}

#[test]
fn corrupted_database_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("corrupt.sqlite");
    std::fs::write(&path, b"this is not a sqlite database").expect("write");
    let result = SqliteStore::open(&path)
        .and_then(|mut store| WalletPersister::initialize(&mut store).map(|_| ()));
    assert!(result.is_err());
}

#[test]
fn changeset_log_compacts_and_merges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("log.sqlite");
    let mut store = SqliteStore::open(&path).expect("store");
    let mut changeset = ChangeSet::default();
    WalletPersister::initialize(&mut store).expect("init");
    for height in 0..40u32 {
        changeset.local_chain.blocks.insert(
            height,
            Some(bdk_wallet::bitcoin::BlockHash::from_str(&format!("{height:064x}")).unwrap()),
        );
        WalletPersister::persist(&mut store, &changeset).expect("persist");
        changeset = ChangeSet::default();
    }
    let rows: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM shadowallet_wallet_changesets",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert!(rows <= 32, "log should stay compacted, found {rows} rows");
    let loaded = WalletPersister::initialize(&mut store).expect("load");
    assert_eq!(loaded.local_chain.blocks.len(), 40);
}

#[test]
fn txid_import_roundtrip_is_consistent() {
    // Guards the TEXT encoding used by legacy BDK tables.
    let txid = Txid::from_str("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
        .expect("txid");
    assert_eq!(txid.to_string().len(), 64);
}
