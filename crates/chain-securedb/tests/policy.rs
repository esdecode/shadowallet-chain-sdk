//! Process-wide policy (its own test binary: the registry and the strict switch are global state).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::Path;
use std::sync::Arc;

use shadowallet_chain_securedb as sdb;

fn plain(path: &Path) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('PLAINTEXTMARKER');")
        .unwrap();
}

fn resolver(master: [u8; 32]) -> sdb::Resolver {
    Arc::new(move |info, salt| sdb::derive_db_key(&master, salt, info).map_err(|e| e.to_string()))
}

#[test]
fn resolver_migrates_locks_and_isolates() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("w.uwv");
    let prefix = vault.to_string_lossy().into_owned();
    let other = dir.path().join("w.uwv2.zcash");
    std::fs::create_dir_all(&other).unwrap();
    let store = dir.path().join("w.uwv.zcash");
    std::fs::create_dir_all(&store).unwrap();
    let db = store.join("zcash-testnet-0.sqlite");
    plain(&db);

    // Nothing registered, nothing protected: plain (tests, tools).
    assert!(matches!(sdb::resolve(&db).unwrap(), sdb::Resolved::Plain));

    sdb::register_resolver(&prefix, 1, resolver([7u8; 32]));

    // Another vault whose name merely starts with this prefix is neither covered nor protected by it.
    let stranger = other.join("x.sqlite");
    assert!(matches!(
        sdb::resolve(&stranger).unwrap(),
        sdb::Resolved::Plain
    ));

    // Covered: plaintext is migrated on first open, then opens only with the key.
    let c = sdb::open_resolved(&db).unwrap();
    assert_eq!(
        c.query_row("SELECT x FROM t", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "PLAINTEXTMARKER"
    );
    drop(c);
    let bytes = std::fs::read(&db).unwrap();
    assert!(!bytes.windows(15).any(|w| w == b"PLAINTEXTMARKER"));
    assert!(sdb::has_retained(&db));

    // Two files get different keys.
    let db2 = store.join("zcash-testnet-1.sqlite");
    let k1 = match sdb::resolve(&db).unwrap() {
        sdb::Resolved::Key(k) => k,
        sdb::Resolved::Plain => panic!("must be keyed"),
    };
    let k2 = match sdb::resolve(&db2).unwrap() {
        sdb::Resolved::Key(k) => k,
        sdb::Resolved::Plain => panic!("must be keyed"),
    };
    assert!(sdb::open(&db, &k2, false).is_err());
    assert!(sdb::open(&db, &k1, false).is_ok());

    // Vault locked: the resolver is gone. Nothing under the vault path opens, and above all not as plaintext.
    sdb::unregister_resolver(1);
    assert!(matches!(
        sdb::open_resolved(&db),
        Err(sdb::SecureDbError::NoKey(_))
    ));
    let fresh = store.join("zcash-testnet-9.sqlite");
    assert!(matches!(
        sdb::prepare(&fresh),
        Err(sdb::SecureDbError::NoKey(_))
    ));
    assert!(!fresh.exists(), "no plaintext file may be created");
    // The stranger vault is still unaffected.
    assert!(matches!(
        sdb::resolve(&stranger).unwrap(),
        sdb::Resolved::Plain
    ));

    // Unlocked again: works with the same key.
    sdb::register_resolver(&prefix, 2, resolver([7u8; 32]));
    assert!(sdb::open_resolved(&db).is_ok());
    // A different vault secret under the same path cannot read it.
    sdb::unregister_resolver(2);
    sdb::register_resolver(&prefix, 3, resolver([8u8; 32]));
    assert!(matches!(
        sdb::open_resolved(&db),
        Err(sdb::SecureDbError::KeyMismatchOrCorrupt)
    ));
    sdb::unregister_resolver(3);

    // Strict switch for a process that wants no plaintext anywhere.
    sdb::require_encryption();
    assert!(matches!(
        sdb::resolve(&stranger),
        Err(sdb::SecureDbError::NoKey(_))
    ));
}
