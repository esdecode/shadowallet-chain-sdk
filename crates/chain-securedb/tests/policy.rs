//! Process-wide policy (its own test binary: the policy is global state).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::Path;
use std::sync::Arc;

use shadowallet_chain_securedb as sdb;

fn plain(path: &Path) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('PLAINTEXTMARKER');")
        .unwrap();
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

    // Nothing registered and nothing required: plain.
    assert!(matches!(sdb::resolve(&db).unwrap(), sdb::Resolved::Plain));

    sdb::require_encryption();
    // Required, locked vault: refuse, do not fall back to plaintext.
    assert!(matches!(
        sdb::prepare(&db),
        Err(sdb::SecureDbError::NoKey(_))
    ));
    assert!(
        std::fs::read(&db).unwrap().starts_with(b"SQLite format 3"),
        "file must be untouched"
    );

    let master = [7u8; 32];
    let r: sdb::Resolver = Arc::new(move |info, salt| {
        sdb::derive_db_key(&master, salt, info).map_err(|e| e.to_string())
    });
    sdb::register_resolver(&prefix, 1, r);

    // Another vault whose name merely starts with this prefix is not covered.
    let stranger = other.join("x.sqlite");
    assert!(matches!(
        sdb::resolve(&stranger),
        Err(sdb::SecureDbError::NoKey(_))
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
        _ => panic!(),
    };
    let k2 = match sdb::resolve(&db2).unwrap() {
        sdb::Resolved::Key(k) => k,
        _ => panic!(),
    };
    assert!(sdb::open(&db, &k2, false).is_err());
    assert!(sdb::open(&db, &k1, false).is_ok());

    // Vault locked: the resolver is gone and the database cannot be opened.
    sdb::unregister_resolver(1);
    assert!(matches!(
        sdb::open_resolved(&db),
        Err(sdb::SecureDbError::NoKey(_))
    ));
}
