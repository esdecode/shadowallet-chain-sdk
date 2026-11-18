//! Key rotation and its crash safety (own test binary: the resolver registry is global state).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::sync::Arc;

use shadowallet_chain_securedb as sdb;

const MASTER: [u8; 32] = [9u8; 32];

fn setup(name: &str, owner: u64) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join(format!("{name}.uwv"));
    let store = dir.path().join(format!("{name}.uwv.zcash"));
    std::fs::create_dir_all(&store).unwrap();
    sdb::register_resolver(
        &vault.to_string_lossy(),
        owner,
        Arc::new(|info, salt| sdb::derive_db_key(&MASTER, salt, info).map_err(|e| e.to_string())),
    );
    let db = store.join("z.sqlite");
    let c = sdb::open_resolved(&db).unwrap();
    c.execute_batch("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES(41),(42);")
        .unwrap();
    drop(c);
    (dir, db)
}

fn total(db: &Path) -> i64 {
    sdb::open_resolved(db)
        .unwrap()
        .query_row("SELECT sum(x) FROM t", [], |r| r.get(0))
        .unwrap()
}

fn next_salt(db: &Path) -> PathBuf {
    db.with_file_name("z.sqlite.keysalt.next")
}

#[test]
fn rotation_changes_the_key_and_keeps_the_data() {
    let (_d, db) = setup("a", 101);
    let before = std::fs::read(&db).unwrap();
    assert!(!sdb::salt_path(&db).exists());
    sdb::rotate_key(&db, None).unwrap();
    assert!(sdb::salt_path(&db).exists(), "the new salt is recorded");
    assert_ne!(
        std::fs::read(&db).unwrap(),
        before,
        "every page was rewritten"
    );
    assert_eq!(total(&db), 83);
    // the old key (default salt) no longer opens it
    let old = sdb::derive_db_key(&MASTER, &sdb::default_salt(), "zcash/z.sqlite").unwrap();
    assert!(sdb::open(&db, &old, false).is_err());
    sdb::rotate_key(&db, None).unwrap();
    assert_eq!(total(&db), 83);
}

#[test]
fn a_crash_after_the_proposal_changes_nothing() {
    let (_d, db) = setup("b", 102);
    assert!(sdb::rotate_key(&db, Some(sdb::RotationStep::AfterProposal)).is_err());
    assert!(next_salt(&db).exists());
    // the next open settles it: the database still has its old key, the proposal is dropped
    assert_eq!(total(&db), 83);
    assert!(!next_salt(&db).exists());
    assert!(!sdb::salt_path(&db).exists());
}

#[test]
fn a_crash_after_the_rekey_is_completed_on_the_next_open() {
    let (_d, db) = setup("c", 103);
    assert!(sdb::rotate_key(&db, Some(sdb::RotationStep::AfterRekey)).is_err());
    // the database is at the NEW key while the official salt is still the old one: opening must still work
    assert!(next_salt(&db).exists());
    assert_eq!(total(&db), 83);
    assert!(!next_salt(&db).exists(), "the proposal was committed");
    assert!(sdb::salt_path(&db).exists());
    assert_eq!(total(&db), 83);
}
