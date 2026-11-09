#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use shadowallet_chain_evm::{ANVIL, EvmError, EvmStore, TokenRecord, TransactionDraft};

const ADDR: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

fn draft() -> TransactionDraft {
    TransactionDraft::native("0x0000000000000000000000000000000000000042", "1")
}

#[test]
fn concurrent_reservations_are_unique_and_ordered() {
    let store = Arc::new(EvmStore::open_in_memory().unwrap());
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            (0..10)
                .map(|_| {
                    store
                        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
                        .unwrap()
                        .nonce
                })
                .collect::<Vec<_>>()
        }));
    }
    let mut all: Vec<u64> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    all.sort_unstable();
    assert_eq!(all, (0..80).collect::<Vec<_>>());
    assert_eq!(store.next_nonce(ANVIL.chain_id, ADDR).unwrap(), Some(80));
}

#[test]
fn network_nonce_wins_and_unregistered_account_is_rejected() {
    let store = EvmStore::open_in_memory().unwrap();
    assert_eq!(
        store.reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft()),
        Err(EvmError::UnknownAccount)
    );
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    let first = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 7, &draft())
        .unwrap();
    assert_eq!(first.nonce, 7);
    let second = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 7, &draft())
        .unwrap();
    assert_eq!(second.nonce, 8);
}

#[test]
fn release_only_reclaims_the_highest_never_broadcast_nonce() {
    let store = EvmStore::open_in_memory().unwrap();
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    let a = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    let b = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    assert!(!store.release_nonce(a.id).unwrap());
    assert!(store.release_nonce(b.id).unwrap());
    assert_eq!(store.next_nonce(ANVIL.chain_id, ADDR).unwrap(), Some(1));
    let c = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    assert_eq!(c.nonce, 1);

    store.mark_signed(c.id, "0x01", "0xdead").unwrap();
    store.mark_broadcast(c.id, "0x01", "0xdead").unwrap();
    assert!(!store.release_nonce(c.id).unwrap());
}

#[test]
fn restart_recovers_pending_nonce_and_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evm.sqlite");
    {
        let store = EvmStore::open(&path).unwrap();
        store.register_account(ANVIL.chain_id, ADDR).unwrap();
        let r = store
            .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
            .unwrap();
        store.mark_broadcast(r.id, "0xabc", "0xraw").unwrap();
        store.integrity_check().unwrap();
    }
    let store = EvmStore::open(&path).unwrap();
    assert_eq!(store.next_nonce(ANVIL.chain_id, ADDR).unwrap(), Some(1));
    let next = store.reconcile_nonce(ANVIL.chain_id, ADDR, 0).unwrap();
    assert_eq!(next, 1);
    let history = store.history(ANVIL.chain_id, ADDR, 10, None).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].nonce, 0);
    assert_eq!(history[0].status, "pending");
    assert_eq!(history[0].tx_hash.as_deref(), Some("0xabc"));
    let page = store
        .history(ANVIL.chain_id, ADDR, 10, Some(history[0].id))
        .unwrap();
    assert!(page.is_empty());
}

#[test]
fn replacement_keeps_nonce_and_does_not_advance_next() {
    let store = EvmStore::open_in_memory().unwrap();
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    let first = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    let replacement = store
        .reserve_replacement(ANVIL.chain_id, ADDR, first.nonce, &draft())
        .unwrap();
    assert_eq!(replacement.nonce, first.nonce);
    assert_eq!(store.next_nonce(ANVIL.chain_id, ADDR).unwrap(), Some(1));
    assert_eq!(
        store.reserve_replacement(ANVIL.chain_id, ADDR, 99, &draft()),
        Err(EvmError::NonceConflict)
    );
}

#[test]
fn abandoned_reservations_expire_and_reclaim_the_nonce() {
    let store = EvmStore::open_in_memory().unwrap();
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    let first = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    assert_eq!(store.expire_stale(ANVIL.chain_id, ADDR, 1).unwrap(), 0);
    std::thread::sleep(std::time::Duration::from_millis(2100));
    assert_eq!(store.expire_stale(ANVIL.chain_id, ADDR, 1).unwrap(), 1);
    assert_eq!(store.next_nonce(ANVIL.chain_id, ADDR).unwrap(), Some(0));
    let again = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    assert_eq!(again.nonce, first.nonce);
}

#[test]
fn ambiguous_broadcast_never_releases_the_nonce() {
    let store = EvmStore::open_in_memory().unwrap();
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    let tx = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    store.mark_broadcast_unknown(tx.id, "timeout").unwrap();
    assert!(!store.release_nonce(tx.id).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(store.expire_stale(ANVIL.chain_id, ADDR, 1).unwrap(), 0);
    assert_eq!(store.next_nonce(ANVIL.chain_id, ADDR).unwrap(), Some(1));
    let next = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    assert_eq!(next.nonce, 1);
}

#[test]
fn independent_connections_do_not_reuse_nonces() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.sqlite");
    {
        let store = EvmStore::open(&path).unwrap();
        store.register_account(ANVIL.chain_id, ADDR).unwrap();
    }
    let mut handles = Vec::new();
    for _ in 0..4 {
        let path = path.clone();
        handles.push(std::thread::spawn(move || {
            let store = EvmStore::open(&path).unwrap();
            (0..10)
                .map(|_| {
                    store
                        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
                        .unwrap()
                        .nonce
                })
                .collect::<Vec<_>>()
        }));
    }
    let mut all: Vec<u64> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    all.sort_unstable();
    assert_eq!(all, (0..40).collect::<Vec<_>>());
}

#[test]
fn corrupt_database_is_rejected_and_scope_mismatch_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.sqlite");
    std::fs::write(&path, b"not a sqlite database").unwrap();
    assert!(matches!(EvmStore::open(&path), Err(EvmError::Store(_))));

    let store = EvmStore::open_in_memory().unwrap();
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    assert!(
        store
            .assert_scope(ANVIL.chain_id, "0x00000000000000000000000000000000000000ff")
            .is_err()
    );
    assert!(store.assert_scope(ANVIL.chain_id, ADDR).is_ok());
}

#[test]
fn token_metadata_and_sync_checkpoint_roundtrip() {
    let store = EvmStore::open_in_memory().unwrap();
    store
        .upsert_token(&TokenRecord {
            chain_id: ANVIL.chain_id,
            contract: "0x0000000000000000000000000000000000000001".to_owned(),
            symbol: Some("TST".to_owned()),
            name: Some("Test Token".to_owned()),
            decimals: Some(18),
        })
        .unwrap();
    let tokens = store.tokens(ANVIL.chain_id).unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].symbol.as_deref(), Some("TST"));
    store
        .set_sync_checkpoint(ANVIL.chain_id, ADDR, 100)
        .unwrap();
    assert_eq!(
        store.sync_checkpoint(ANVIL.chain_id, ADDR).unwrap(),
        Some(100)
    );
    store
        .advance_sync_checkpoint(ANVIL.chain_id, ADDR, 90)
        .unwrap();
    assert_eq!(
        store.sync_checkpoint(ANVIL.chain_id, ADDR).unwrap(),
        Some(100)
    );
    store.set_sync_checkpoint(ANVIL.chain_id, ADDR, 80).unwrap();
    assert_eq!(
        store.sync_checkpoint(ANVIL.chain_id, ADDR).unwrap(),
        Some(80)
    );
}
