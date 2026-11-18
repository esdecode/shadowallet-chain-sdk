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

#[test]
fn definitive_rejection_frees_the_nonce_and_the_hash() {
    let store = EvmStore::open_in_memory().unwrap();
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    let tx = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    store.mark_signed(tx.id, "0xabc", "0x01").unwrap();
    store.mark_rejected(tx.id, "insufficient funds").unwrap();
    assert_eq!(store.next_nonce(ANVIL.chain_id, ADDR).unwrap(), Some(0));
    // The identical retry signs to the same hash: it must not collide with the failed row.
    let again = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    assert_eq!(again.nonce, 0);
    store.mark_signed(again.id, "0xabc", "0x01").unwrap();
    // A pending (accepted) row can never be rejected away.
    store.mark_broadcast(again.id, "0xabc", "0x01").unwrap();
    assert!(store.mark_rejected(again.id, "late").is_err());
}

#[test]
fn rejection_keeps_the_nonce_when_a_later_row_is_active() {
    let store = EvmStore::open_in_memory().unwrap();
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    let first = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    let second = store
        .reserve_nonce(ANVIL.chain_id, ADDR, 0, &draft())
        .unwrap();
    assert_eq!((first.nonce, second.nonce), (0, 1));
    store.mark_signed(first.id, "0x01", "0x01").unwrap();
    store.mark_rejected(first.id, "rejected").unwrap();
    assert_eq!(store.next_nonce(ANVIL.chain_id, ADDR).unwrap(), Some(2));
}

use shadowallet_chain_evm::CancelOutcome;

fn reserve(store: &EvmStore, network: u64) -> (i64, u64) {
    let r = store
        .reserve_nonce(ANVIL.chain_id, ADDR, network, &draft())
        .unwrap();
    (r.id, r.nonce)
}

fn status_of(store: &EvmStore, id: i64) -> String {
    store
        .history(ANVIL.chain_id, ADDR, 100, None)
        .unwrap()
        .into_iter()
        .find(|r| r.id == id)
        .unwrap()
        .status
}

fn open_store() -> EvmStore {
    let store = EvmStore::open_in_memory().unwrap();
    store.register_account(ANVIL.chain_id, ADDR).unwrap();
    store
}

#[test]
fn cancel_before_signing_releases_the_nonce_and_is_idempotent() {
    let store = open_store();
    let (id, nonce) = reserve(&store, 0);
    assert_eq!(nonce, 0);
    assert_eq!(
        store.cancel_reservation(id).unwrap(),
        CancelOutcome::Released
    );
    assert_eq!(
        store.cancel_reservation(id).unwrap(),
        CancelOutcome::AlreadyReleased
    );
    assert_eq!(
        store.cancel_reservation(9999).unwrap(),
        CancelOutcome::NotFound
    );
    assert_eq!(
        reserve(&store, 0).1,
        0,
        "the released nonce is handed out again"
    );
}

#[test]
fn a_cancelled_reservation_can_never_be_signed() {
    let store = open_store();
    let (id, _) = reserve(&store, 0);
    store.cancel_reservation(id).unwrap();
    assert!(
        store.mark_signed(id, "0x01", "0x01").is_err(),
        "sign after cancel must fail"
    );
    assert!(store.mark_broadcast(id, "0x01", "0x01").is_err());
    assert_eq!(status_of(&store, id), "failed");
}

#[test]
fn a_signed_or_later_reservation_is_never_cancelled() {
    let store = open_store();
    let (signed, _) = reserve(&store, 0);
    let (unknown, _) = reserve(&store, 0);
    let (pending, _) = reserve(&store, 0);
    let (confirmed, _) = reserve(&store, 0);
    store.mark_signed(signed, "0xa1", "0x01").unwrap();
    store.mark_signed(unknown, "0xa2", "0x02").unwrap();
    store.mark_broadcast_unknown(unknown, "timeout").unwrap();
    store.mark_signed(pending, "0xa3", "0x03").unwrap();
    store.mark_broadcast(pending, "0xa3", "0x03").unwrap();
    store.mark_receipt(confirmed, 5, true).unwrap();
    for (id, expect) in [
        (signed, "signed"),
        (unknown, "broadcast_unknown"),
        (pending, "pending"),
        (confirmed, "confirmed"),
    ] {
        assert_eq!(
            store.cancel_reservation(id).unwrap(),
            CancelOutcome::Retained(expect.to_owned())
        );
        assert_eq!(status_of(&store, id), expect, "state untouched");
    }
}

#[test]
fn cancelling_a_lower_nonce_leaves_a_hole_that_is_filled_not_skipped() {
    let store = open_store();
    let (a, na) = reserve(&store, 0);
    let (_b, nb) = reserve(&store, 0);
    assert_eq!((na, nb), (0, 1));
    store.cancel_reservation(a).unwrap();
    assert_eq!(reserve(&store, 0).1, 0, "the hole at 0 is filled first");
    assert_eq!(
        reserve(&store, 0).1,
        2,
        "then allocation continues above the stack"
    );
}

#[test]
fn holes_below_the_network_nonce_and_hash_bearing_rows_are_never_reused() {
    let store = open_store();
    let (a, _) = reserve(&store, 0);
    store.cancel_reservation(a).unwrap();
    assert_eq!(reserve(&store, 5).1, 5, "the network already consumed 0..4");
    // A failed row that ever carried a hash keeps its nonce protected.
    let store = open_store();
    let (a, _) = reserve(&store, 0);
    let (_b, _) = reserve(&store, 0);
    store.mark_signed(a, "0xdead", "0x01").unwrap();
    store.mark_failed(a, "unclear").unwrap();
    assert_eq!(
        reserve(&store, 0).1,
        2,
        "nonce 0 may be on the network: not reused"
    );
}

#[test]
fn release_abandoned_frees_only_unsigned_rows_and_honours_keep() {
    let store = open_store();
    let (kept, _) = reserve(&store, 0);
    let (orphan, _) = reserve(&store, 0);
    let (signed, _) = reserve(&store, 0);
    let (unknown, _) = reserve(&store, 0);
    store.mark_signed(signed, "0xb1", "0x01").unwrap();
    store.mark_signed(unknown, "0xb2", "0x02").unwrap();
    store.mark_broadcast_unknown(unknown, "reset").unwrap();
    assert_eq!(
        store
            .release_abandoned(ANVIL.chain_id, ADDR, &[kept])
            .unwrap(),
        1
    );
    assert_eq!(status_of(&store, kept), "reserved");
    assert_eq!(status_of(&store, orphan), "failed");
    assert_eq!(status_of(&store, signed), "signed");
    assert_eq!(status_of(&store, unknown), "broadcast_unknown");
    assert_eq!(
        store
            .release_abandoned(ANVIL.chain_id, ADDR, &[kept])
            .unwrap(),
        0
    );
    assert_eq!(
        reserve(&store, 0).1,
        1,
        "the abandoned nonce 1 is reused, 2 and 3 stay protected"
    );
}

#[test]
fn nonce_state_is_separate_per_chain_and_per_address() {
    let store = open_store();
    store.register_account(1, ADDR).unwrap();
    let other = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
    store.register_account(ANVIL.chain_id, other).unwrap();
    let (a, _) = reserve(&store, 0);
    let on_other_chain = store.reserve_nonce(1, ADDR, 0, &draft()).unwrap();
    let other_address = store
        .reserve_nonce(ANVIL.chain_id, other, 0, &draft())
        .unwrap();
    assert_eq!((on_other_chain.nonce, other_address.nonce), (0, 0));
    store.cancel_reservation(a).unwrap();
    assert_eq!(store.release_abandoned(1, ADDR, &[]).unwrap(), 1);
    assert_eq!(
        store.release_abandoned(ANVIL.chain_id, other, &[]).unwrap(),
        1
    );
    assert_eq!(status_of(&store, a), "failed");
}
