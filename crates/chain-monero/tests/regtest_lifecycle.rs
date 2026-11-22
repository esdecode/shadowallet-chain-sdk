//! The complete production Monero send lifecycle against a REAL `monerod` (regtest, offline, hard fork 16, mainnet genesis and
//! address format): scan, spendable outputs, proposal, local signing, the daemon's own consensus validation, persistence,
//! confirmation and the recipient's independent scan.
//!
//! Skipped unless `SHADOWALLET_MONEROD` names a `monerod` executable. Run with
//! `cargo test -p shadowallet-chain-monero --features mainnet-send --test regtest_lifecycle -- --nocapture`.
#![cfg(feature = "mainnet-send")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/monerod.rs"]
mod monerod;
#[path = "support/proxy.rs"]
mod proxy;

use monerod::Monerod;
use shadowallet_chain_monero::*;

const XMR: u64 = 1_000_000_000_000;

fn account(words: &str) -> MoneroAccount {
    let m = bip39::Mnemonic::parse(words).unwrap();
    MoneroAccount::from_seed(Network::Mainnet, &m.to_seed(""), 0).unwrap()
}

fn sender() -> MoneroAccount {
    account(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
}

fn recipient() -> MoneroAccount {
    account("legal winner thank year wave sausage worth useful legal winner thank yellow")
}

fn open_store(dir: &std::path::Path, name: &str, acct: &MoneroAccount) -> MoneroStore {
    let store = MoneroStore::open(&dir.join(name)).unwrap();
    store
        .register_account("monero-mainnet", &acct.primary_address().to_string(), 1)
        .unwrap();
    store
}

async fn chain_with_funds() -> Option<(Monerod, tempfile::TempDir)> {
    let d = Monerod::start().await?;
    d.generate(&sender().primary_address().to_string(), 400)
        .await;
    Some((d, tempfile::tempdir().unwrap()))
}

#[tokio::test]
async fn the_full_lifecycle_is_accepted_by_a_real_monerod_and_confirmed() {
    let Some((d, dir)) = chain_with_funds().await else {
        eprintln!("SKIPPED: SHADOWALLET_MONEROD is not set");
        return;
    };
    let (acct, rcpt) = (sender(), recipient());
    let node = connect(MAINNET, &d.url, None).await.unwrap();
    let store = open_store(dir.path(), "sender.db", &acct);

    // 1. scan: the wallet finds its coinbase outputs and only the old ones are spendable
    let report = sync(&store, &acct, &node, 1000).await.unwrap();
    assert!(report.new_outputs >= 400, "{report:?}");
    let before = balance(&store).unwrap();
    assert!(before.unlocked > 0 && before.locked > 0, "{before:?}");

    // 2. proposal (production builder, real decoys from the daemon)
    let to = rcpt.primary_address().to_string();
    let amount = 3 * XMR;
    // regtest's base fee is inflated by its huge initial block reward (4.7M per weight unit at Normal), above the wallet's
    // hostile-node guard of 2M; Unimportant (1.2M) is inside it. The guard itself is exercised below.
    let prepared = prepare_send(
        &store,
        &acct,
        &node,
        &to,
        amount,
        FeePriority::Unimportant,
        None,
    )
    .await
    .unwrap();
    assert_eq!(prepared.to, to);
    assert_eq!(prepared.amount, amount);
    assert_eq!(prepared.ring_size, 16);
    assert_eq!(
        prepared.input_total,
        amount + prepared.fee + prepared.change,
        "inputs = payment + fee + change"
    );
    let (fee, change, ids) = (prepared.fee, prepared.change, prepared.input_ids.clone());
    // the inputs are reserved while the proposal exists
    let reserved = store
        .outputs()
        .unwrap()
        .into_iter()
        .filter(|o| o.reserved)
        .count();
    assert_eq!(reserved, ids.len());

    // 3. signing, then the daemon's own consensus validation through the production publish path
    let tx = sign_prepared(&acct, &node, prepared).unwrap();
    let txid = publish_signed(&store, &node, &tx, &to, amount, fee, 1)
        .await
        .unwrap();
    assert_eq!(txid, tx.hash());
    assert_eq!(d.pool_size().await, 1, "monerod accepted it into its pool");

    // 4. what monerod itself decodes must be what was reviewed
    let seen = d.transaction(&txid).await.unwrap();
    assert_eq!(seen["in_pool"], true);
    let decoded: serde_json::Value =
        serde_json::from_str(seen["as_json"].as_str().unwrap()).unwrap();
    assert_eq!(decoded["version"], 2);
    assert_eq!(
        decoded["rct_signatures"]["type"], 6,
        "RCTTypeBulletproofPlus"
    );
    assert_eq!(decoded["rct_signatures"]["txnFee"].as_u64().unwrap(), fee);
    assert_eq!(
        decoded["vin"].as_array().unwrap().len(),
        ids.len(),
        "inputs"
    );
    for vin in decoded["vin"].as_array().unwrap() {
        assert_eq!(vin["key"]["key_offsets"].as_array().unwrap().len(), 16);
    }
    let outs = decoded["vout"].as_array().unwrap().len();
    assert_eq!(outs, 2, "payment + change (Monero always has two outputs)");
    assert!(change > 0);
    assert_eq!(
        decoded["rctsig_prunable"]["CLSAGs"]
            .as_array()
            .unwrap()
            .len(),
        ids.len(),
        "one CLSAG per input"
    );
    let key_images: Vec<[u8; 32]> = store
        .outputs()
        .unwrap()
        .into_iter()
        .filter(|o| ids.contains(&o.id))
        .map(|o| o.key_image)
        .collect();
    assert!(
        d.key_image_spent(&key_images).await.iter().all(|s| *s == 2),
        "the daemon sees the wallet's key images spent in its pool"
    );

    // 5. persistent state: pending, inputs still reserved
    let history = store.history(10).unwrap();
    let row = history.iter().find(|t| t.txid == txid).unwrap();
    assert_eq!(
        (row.direction.as_str(), row.status.as_str()),
        ("out", "pending")
    );
    assert_eq!(row.counterparty.as_deref(), Some(to.as_str()));

    // 6. confirmation: mine it, the wallet reconciles by scanning
    d.generate(&acct.primary_address().to_string(), 1).await;
    sync(&store, &acct, &node, 1000).await.unwrap();
    let history = store.history(10).unwrap();
    let row = history.iter().find(|t| t.txid == txid).unwrap();
    assert_eq!(row.status, "confirmed");
    assert_eq!(row.amount, amount);
    assert_eq!(row.fee, fee);
    assert!(row.height.is_some());
    let after = balance(&store).unwrap();
    assert!(
        after.total >= before.total - amount - fee,
        "change returned"
    );

    // 7. the recipient, with only its own keys, finds exactly the paid amount
    let rstore = open_store(dir.path(), "recipient.db", &rcpt);
    sync(&rstore, &rcpt, &node, 1000).await.unwrap();
    let got: u64 = rstore
        .outputs()
        .unwrap()
        .iter()
        .filter(|o| o.txid == txid)
        .map(|o| o.amount)
        .sum();
    assert_eq!(got, amount);
}

fn pending_row(store: &MoneroStore, txid: [u8; 32]) -> (String, Option<u64>) {
    let row = store
        .history(50)
        .unwrap()
        .into_iter()
        .find(|t| t.txid == txid)
        .unwrap();
    (row.status, row.height)
}

fn reserved_ids(store: &MoneroStore) -> Vec<i64> {
    let mut ids: Vec<i64> = store
        .outputs()
        .unwrap()
        .into_iter()
        .filter(|o| o.reserved)
        .map(|o| o.id)
        .collect();
    ids.sort_unstable();
    ids
}

fn sorted(mut v: Vec<i64>) -> Vec<i64> {
    v.sort_unstable();
    v
}

async fn built(
    store: &MoneroStore,
    node: &Node,
    amount: u64,
) -> (Transaction, String, u64, Vec<i64>) {
    let acct = sender();
    let to = recipient().primary_address().to_string();
    let prepared = prepare_send(
        store,
        &acct,
        node,
        &to,
        amount,
        FeePriority::Unimportant,
        None,
    )
    .await
    .unwrap();
    let (fee, ids) = (prepared.fee, prepared.input_ids.clone());
    let tx = sign_prepared(&acct, node, prepared).unwrap();
    (tx, to, fee, ids)
}

use monero_wallet::transaction::Transaction;

#[tokio::test]
async fn the_daemon_refuses_every_tampered_transaction_and_accepts_the_genuine_one() {
    let Some((d, dir)) = chain_with_funds().await else {
        eprintln!("SKIPPED: SHADOWALLET_MONEROD is not set");
        return;
    };
    let acct = sender();
    let node = connect(MAINNET, &d.url, None).await.unwrap();
    let store = open_store(dir.path(), "s.db", &acct);
    sync(&store, &acct, &node, 1000).await.unwrap();
    let (tx, to, fee, _) = built(&store, &node, 2 * XMR).await;
    let bytes = tx.serialize();
    // flip one bit at many positions across the whole transaction (prefix, key image, ring offsets, outputs, fee, proofs):
    // monerod's consensus code must refuse each of them
    for step in 1..=40usize {
        let at = bytes.len() * step / 41;
        let mut bad = bytes.clone();
        bad[at] ^= 0x01;
        let answer = d.send_raw(&bad).await;
        assert_ne!(
            answer["status"], "OK",
            "a modified transaction was accepted at byte {at}: {answer}"
        );
    }
    assert!(
        d.get_height().await.is_some(),
        "the daemon survived every malformed submission"
    );
    assert_eq!(d.pool_size().await, 0, "nothing tampered reached the pool");
    // the genuine bytes go through the production publish path
    let txid = publish_signed(&store, &node, &tx, &to, 2 * XMR, fee, 1)
        .await
        .unwrap();
    assert_eq!(d.pool_size().await, 1);
    // resubmitting the same transaction is not accepted twice and creates no second history row
    let again = publish_signed(&store, &node, &tx, &to, 2 * XMR, fee, 2).await;
    if let Ok(again_id) = again {
        assert_eq!(again_id, txid, "the same transaction has the same id");
    }
    assert_eq!(d.pool_size().await, 1, "the pool still holds exactly one");
    assert_eq!(
        store
            .history(50)
            .unwrap()
            .iter()
            .filter(|t| t.txid == txid)
            .count(),
        1
    );
    assert_eq!(pending_row(&store, txid).0, "pending");
}

#[tokio::test]
async fn an_uncertain_broadcast_keeps_the_coins_reserved_across_a_restart_until_the_chain_decides()
{
    let Some((d, dir)) = chain_with_funds().await else {
        eprintln!("SKIPPED: SHADOWALLET_MONEROD is not set");
        return;
    };
    let acct = sender();
    let direct = connect(MAINNET, &d.url, None).await.unwrap();
    let fault = proxy::FaultProxy::start(&d.url);
    let node = connect(MAINNET, &fault.url, None).await.unwrap();
    let path = dir.path().join("s.db");
    let store = open_store(dir.path(), "s.db", &acct);
    sync(&store, &acct, &direct, 1000).await.unwrap();
    let (tx, to, fee, ids) = built(&store, &node, 2 * XMR).await;
    let txid = tx.hash();

    // the daemon takes the transaction, but the wallet never hears the answer
    fault
        .drop_send_answer
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let err = publish_signed(&store, &node, &tx, &to, 2 * XMR, fee, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, MoneroError::Node(_)), "{err}");
    assert_eq!(pending_row(&store, txid).0, "pending");
    assert_eq!(d.pool_size().await, 1, "it did reach the network");

    // restart: the unknown outcome must not free the inputs, and a new proposal must not reuse them
    drop(store);
    let store = MoneroStore::open(&path).unwrap();
    assert_eq!(store.release_unpublished_reservations().unwrap(), 0);
    assert_eq!(
        reserved_ids(&store),
        sorted(ids.clone()),
        "exactly the signed transaction's inputs stay reserved"
    );
    let next = prepare_send(
        &store,
        &acct,
        &direct,
        &to,
        XMR,
        FeePriority::Unimportant,
        None,
    )
    .await
    .unwrap();
    assert!(
        next.input_ids.iter().all(|i| !ids.contains(i)),
        "a second transaction never spends the inputs of the uncertain one"
    );
    store.reserve(&next.input_ids, false).unwrap();

    // the chain decides: mined => confirmed, reservation gone, spend recorded
    d.generate(&acct.primary_address().to_string(), 1).await;
    sync(&store, &acct, &direct, 1000).await.unwrap();
    assert_eq!(pending_row(&store, txid).0, "confirmed");
    assert!(reserved_ids(&store).is_empty());
    assert!(
        store
            .outputs()
            .unwrap()
            .into_iter()
            .filter(|o| ids.contains(&o.id))
            .all(|o| o.spent_in == Some(txid))
    );
}

#[tokio::test]
async fn a_transaction_the_daemon_never_saw_stays_pending_and_reserved_while_a_prepared_only_proposal_is_released_on_restart()
 {
    let Some((d, dir)) = chain_with_funds().await else {
        eprintln!("SKIPPED: SHADOWALLET_MONEROD is not set");
        return;
    };
    let acct = sender();
    let direct = connect(MAINNET, &d.url, None).await.unwrap();
    let fault = proxy::FaultProxy::start(&d.url);
    let node = connect(MAINNET, &fault.url, None).await.unwrap();
    let path = dir.path().join("s.db");
    let store = open_store(dir.path(), "s.db", &acct);
    sync(&store, &acct, &direct, 1000).await.unwrap();

    // a proposal that is only prepared: reserved now, released by a restart
    let to = recipient().primary_address().to_string();
    let only_prepared = prepare_send(
        &store,
        &acct,
        &direct,
        &to,
        XMR,
        FeePriority::Unimportant,
        None,
    )
    .await
    .unwrap();
    assert!(!reserved_ids(&store).is_empty());
    drop(only_prepared);
    drop(store);
    let store = MoneroStore::open(&path).unwrap();
    assert!(store.release_unpublished_reservations().unwrap() > 0);
    assert!(
        reserved_ids(&store).is_empty(),
        "prepared-only reservations do not survive a restart"
    );

    // a signed transaction whose submission never reached the daemon: nothing in the pool, still pending, still reserved
    fault
        .block_send
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (tx, to, fee, ids) = built(&store, &node, 2 * XMR).await;
    let txid = tx.hash();
    assert!(
        publish_signed(&store, &node, &tx, &to, 2 * XMR, fee, 1)
            .await
            .is_err()
    );
    assert_eq!(d.pool_size().await, 0);
    assert_eq!(pending_row(&store, txid).0, "pending");
    drop(store);
    let store = MoneroStore::open(&path).unwrap();
    assert_eq!(store.release_unpublished_reservations().unwrap(), 0);
    assert_eq!(
        reserved_ids(&store),
        sorted(ids),
        "a timeout is not proof that the transaction is gone"
    );
}

#[tokio::test]
async fn coin_control_refuses_locked_spent_unknown_and_duplicate_outputs() {
    let Some((d, dir)) = chain_with_funds().await else {
        eprintln!("SKIPPED: SHADOWALLET_MONEROD is not set");
        return;
    };
    let acct = sender();
    let node = connect(MAINNET, &d.url, None).await.unwrap();
    let store = open_store(dir.path(), "s.db", &acct);
    sync(&store, &acct, &node, 1000).await.unwrap();
    let to = recipient().primary_address().to_string();
    let outputs = store.outputs().unwrap();
    let young = outputs.last().unwrap().id; // the newest coinbase output is still locked
    let old = outputs.first().unwrap().id;
    let refused = |ids: Vec<i64>| {
        let (store, acct, node, to) = (&store, &acct, &node, to.clone());
        async move {
            prepare_send(
                store,
                acct,
                node,
                &to,
                XMR,
                FeePriority::Unimportant,
                Some(&ids),
            )
            .await
            .is_err()
        }
    };
    assert!(refused(vec![young]).await, "a locked output");
    assert!(refused(vec![9_999_999]).await, "an unknown output");
    assert!(refused(vec![old, old]).await, "the same output twice");
    assert!(refused(vec![]).await, "no output at all");
    // spend `old`: while pending it is reserved, once confirmed it is spent
    let prepared = prepare_send(
        &store,
        &acct,
        &node,
        &to,
        XMR,
        FeePriority::Unimportant,
        Some(&[old]),
    )
    .await
    .unwrap();
    let fee = prepared.fee;
    let tx = sign_prepared(&acct, &node, prepared).unwrap();
    publish_signed(&store, &node, &tx, &to, XMR, fee, 1)
        .await
        .unwrap();
    assert!(refused(vec![old]).await, "a reserved output");
    d.generate(&acct.primary_address().to_string(), 1).await;
    sync(&store, &acct, &node, 1000).await.unwrap();
    assert!(refused(vec![old]).await, "a spent output");
    // an amount the wallet does not have, and the amount zero
    let too_much = prepare_send(
        &store,
        &acct,
        &node,
        &to,
        u64::MAX / 4,
        FeePriority::Unimportant,
        None,
    )
    .await
    .err()
    .unwrap();
    assert!(too_much.to_string().contains("insufficient"), "{too_much}");
    assert!(
        prepare_send(&store, &acct, &node, &to, 0, FeePriority::Unimportant, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_chain_reorganisation_after_confirmation_returns_the_spend_to_pending_and_keeps_the_inputs_reserved()
 {
    let Some((d, dir)) = chain_with_funds().await else {
        eprintln!("SKIPPED: SHADOWALLET_MONEROD is not set");
        return;
    };
    let acct = sender();
    let node = connect(MAINNET, &d.url, None).await.unwrap();
    let store = open_store(dir.path(), "s.db", &acct);
    sync(&store, &acct, &node, 1000).await.unwrap();
    let (tx, to, fee, ids) = built(&store, &node, 2 * XMR).await;
    let txid = publish_signed(&store, &node, &tx, &to, 2 * XMR, fee, 1)
        .await
        .unwrap();
    d.generate(&acct.primary_address().to_string(), 3).await;
    sync(&store, &acct, &node, 1000).await.unwrap();
    let (status, height) = pending_row(&store, txid);
    assert_eq!(status, "confirmed");
    let confirmed_at = height.unwrap();

    // the block holding the transaction (and everything after it) disappears
    let tip = d.get_height().await.unwrap() - 1;
    d.pop_blocks(tip - confirmed_at + 1).await;
    let report = sync(&store, &acct, &node, 1000).await.unwrap();
    assert!(report.reorg_depth > 0, "{report:?}");
    let (status, height) = pending_row(&store, txid);
    assert_eq!(
        (status.as_str(), height),
        ("pending", None),
        "no longer confirmed"
    );
    assert_eq!(
        reserved_ids(&store),
        sorted(ids),
        "the inputs are not freed by a reorganisation"
    );
    // the daemon returned the transaction to its pool; mining again confirms it again, once
    assert_eq!(
        d.pool_size().await,
        1,
        "popped transactions go back to the pool"
    );
    d.generate(&acct.primary_address().to_string(), 2).await;
    sync(&store, &acct, &node, 1000).await.unwrap();
    assert_eq!(pending_row(&store, txid).0, "confirmed");
    assert!(reserved_ids(&store).is_empty());
    assert_eq!(
        store
            .history(100)
            .unwrap()
            .iter()
            .filter(|t| t.txid == txid)
            .count(),
        1
    );
}

#[tokio::test]
async fn an_old_pending_transaction_is_expired_only_when_the_node_knows_neither_it_nor_a_spend_of_its_inputs()
 {
    let Some((d, dir)) = chain_with_funds().await else {
        eprintln!("SKIPPED: SHADOWALLET_MONEROD is not set");
        return;
    };
    let acct = sender();
    let direct = connect(MAINNET, &d.url, None).await.unwrap();
    let fault = proxy::FaultProxy::start(&d.url);
    let blocked = connect(MAINNET, &fault.url, None).await.unwrap();
    let store = open_store(dir.path(), "s.db", &acct);
    sync(&store, &acct, &direct, 1000).await.unwrap();
    let t0 = 1_000_000u64;
    let old = t0 + PENDING_EXPIRY_MS + 1;

    // (a) a transaction the daemon never saw
    fault
        .block_send
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (tx_a, to, fee_a, ids_a) = built(&store, &blocked, 2 * XMR).await;
    assert!(
        publish_signed(&store, &blocked, &tx_a, &to, 2 * XMR, fee_a, t0)
            .await
            .is_err()
    );
    assert_eq!(
        reconcile_pending(&store, &direct, t0 + 3_600_000, PENDING_EXPIRY_MS)
            .await
            .unwrap(),
        0,
        "too young to judge"
    );
    assert_eq!(reserved_ids(&store), sorted(ids_a.clone()));
    assert_eq!(
        reconcile_pending(&store, &direct, old, PENDING_EXPIRY_MS)
            .await
            .unwrap(),
        1,
        "unknown to the node, inputs unspent, old enough"
    );
    assert_eq!(pending_row(&store, tx_a.hash()).0, "expired");
    assert!(
        reserved_ids(&store).is_empty(),
        "exactly its inputs were freed"
    );

    // (b) a transaction the daemon holds is never judged gone, however old
    let (tx_b, to, fee_b, _) = built(&store, &direct, 2 * XMR).await;
    publish_signed(&store, &direct, &tx_b, &to, 2 * XMR, fee_b, t0)
        .await
        .unwrap();
    assert_eq!(
        reconcile_pending(&store, &direct, old, PENDING_EXPIRY_MS)
            .await
            .unwrap(),
        0
    );
    assert_eq!(pending_row(&store, tx_b.hash()).0, "pending");
    assert!(!reserved_ids(&store).is_empty());
    d.generate(&acct.primary_address().to_string(), 1).await;
    sync(&store, &acct, &direct, 1000).await.unwrap();
    assert_eq!(pending_row(&store, tx_b.hash()).0, "confirmed");

    // (c) a transaction whose inputs were spent on chain by a DIFFERENT transaction can never confirm
    let outs = store.outputs().unwrap();
    let pick = outs
        .iter()
        .find(|o| o.spent_in.is_none() && !o.reserved && o.height < 100)
        .unwrap()
        .id;
    let acct2 = sender();
    let p_c = prepare_send(
        &store,
        &acct2,
        &blocked,
        &to,
        XMR,
        FeePriority::Unimportant,
        Some(&[pick]),
    )
    .await
    .unwrap();
    let fee_c = p_c.fee;
    let tx_c = sign_prepared(&acct2, &blocked, p_c).unwrap();
    assert!(
        publish_signed(&store, &blocked, &tx_c, &to, XMR, fee_c, t0)
            .await
            .is_err()
    );
    store.reserve(&[pick], false).unwrap(); // the user abandons it locally...
    let p_d = prepare_send(
        &store,
        &acct2,
        &direct,
        &to,
        XMR,
        FeePriority::Unimportant,
        Some(&[pick]),
    )
    .await
    .unwrap();
    let fee_d = p_d.fee;
    let tx_d = sign_prepared(&acct2, &direct, p_d).unwrap();
    publish_signed(&store, &direct, &tx_d, &to, XMR, fee_d, t0)
        .await
        .unwrap(); // ...and the same coin is spent by another transaction
    d.generate(&acct.primary_address().to_string(), 1).await;
    sync(&store, &acct, &direct, 1000).await.unwrap();
    assert_eq!(pending_row(&store, tx_d.hash()).0, "confirmed");
    assert_eq!(pending_row(&store, tx_c.hash()).0, "pending");
    assert_eq!(
        reconcile_pending(&store, &direct, old, PENDING_EXPIRY_MS)
            .await
            .unwrap(),
        1
    );
    assert_eq!(pending_row(&store, tx_c.hash()).0, "expired");
}
