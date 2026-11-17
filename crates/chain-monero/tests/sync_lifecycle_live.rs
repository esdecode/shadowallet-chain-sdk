//! Synchronization lifecycle against a REAL public Monero stagenet node (ignored by default, needs internet).
//!
//! Uses a disposable stagenet wallet that owns test coins: `XMR_TEST_PHRASE` (BIP-39 words, never printed) and
//! `XMR_RESTORE` (a height shortly before its first receipt). Proves that
//!  * cooperative cancel + resume, repeated, ends in exactly the state an uninterrupted scan reaches;
//!  * a process killed in the middle of a scan (TerminateProcess / SIGKILL, no cleanup of any kind) leaves an intact
//!    database, resumes from its checkpoint and ends in exactly the same state, without duplicate history.
//!
//! cargo test -p shadowallet-chain-monero --test sync_lifecycle_live -- --ignored --nocapture --test-threads=1
//! The same test binary is pushed to Android (`cargo ndk ... test --no-run`) and run with `adb shell`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use shadowallet_chain_monero::*;

const NODES: [&str; 2] = [
    "http://node.sethforprivacy.com:38089",
    "http://stagenet.xmr-tw.org:38081",
];

fn restore() -> u64 {
    std::env::var("XMR_RESTORE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_250_750)
}

/// Fixed scan target: well inside the chain (no reorg risk) and, when `XMR_SPAN` is set, at most that many blocks after the
/// restore height (a short run on a slow public node that still contains the wallet's first receipts).
fn scan_target(tip: u64) -> u64 {
    let deep = tip - 12;
    match std::env::var("XMR_SPAN")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        Some(span) => deep.min(restore() + span),
        None => deep,
    }
}

fn account() -> MoneroAccount {
    let phrase =
        std::env::var("XMR_TEST_PHRASE").expect("XMR_TEST_PHRASE (disposable stagenet wallet)");
    let m = bip39::Mnemonic::parse(phrase.trim()).unwrap();
    MoneroAccount::from_seed(Network::Stagenet, &m.to_seed(""), 0).unwrap()
}

async fn node() -> Node {
    if let Ok(url) = std::env::var("XMR_NODE") {
        return connect(STAGENET, &url, None).await.unwrap();
    }
    for url in NODES {
        if let Ok(n) = connect(STAGENET, url, None).await {
            return n;
        }
    }
    panic!("no stagenet node reachable");
}

fn open_store(path: &Path, acct: &MoneroAccount) -> MoneroStore {
    let store = MoneroStore::open(path).unwrap();
    store
        .register_account(
            "monero-stagenet",
            &acct.primary_address().to_string(),
            restore(),
        )
        .unwrap();
    store
}

/// Everything a user can observe, in a canonical order, as text (no key material is part of it).
fn snapshot(store: &MoneroStore) -> String {
    let mut outputs: Vec<String> = store
        .outputs()
        .unwrap()
        .iter()
        .map(|o| {
            format!(
                "{}:{}:{}:{}:{:?}",
                hex(&o.txid),
                o.index_in_tx,
                o.amount,
                o.height,
                o.spent_in.map(|t| hex(&t))
            )
        })
        .collect();
    outputs.sort();
    let mut history: Vec<String> = store
        .history(10_000)
        .unwrap()
        .iter()
        .map(|t| {
            format!(
                "{}:{}:{}:{}:{:?}:{}",
                hex(&t.txid),
                t.direction,
                t.amount,
                t.fee,
                t.height,
                t.status
            )
        })
        .collect();
    history.sort();
    let unique: std::collections::BTreeSet<_> = history
        .iter()
        .map(|h| h.split(':').next().unwrap().to_owned())
        .collect();
    assert_eq!(
        unique.len(),
        history.len(),
        "no duplicate transaction in the history"
    );
    format!(
        "scanned={} balance={:?} outputs={outputs:?} history={history:?}",
        store.scanned_height().unwrap(),
        balance(store).unwrap()
    )
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Scan until `target` (a fixed height, so a reference and an interrupted scan stop at the same block).
async fn scan_to(
    store: &MoneroStore,
    acct: &MoneroAccount,
    node: &Node,
    target: u64,
    cancel: &AtomicBool,
) -> SyncReport {
    let mut last = SyncReport::default();
    loop {
        let done = store.scanned_height().unwrap();
        if done >= target as i64 {
            return last;
        }
        let max = (target as i64 - done) as usize;
        // A node that keeps failing after the SDK's own retries is reported as an error with the checkpoint intact; the
        // user's "Retry" is modelled here (bounded), and the test fails only if the node stays down.
        let mut failures = 0;
        last = loop {
            match sync_cancellable(store, acct, node, max.min(400), cancel).await {
                Ok(report) => break report,
                Err(error) => {
                    failures += 1;
                    println!(
                        "node error #{failures} (state intact, scanned {}): {error}",
                        store.scanned_height().unwrap()
                    );
                    assert!(failures <= 4, "the node stays unreachable");
                    assert!(store.integrity_ok().unwrap());
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        };
        if last.cancelled {
            return last;
        }
    }
}

#[tokio::test]
#[ignore = "network, needs XMR_TEST_PHRASE"]
async fn cancel_and_resume_cycles_match_an_uninterrupted_scan() {
    let acct = account();
    let node = node().await;
    let target = scan_target(tip(&node).await.unwrap()); // fixed, well inside the chain (no reorg risk)
    let dir = tempfile::tempdir().unwrap();

    let reference = open_store(&dir.path().join("reference.db"), &acct);
    scan_to(&reference, &acct, &node, target, &AtomicBool::new(false)).await;
    let want = snapshot(&reference);
    println!("reference ready, scanned to {target}");

    let cycled = open_store(&dir.path().join("cycled.db"), &acct);
    let mut cancels = 0;
    let mut checkpoints: Vec<i64> = Vec::new();
    for round in 0u64.. {
        if cycled.scanned_height().unwrap() >= target as i64 {
            break;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let stopper = cancel.clone();
        let delay = 400 + (round % 3) * 700; // 0.4 s, 1.1 s, 1.8 s
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            stopper.store(true, Ordering::Relaxed);
        });
        let r = scan_to(&cycled, &acct, &node, target, &cancel).await;
        handle.abort();
        let now = cycled.scanned_height().unwrap();
        if let Some(prev) = checkpoints.last() {
            assert!(now >= *prev, "the checkpoint never moves backwards");
        }
        checkpoints.push(now);
        if r.cancelled {
            cancels += 1;
        }
        assert!(round < 400, "scan did not progress");
    }
    println!("cancelled {cancels} times, checkpoints {checkpoints:?}");
    assert!(cancels >= 2, "the test must actually interrupt the scan");
    assert!(cycled.integrity_ok().unwrap());
    assert_eq!(
        snapshot(&cycled),
        want,
        "cancel/resume cycles end exactly where an uninterrupted scan ends"
    );
    if std::env::var("XMR_EXPECT_FUNDS").is_ok() {
        assert!(
            !cycled.history(10).unwrap().is_empty(),
            "the funded wallet has history"
        );
    }
}

/// Child process of the kill test: scans forever (until it is killed).
#[tokio::test]
#[ignore = "child process of killed_process_resumes_without_loss"]
async fn scan_child() {
    let Ok(path) = std::env::var("XMR_CHILD_DB") else {
        return;
    };
    let acct = account();
    let node = node().await;
    let store = open_store(&PathBuf::from(path), &acct);
    let never = AtomicBool::new(false);
    loop {
        let done = store.scanned_height().unwrap();
        let target = std::env::var("XMR_TARGET").unwrap().parse::<i64>().unwrap();
        if done >= target {
            return;
        }
        // never past the target, so the victim and the reference stop at the same block
        let step = (target - done).min(50) as usize;
        sync_cancellable(&store, &acct, &node, step, &never)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "network, needs XMR_TEST_PHRASE"]
async fn killed_process_resumes_without_loss() {
    let acct = account();
    let node = node().await;
    let target = scan_target(tip(&node).await.unwrap());
    let dir = tempfile::tempdir().unwrap();

    let reference = open_store(&dir.path().join("reference.db"), &acct);
    scan_to(&reference, &acct, &node, target, &AtomicBool::new(false)).await;
    let want = snapshot(&reference);

    let victim = dir.path().join("victim.db");
    let exe = std::env::current_exe().unwrap();
    let mut last_checkpoint = i64::MIN;
    // A slow public node needs proportionally longer between kills (`XMR_KILL_SCALE`) for the child to commit anything.
    let scale = std::env::var("XMR_KILL_SCALE")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1);
    for (i, wait_ms) in [2500u64, 4000, 1500, 6000]
        .into_iter()
        .map(|w| w * scale)
        .enumerate()
    {
        let mut child = Command::new(&exe)
            .args([
                "--ignored",
                "--exact",
                "scan_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("XMR_CHILD_DB", &victim)
            .env("XMR_TARGET", target.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        // Hard kill: TerminateProcess on Windows, SIGKILL on Android/Linux. No cleanup code can run in the child.
        child.kill().unwrap();
        child.wait().unwrap();
        let store = open_store(&victim, &acct);
        assert!(
            store.integrity_ok().unwrap(),
            "database intact after kill #{i}"
        );
        let checkpoint = store.scanned_height().unwrap();
        assert!(
            checkpoint >= last_checkpoint,
            "checkpoint never moves backwards (kill #{i})"
        );
        println!("kill #{i} after {wait_ms} ms: checkpoint {checkpoint}");
        last_checkpoint = checkpoint;
        snapshot(&store); // asserts no duplicate history so far
    }
    assert!(
        last_checkpoint > restore() as i64,
        "the victim made progress before it was killed"
    );
    let victim_store = open_store(&victim, &acct);
    scan_to(&victim_store, &acct, &node, target, &AtomicBool::new(false)).await;
    assert!(victim_store.integrity_ok().unwrap());
    assert_eq!(
        snapshot(&victim_store),
        want,
        "a scan killed four times ends exactly where an uninterrupted scan ends"
    );
}
