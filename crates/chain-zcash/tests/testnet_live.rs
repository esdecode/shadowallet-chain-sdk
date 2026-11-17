//! Read-only checks against a public Zcash testnet lightwalletd. Ignored by default (internet needed):
//! `cargo test -p shadowallet-chain-zcash --test testnet_live -- --ignored --nocapture --test-threads=1`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_zcash::*;

const SERVER: &str = "https://testnet.zec.rocks:443";

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        .unwrap()
        .to_seed("")
        .to_vec()
}

#[tokio::test]
#[ignore = "network"]
async fn identity_is_enforced() {
    let (_c, info) = connect(TESTNET, SERVER).await.unwrap();
    println!("server: {info:?}");
    assert_eq!(info.chain_name, "test");
    let err = connect(MAINNET, SERVER).await.err().unwrap();
    assert!(matches!(err, ZcashError::Network(_)), "{err}");
}

#[tokio::test]
#[ignore = "network"]
async fn creates_a_wallet_syncs_and_survives_a_restart() {
    let (mut client, info) = connect(TESTNET, SERVER).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zec.sqlite");
    let mut w = open_wallet(
        TESTNET,
        &path,
        &seed(),
        0,
        &mut client,
        Some(info.block_height.saturating_sub(10)),
    )
    .await
    .unwrap();
    update_tip(&mut w, &mut client).await.unwrap();
    sync(&mut w, &mut client, 100).await.unwrap();
    let b = balances(&w).unwrap();
    println!("balances {b:?}");
    assert!(b.chain_tip >= info.block_height.saturating_sub(5));
    assert!(
        b.fully_scanned + 50 >= b.chain_tip,
        "scanned to near the tip: {b:?}"
    );
    assert_eq!(
        b.orchard_spendable + b.transparent_spendable + b.sapling_total,
        0,
        "a throwaway wallet owns nothing"
    );
    let addr = current_address(&mut w).unwrap();
    assert!(addr.starts_with("utest1"), "{addr}");
    assert_eq!(
        addr,
        current_address(&mut w).unwrap(),
        "the current address is stable"
    );
    let fresh = new_address(&mut w).unwrap();
    assert_ne!(addr, fresh);
    assert!(transparent_address_of(&w).unwrap().starts_with("tm"));
    assert!(history(&w, 10).unwrap().is_empty());
    drop(w);
    // reopen: the same account, the same address, the checkpoint is kept
    let mut w2 = open_wallet(
        TESTNET,
        &path,
        &seed(),
        0,
        &mut client,
        Some(info.block_height.saturating_sub(10)),
    )
    .await
    .unwrap();
    assert_eq!(
        current_address(&mut w2).unwrap(),
        fresh,
        "the most recently generated address is the current one"
    );
    sync(&mut w2, &mut client, 100).await.unwrap();
    assert!(balances(&w2).unwrap().fully_scanned >= b.fully_scanned);
}

// ---------------------------------------------------------------------------------------------------------------
// Synchronization lifecycle (cooperative cancel, resume, killed process, RPC failure). Same ignored/networked setup.
// ZEC_TEST_PHRASE (optional, BIP-39 words of a disposable testnet wallet, never printed) and ZEC_SPAN (blocks behind the
// tip to scan from, default 6000) tune the run.
// ---------------------------------------------------------------------------------------------------------------
mod lifecycle {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::Duration;

    fn lifecycle_seed() -> Vec<u8> {
        match std::env::var("ZEC_TEST_PHRASE") {
            Ok(p) => bip39::Mnemonic::parse(p.trim())
                .unwrap()
                .to_seed("")
                .to_vec(),
            Err(_) => seed(),
        }
    }

    fn span() -> u32 {
        std::env::var("ZEC_SPAN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6000)
    }

    /// What the user can observe, without the moving chain tip: the TOTAL per pool (spendable + pending: a note moves
    /// from pending to spendable as the tip advances between two scans, which is not a difference in what was found)
    /// and the transaction history.
    fn observable(w: &ZcashWallet) -> String {
        let b = balances(w).unwrap();
        format!(
            "ironwood={} orchard={} sapling={} transparent={} history={:?}",
            b.ironwood_spendable + b.ironwood_pending,
            b.orchard_spendable + b.orchard_pending,
            b.sapling_total,
            b.transparent_spendable + b.transparent_pending,
            history(w, 10_000).unwrap()
        )
    }

    fn integrity_ok(path: &std::path::Path) -> bool {
        let conn =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let answer: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        answer == "ok"
    }

    async fn open(path: &std::path::Path, birthday: u32) -> (Client, ZcashWallet) {
        let (mut client, _info) = connect(TESTNET, SERVER).await.unwrap();
        let w = open_wallet(
            TESTNET,
            path,
            &lifecycle_seed(),
            0,
            &mut client,
            Some(birthday),
        )
        .await
        .unwrap();
        (client, w)
    }

    async fn full_scan(w: &mut ZcashWallet, client: &mut Client) {
        for attempt in 1..=4 {
            update_tip(w, client).await.unwrap();
            match sync(w, client, 100).await {
                Ok(()) => return,
                Err(e) => {
                    println!("full scan error #{attempt}: {e}");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
        panic!("the server stays unreachable");
    }

    #[tokio::test]
    #[ignore = "network"]
    async fn cancel_and_resume_cycles_match_an_uninterrupted_scan() {
        let (_c, info) = connect(TESTNET, SERVER).await.unwrap();
        let birthday = info.block_height.saturating_sub(span());
        let dir = tempfile::tempdir().unwrap();

        let (mut rc, mut reference) = open(&dir.path().join("reference.sqlite"), birthday).await;
        full_scan(&mut reference, &mut rc).await;
        let want = observable(&reference);
        println!("reference done: {want}");

        let path = dir.path().join("cycled.sqlite");
        let (mut client, mut w) = open(&path, birthday).await;
        update_tip(&mut w, &mut client).await.unwrap();
        let token = CancelToken::new();
        let mut cancels = 0;
        let mut last = 0u32;
        for round in 0u64..300 {
            token.reset();
            let stopper = token.clone();
            let delay = 250 + (round % 4) * 450;
            let timer = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                stopper.cancel();
            });
            let outcome = sync_cancellable(&mut w, &mut client, 100, &token).await;
            timer.abort();
            match outcome {
                Ok(SyncOutcome::Cancelled) => cancels += 1,
                Ok(SyncOutcome::Complete) => break,
                Err(e) => println!("round {round}: {e} (state is kept)"),
            }
            let scanned = balances(&w).unwrap().fully_scanned;
            assert!(
                scanned >= last,
                "the verified checkpoint never moves backwards ({scanned} < {last})"
            );
            last = scanned;
        }
        println!("cancelled {cancels} times, checkpoint {last}");
        assert!(
            cancels >= 2,
            "the test must actually interrupt the scan (raise ZEC_SPAN)"
        );
        update_tip(&mut w, &mut client).await.unwrap();
        sync(&mut w, &mut client, 100).await.unwrap();
        assert!(integrity_ok(&path));
        assert_eq!(
            observable(&w),
            want,
            "cancel/resume ends exactly where an uninterrupted scan ends"
        );
        let b = balances(&w).unwrap();
        assert!(b.fully_scanned + 50 >= b.chain_tip);
    }

    #[tokio::test]
    #[ignore = "network"]
    async fn a_cancel_before_the_scan_does_nothing_and_reset_rearms_it() {
        let (_c, info) = connect(TESTNET, SERVER).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (mut client, mut w) = open(
            &dir.path().join("w.sqlite"),
            info.block_height.saturating_sub(300),
        )
        .await;
        let token = CancelToken::new();
        token.cancel();
        let before = balances(&w).unwrap().fully_scanned;
        assert_eq!(
            sync_cancellable(&mut w, &mut client, 100, &token)
                .await
                .unwrap(),
            SyncOutcome::Cancelled
        );
        assert_eq!(
            balances(&w).unwrap().fully_scanned,
            before,
            "an already-cancelled scan touches nothing"
        );
        token.reset();
        update_tip(&mut w, &mut client).await.unwrap();
        assert_eq!(
            sync_cancellable(&mut w, &mut client, 100, &token)
                .await
                .unwrap(),
            SyncOutcome::Complete
        );
    }

    #[tokio::test]
    #[ignore = "network"]
    async fn an_rpc_failure_keeps_the_checkpoint_and_the_scan_resumes() {
        let (_c, info) = connect(TESTNET, SERVER).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.sqlite");
        let (mut client, mut w) = open(&path, info.block_height.saturating_sub(span())).await;
        update_tip(&mut w, &mut client).await.unwrap();
        let token = Arc::new(CancelToken::new());
        let stopper = token.clone();
        let timer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(900)).await;
            stopper.cancel();
        });
        let _ = sync_cancellable(&mut w, &mut client, 100, &token)
            .await
            .unwrap();
        timer.abort();
        let checkpoint = balances(&w).unwrap().fully_scanned;
        let observed = observable(&w);

        // The server disappears: a client whose endpoint refuses connections stands for "offline"/"RPC failure".
        let dead = tonic::transport::Channel::from_static("http://127.0.0.1:9")
            .connect_timeout(Duration::from_secs(2))
            .connect_lazy();
        let mut offline = Client::new(dead);
        let failed = sync(&mut w, &mut offline, 100).await;
        assert!(
            failed.is_err(),
            "an unreachable server is an error, never a silent success"
        );
        assert_eq!(
            balances(&w).unwrap().fully_scanned,
            checkpoint,
            "the checkpoint survives the failure"
        );
        assert_eq!(
            observable(&w),
            observed,
            "balances and history are untouched by the failure"
        );
        assert!(integrity_ok(&path));

        // The network is back: the same wallet continues.
        update_tip(&mut w, &mut client).await.unwrap();
        sync(&mut w, &mut client, 100).await.unwrap();
        assert!(balances(&w).unwrap().fully_scanned >= checkpoint);
    }

    /// Child process of the kill test: scans in a loop until it is killed (or the wallet is current).
    #[tokio::test]
    #[ignore = "child process of a_killed_process_resumes_from_its_checkpoint"]
    async fn scan_child() {
        let Ok(path) = std::env::var("ZEC_CHILD_DB") else {
            return;
        };
        let birthday: u32 = std::env::var("ZEC_BIRTHDAY").unwrap().parse().unwrap();
        let (mut client, mut w) = open(std::path::Path::new(&path), birthday).await;
        loop {
            update_tip(&mut w, &mut client).await.unwrap();
            sync(&mut w, &mut client, 100).await.unwrap();
            let b = balances(&w).unwrap();
            if b.fully_scanned + 10 >= b.chain_tip {
                return;
            }
        }
    }

    #[tokio::test]
    #[ignore = "network"]
    async fn a_killed_process_resumes_from_its_checkpoint() {
        let (_c, info) = connect(TESTNET, SERVER).await.unwrap();
        let birthday = info.block_height.saturating_sub(span());
        let dir = tempfile::tempdir().unwrap();

        let (mut rc, mut reference) = open(&dir.path().join("reference.sqlite"), birthday).await;
        full_scan(&mut reference, &mut rc).await;
        let want = observable(&reference);

        let victim = dir.path().join("victim.sqlite");
        let exe = std::env::current_exe().unwrap();
        let mut last = 0u32;
        for (i, wait_ms) in [3000u64, 2000, 4500].into_iter().enumerate() {
            let mut child = Command::new(&exe)
                .args([
                    "--ignored",
                    "--exact",
                    "lifecycle::scan_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("ZEC_CHILD_DB", &victim)
                .env("ZEC_BIRTHDAY", birthday.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            // Hard kill (TerminateProcess / SIGKILL): no cleanup code runs in the child.
            child.kill().unwrap();
            child.wait().unwrap();
            if !victim.exists() {
                continue;
            }
            assert!(integrity_ok(&victim), "database intact after kill #{i}");
            let (_c2, w) = open(&victim, birthday).await;
            let scanned = balances(&w).unwrap().fully_scanned;
            println!("kill #{i} after {wait_ms} ms: checkpoint {scanned}");
            assert!(
                scanned >= last,
                "the checkpoint never moves backwards (kill #{i})"
            );
            last = scanned;
        }
        let (mut client, mut w) = open(&victim, birthday).await;
        full_scan(&mut w, &mut client).await;
        assert!(integrity_ok(&victim));
        assert_eq!(
            observable(&w),
            want,
            "a scan killed several times ends where an uninterrupted scan ends"
        );
    }
}
