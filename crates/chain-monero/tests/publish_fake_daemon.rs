//! The production broadcast path (`publish_signed`) against a deterministic FAKE Monero daemon. Offline, no real network.
//!
//! The "signed transaction" is a real public mainnet transaction (fixture bytes, public chain data) because the broadcast code
//! only serialises and submits it; what is verified here is what the wallet records and returns for every kind of answer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use monero_wallet::transaction::Transaction;
use shadowallet_chain_monero::*;

fn fixture() -> (Transaction, [u8; 32]) {
    let hex_text = include_str!("fixtures/mainnet_rct_tx.hex").trim();
    let bytes = hex::decode(hex_text).unwrap();
    let tx = Transaction::read(&mut bytes.as_slice()).unwrap();
    let id = hex::decode(include_str!("fixtures/mainnet_rct_tx.txid").trim()).unwrap();
    assert_eq!(
        tx.hash().as_slice(),
        id.as_slice(),
        "the fixture parses to its published transaction id"
    );
    let hash = tx.hash();
    (tx, hash)
}

#[derive(Clone, Copy)]
enum Mode {
    Ok,
    Reject(&'static str),
    Stall,
    Reset,
    Garbage,
}

/// Counts the `send_raw_transaction` requests it receives. Anything else (the start-up batch request) gets an empty answer.
fn fake_daemon(mode: Mode) -> (String, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = sent.clone();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut c) = conn else { continue };
            let counter = counter.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let n = c.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if head.starts_with("POST /send_raw_transaction") {
                    counter.fetch_add(1, Ordering::SeqCst);
                    match mode {
                        Mode::Ok => {
                            r#"{"status":"OK","double_spend":false,"fee_too_low":false,"invalid_input":false,"invalid_output":false,"low_mixin":false,"not_relayed":false,"overspend":false,"too_big":false,"too_few_outputs":false,"reason":""}"#.to_owned()
                        }
                        Mode::Reject(reason) => format!(
                            r#"{{"status":"Failed","double_spend":false,"fee_too_low":false,"invalid_input":false,"invalid_output":false,"low_mixin":false,"not_relayed":false,"overspend":false,"too_big":false,"too_few_outputs":false,"reason":"{reason}"}}"#
                        ),
                        Mode::Stall => {
                            std::thread::sleep(Duration::from_secs(20));
                            return;
                        }
                        Mode::Reset => return,
                        Mode::Garbage => "<html>not json</html>".to_owned(),
                    }
                } else {
                    "[]".to_owned()
                };
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    (url, sent)
}

async fn node(net: MoneroNet, url: &str) -> Node {
    let transport = ProxyTransport::new_with_timeout(url, None, 2).unwrap();
    Node {
        net,
        daemon: shadowallet_chain_monero::Daemon::new(transport)
            .await
            .unwrap(),
    }
}

fn status_of(store: &MoneroStore, txid: [u8; 32]) -> Vec<(String, String)> {
    store
        .history(50)
        .unwrap()
        .into_iter()
        .filter(|t| t.txid == txid)
        .map(|t| (t.direction, t.status))
        .collect()
}

#[tokio::test]
async fn an_accepted_transaction_is_recorded_pending_with_its_local_id() {
    let (tx, id) = fixture();
    let (url, sent) = fake_daemon(Mode::Ok);
    let n = node(STAGENET, &url).await;
    let dir = tempfile::tempdir().unwrap();
    let store = MoneroStore::open(&dir.path().join("a.db")).unwrap();
    let txid = publish_signed(&store, &n, &tx, "5recipient", 1_000, 30, 1)
        .await
        .unwrap();
    assert_eq!(
        txid, id,
        "the id comes from the transaction bytes, not from the node"
    );
    assert_eq!(sent.load(Ordering::SeqCst), 1);
    assert_eq!(
        status_of(&store, id),
        vec![("out".to_owned(), "pending".to_owned())]
    );
    // duplicate submission by the user: one history row, the node is asked again but nothing is duplicated
    publish_signed(&store, &n, &tx, "5recipient", 1_000, 30, 2)
        .await
        .unwrap();
    assert_eq!(status_of(&store, id).len(), 1);
}

#[tokio::test]
async fn a_definite_rejection_marks_the_row_failed_and_is_reported_as_rejected() {
    let (tx, id) = fixture();
    for reason in ["fee too low", "Invalid input", "low mixin"] {
        let (url, _) = fake_daemon(Mode::Reject(reason));
        let n = node(STAGENET, &url).await;
        let dir = tempfile::tempdir().unwrap();
        let store = MoneroStore::open(&dir.path().join("r.db")).unwrap();
        let err = publish_signed(&store, &n, &tx, "5recipient", 1_000, 30, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, MoneroError::Rejected(_)), "{reason}: {err}");
        assert_eq!(
            status_of(&store, id),
            vec![("out".to_owned(), "failed".to_owned())],
            "{reason}"
        );
    }
}

#[tokio::test]
async fn an_ambiguous_answer_keeps_the_row_pending_and_survives_a_restart() {
    let (tx, id) = fixture();
    for (name, mode) in [
        (
            "double spend may be our own transaction",
            Mode::Reject("double spend"),
        ),
        (
            "already known",
            Mode::Reject("Transaction already in the pool"),
        ),
        ("unreadable answer", Mode::Garbage),
        ("connection reset", Mode::Reset),
    ] {
        let (url, _) = fake_daemon(mode);
        let n = node(STAGENET, &url).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.db");
        let store = MoneroStore::open(&path).unwrap();
        let err = publish_signed(&store, &n, &tx, "5recipient", 1_000, 30, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, MoneroError::Node(_)), "{name}: {err}");
        assert_eq!(
            status_of(&store, id),
            vec![("out".to_owned(), "pending".to_owned())],
            "{name}"
        );
        drop(store);
        let again = MoneroStore::open(&path).unwrap();
        assert_eq!(
            status_of(&again, id),
            vec![("out".to_owned(), "pending".to_owned())],
            "{name}: after a restart"
        );
    }
}

#[tokio::test]
async fn a_stalled_daemon_times_out_within_the_bound_and_leaves_the_row_pending() {
    let (tx, id) = fixture();
    let (url, _) = fake_daemon(Mode::Stall);
    let n = node(STAGENET, &url).await;
    let dir = tempfile::tempdir().unwrap();
    let store = MoneroStore::open(&dir.path().join("s.db")).unwrap();
    let t = Instant::now();
    let err = publish_signed(&store, &n, &tx, "5recipient", 1_000, 30, 1)
        .await
        .unwrap_err();
    assert!(
        t.elapsed() < Duration::from_secs(10),
        "bounded wait: {:?}",
        t.elapsed()
    );
    assert!(matches!(err, MoneroError::Node(_)), "{err}");
    assert_eq!(
        status_of(&store, id),
        vec![("out".to_owned(), "pending".to_owned())],
        "a timeout proves nothing"
    );
}

#[cfg(not(feature = "mainnet-send"))]
#[tokio::test]
async fn the_default_build_never_submits_to_a_mainnet_node_handle() {
    let (tx, id) = fixture();
    let (url, sent) = fake_daemon(Mode::Ok);
    let n = node(MAINNET, &url).await;
    let dir = tempfile::tempdir().unwrap();
    let store = MoneroStore::open(&dir.path().join("m.db")).unwrap();
    let err = publish_signed(&store, &n, &tx, "4recipient", 1_000, 30, 1)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("mainnet broadcasting is disabled"),
        "{err}"
    );
    assert_eq!(sent.load(Ordering::SeqCst), 0, "nothing was sent");
    assert!(status_of(&store, id).is_empty(), "nothing was recorded");
}
