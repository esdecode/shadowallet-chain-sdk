//! Broadcast against a deterministic fake Esplora server (mainnet-network engine, no real node, nothing reaches a network).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use shadowallet_chain_bitcoin::{BitcoinEngine, BtcNetwork, WatchDescriptors};

const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

fn engine(dir: &std::path::Path) -> BitcoinEngine {
    let d = WatchDescriptors::from_extended_pubkey(ZPUB, BtcNetwork::Mainnet).unwrap();
    BitcoinEngine::create(&dir.join("w.sqlite"), d).unwrap()
}

fn raw_tx() -> (Vec<u8>, String) {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1u8; 71], vec![2u8; 33]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_op_return([1u8; 4]),
        }],
    };
    (
        bdk_wallet::bitcoin::consensus::serialize(&tx),
        tx.compute_txid().to_string(),
    )
}

/// `Some((status, body))` answers every request; `None` accepts and never answers (a stalled provider);
/// `reset` closes the connection without any answer.
fn serve(answer: Option<(u16, String)>, reset: bool) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let answer = answer.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 65536];
                let _ = s.read(&mut buf);
                if reset {
                    return;
                }
                match answer {
                    Some((status, body)) => {
                        let _ = write!(
                            s,
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                    }
                    None => std::thread::sleep(Duration::from_secs(30)),
                }
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

#[test]
fn an_accepted_submission_returns_the_locally_computed_id_even_when_the_provider_echoes_another() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let (raw, txid) = raw_tx();
    let honest = serve(Some((200, txid.clone())), false);
    assert_eq!(e.broadcast_esplora(&raw, &honest).unwrap(), txid);
    // a provider answering 200 with a DIFFERENT id cannot redirect tracking: the id comes from the signed bytes
    let lying = serve(Some((200, "ab".repeat(32))), false);
    assert_eq!(e.broadcast_esplora(&raw, &lying).unwrap(), txid);
}

#[test]
fn rejections_are_errors_that_carry_the_providers_reason() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let (raw, _) = raw_tx();
    for (reason, needle) in [
        (
            r#"sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met, 100 < 141"}"#,
            "min relay fee not met",
        ),
        (
            r#"sendrawtransaction RPC error: {"code":-25,"message":"bad-txns-inputs-missingorspent"}"#,
            "bad-txns-inputs-missingorspent",
        ),
        (
            r#"sendrawtransaction RPC error: {"code":-26,"message":"txn-mempool-conflict"}"#,
            "txn-mempool-conflict",
        ),
        (
            r#"sendrawtransaction RPC error: {"code":-27,"message":"Transaction already in block chain"}"#,
            "already in block chain",
        ),
    ] {
        let url = serve(Some((400, reason.to_owned())), false);
        let err = e.broadcast_esplora(&raw, &url).unwrap_err().to_string();
        assert!(err.contains("RPC error") && err.contains(needle), "{err}");
    }
}

#[test]
fn a_stalled_provider_times_out_within_the_bound_and_a_reset_connection_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let (raw, _) = raw_tx();
    let stalled = serve(None, false);
    let t = Instant::now();
    assert!(e.broadcast_esplora_with_timeout(&raw, &stalled, 2).is_err());
    assert!(
        t.elapsed() < Duration::from_secs(10),
        "bounded wait, took {:?}",
        t.elapsed()
    );
    let reset = serve(None, true);
    assert!(e.broadcast_esplora_with_timeout(&raw, &reset, 2).is_err());
}

#[test]
fn garbage_bytes_are_refused_before_any_network_use() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let url = serve(Some((200, String::new())), false);
    assert!(e.broadcast_esplora(&[1, 2, 3], &url).is_err());
}
