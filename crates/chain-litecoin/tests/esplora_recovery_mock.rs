#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Seed recovery over a MOCK Esplora server (no network, disposable public-label seed).
//!
//! A synthetic Litecoin MAINNET ledger pays addresses of the account derived from `SHA256("shadowallet-recovery-vector/litecoin")`:
//! external 0, 5 and 40, and change 0 and 7. A fresh engine ("restored vault") opens against the mock and must rediscover exactly
//! what the gap-limit rules allow, repeatedly and idempotently, with identical results for an independent second restore, and must
//! never hand out an already-used receive address. Funds beyond the gap are NOT found: this test documents that limit.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use litecoin::absolute::LockTime;
use litecoin::bip32::{DerivationPath, Xpriv, Xpub};
use litecoin::consensus::encode::serialize_hex;
use litecoin::hashes::{Hash, sha256};
use litecoin::secp256k1::Secp256k1;
use litecoin::transaction::Version;
use litecoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use shadowallet_chain_litecoin::engine::LtcEngine;
use shadowallet_chain_litecoin::{LtcAccount, LtcNetwork};

fn serve(routes: Arc<Mutex<HashMap<String, String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let routes = routes.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let (status, body) = match routes.lock().unwrap().get(&path) {
                    Some(b) => (200, b.clone()),
                    None if path.contains("/txs") => (200, "[]".to_owned()),
                    None if path.ends_with("/utxo") => (200, "[]".to_owned()),
                    None => (404, "not found".to_owned()),
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn account(seed: &[u8]) -> (LtcAccount, [u8; 4], String) {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(LtcNetwork::Mainnet.kind(), seed).unwrap();
    let acct = master
        .derive_priv(&secp, &DerivationPath::from_str("m/84'/2'/0'").unwrap())
        .unwrap();
    let xpub = Xpub::from_priv(&secp, &acct).to_string();
    let fp = master.fingerprint(&secp).to_bytes();
    (
        LtcAccount::from_xpub(LtcNetwork::Mainnet, &xpub, fp).unwrap(),
        fp,
        xpub,
    )
}

/// One synthetic confirmed funding transaction paying `value` to `spk`.
fn funding(tag: u8, spk: ScriptBuf, value: u64) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        }],
        mw_tx: None,
        is_hog_ex: false,
    }
}

fn restore(
    base: &str,
    xpub: &str,
    fp: [u8; 4],
    dir: &std::path::Path,
    lookahead: u32,
) -> LtcEngine {
    LtcEngine::open_esplora(
        LtcNetwork::Mainnet,
        xpub,
        fp,
        base,
        &dir.join("w.sqlite"),
        lookahead,
    )
    .unwrap()
}

fn found(e: &LtcEngine) -> Vec<(u32, u32, u64)> {
    let mut v: Vec<(u32, u32, u64)> = e
        .utxos()
        .iter()
        .map(|u| (u.keychain, u.index, u.value_sats))
        .collect();
    v.sort_unstable();
    v
}

#[test]
fn restore_rediscovers_within_the_gap_is_idempotent_and_never_reuses_an_address() {
    let seed = sha256::Hash::hash(b"shadowallet-recovery-vector/litecoin").to_byte_array();
    let (acct, fp, xpub) = account(&seed);
    let lookahead = 20u32;
    // keychain, index, value, tag, height
    let wanted: [(u32, u32, u64, u8, u64); 5] = [
        (0, 0, 50_000, 1, 100),
        (0, 5, 70_000, 2, 105),
        (1, 0, 30_000, 3, 110),
        (0, 40, 90_000, 4, 120), // beyond the external gap: 5 + 1 + 20 = 26 < 40
        (1, 7, 10_000, 5, 121),  // beyond the initial change window and not contiguous
    ];
    let mut routes: HashMap<String, String> = HashMap::new();
    for (k, i, value, tag, height) in wanted {
        let addr = acct.address(k, i).unwrap();
        let tx = funding(tag, addr.script_pubkey(), value);
        let txid = tx.compute_txid().to_string();
        let spk_hex = hex::encode(addr.script_pubkey().as_bytes());
        let entry = format!(
            r#"{{"txid":"{txid}","status":{{"confirmed":true,"block_height":{height}}},"vin":[{{"prevout":null}}],"vout":[{{"scriptpubkey":"{spk_hex}","value":{value}}}]}}"#
        );
        routes.insert(format!("/address/{addr}/txs"), format!("[{entry}]"));
        routes.insert(
            format!("/address/{addr}/utxo"),
            format!(
                r#"[{{"txid":"{txid}","vout":0,"status":{{"confirmed":true,"block_height":{height}}}}}]"#
            ),
        );
        routes.insert(format!("/tx/{txid}/hex"), serialize_hex(&tx));
    }
    routes.insert("/blocks/tip/height".to_owned(), "130".to_owned());
    let base = serve(Arc::new(Mutex::new(routes)));

    let tmp = std::env::temp_dir();
    let pid = std::process::id();
    let (dir1, dir2, dir3) = (
        tmp.join(format!("sw-ltc-rec1-{pid}")),
        tmp.join(format!("sw-ltc-rec2-{pid}")),
        tmp.join(format!("sw-ltc-rec3-{pid}")),
    );
    let mut a = restore(&base, &xpub, fp, &dir1, lookahead);
    let r1 = a.sync().unwrap();
    // found: ext 0, ext 5, change 0 (inside the windows); NOT found: ext 40 and change 7 (beyond the gap limit)
    let list = found(&a);
    assert_eq!(
        list,
        vec![(0, 0, 50_000), (0, 5, 70_000), (1, 0, 30_000)],
        "{r1:?}"
    );
    assert_eq!(r1.history, 3);
    assert_eq!(a.balance().confirmed_sats, 150_000);
    assert!(a.utxos().iter().all(|u| u.confirmations > 0));
    // idempotent repeat
    let r2 = a.sync().unwrap();
    assert_eq!((r2.utxos, r2.history), (r1.utxos, r1.history));
    // the next receive address is past every used one: no address reuse after recovery
    let next = a.next_receive_address().unwrap().to_string();
    assert_eq!(
        next,
        acct.address(0, 6).unwrap().to_string(),
        "first unused index after the highest used one"
    );
    assert!(
        a.change_index() >= 1,
        "change index moved past the used change address"
    );

    // an independent second restore (clean database) reaches the same state
    let mut b = restore(&base, &xpub, fp, &dir2, lookahead);
    let rb = b.sync().unwrap();
    assert_eq!((rb.utxos, rb.history), (r1.utxos, r1.history));
    assert_eq!(found(&b), list);

    // a different seed finds nothing on the same ledger (wallet isolation)
    let other = sha256::Hash::hash(b"shadowallet-recovery-vector/other").to_byte_array();
    let (_, ofp, oxpub) = account(&other);
    let mut c = restore(&base, &oxpub, ofp, &dir3, lookahead);
    assert_eq!(c.sync().unwrap().utxos, 0);
    for d in [dir1, dir2, dir3] {
        let _ = std::fs::remove_dir_all(d);
    }
}
