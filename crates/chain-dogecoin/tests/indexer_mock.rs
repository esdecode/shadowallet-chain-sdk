#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The public-testnet indexer backend against a local mock of BOTH services (SoChain-style REST and a
//! Dogecoin Core JSON-RPC gateway). Honest data must sync; every kind of provider contradiction, outage,
//! rate limit and uncertain broadcast must be classified correctly and must never be retried when it is a write.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use doge::bip32::{DerivationPath, Xpriv, Xpub};
use doge::consensus::encode::serialize_hex;
use doge::secp256k1::Secp256k1;
use doge::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use serde_json::{Value, json};
use shadowallet_chain_dogecoin::engine::DogeEngine;
use shadowallet_chain_dogecoin::indexer::{IndexerConfig, TESTNET_GENESIS};
use shadowallet_chain_dogecoin::{DogeAccount, DogeNetwork};

const TIP: u64 = 5000;

#[derive(Default, Clone)]
struct Behaviour {
    sochain_genesis: Option<String>,
    rpc_genesis: Option<String>,
    rpc_block_differs: bool,
    claimed_value: Option<String>,
    tamper_txid: bool,
    foreign_script: bool,
    gettxout_null: bool,
    gettxout_value: Option<f64>,
    sochain_fail: Option<u16>,
    sochain_429_first: u32,
    send_drop_connection: bool,
    send_error: Option<(i64, String)>,
    send_wrong_txid: bool,
    fee: Option<f64>,
    unknown_tx: bool,
    tx_conf: i64,
    history_on: Vec<String>,
}

struct Mock {
    base: String,
    hits: Arc<Mutex<HashMap<String, u32>>>,
    behaviour: Arc<Mutex<Behaviour>>,
    funding_hex: String,
    funding_txid: String,
    address: String,
}

fn http_response(status: u16, extra: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let len = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    while buf.len() < header_end + len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let first = head.lines().next()?.to_owned();
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    Some((
        method,
        path,
        String::from_utf8_lossy(&buf[header_end..]).to_string(),
    ))
}

fn block_hash(h: u64) -> String {
    if h == 0 {
        TESTNET_GENESIS.to_owned()
    } else {
        format!("{h:064x}")
    }
}

fn funding(account: &DogeAccount) -> (String, String, String, ScriptBuf) {
    let address = account.address(0, 0).unwrap();
    let script = address.script_pubkey();
    let tx = Transaction {
        version: doge::transaction::Version(1),
        lock_time: doge::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x04, 1, 2, 3, 4]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_234_567_890),
            script_pubkey: script.clone(),
        }],
    };
    (
        address.to_string(),
        serialize_hex(&tx),
        tx.compute_txid().to_string(),
        script,
    )
}

fn start(account: &DogeAccount) -> Mock {
    let (address, funding_hex, funding_txid, script) = funding(account);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let hits: Arc<Mutex<HashMap<String, u32>>> = Arc::default();
    let behaviour: Arc<Mutex<Behaviour>> = Arc::new(Mutex::new(Behaviour {
        tx_conf: 7,
        ..Default::default()
    }));
    let (h2, b2) = (hits.clone(), behaviour.clone());
    let (fh, ft, addr, spk) = (
        funding_hex.clone(),
        funding_txid.clone(),
        address.clone(),
        hex::encode(script.as_bytes()),
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (h2, b2, fh, ft, addr, spk) = (
                h2.clone(),
                b2.clone(),
                fh.clone(),
                ft.clone(),
                addr.clone(),
                spk.clone(),
            );
            std::thread::spawn(move || {
                let Some((method, path, body)) = read_request(&mut stream) else {
                    return;
                };
                let b = b2.lock().unwrap().clone();
                let count = |key: &str| {
                    let mut g = h2.lock().unwrap();
                    let c = g.entry(key.to_owned()).or_insert(0);
                    *c += 1;
                    *c
                };
                if method == "POST" {
                    let req: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                    let m = req["method"].as_str().unwrap_or("").to_owned();
                    count(&format!("rpc:{m}"));
                    let result =
                        |v: Value| json!({"result": v, "error": null, "id": "sw"}).to_string();
                    let error = |c: i64, msg: &str| {
                        json!({"result": null, "error": {"code": c, "message": msg}, "id": "sw"})
                            .to_string()
                    };
                    let reply = match m.as_str() {
                        "getblockhash" => {
                            let h = req["params"][0].as_u64().unwrap_or(0);
                            if h == 0 {
                                result(json!(
                                    b.rpc_genesis
                                        .clone()
                                        .unwrap_or_else(|| TESTNET_GENESIS.to_owned())
                                ))
                            } else if b.rpc_block_differs {
                                result(json!(format!("{:064x}", h + 99)))
                            } else {
                                result(json!(block_hash(h)))
                            }
                        }
                        "gettxout" => {
                            if b.gettxout_null {
                                result(Value::Null)
                            } else {
                                result(json!({
                                    "bestblock": block_hash(TIP),
                                    "confirmations": 11,
                                    "value": b.gettxout_value.unwrap_or(12.3456789),
                                    "scriptPubKey": {"hex": spk},
                                    "coinbase": false
                                }))
                            }
                        }
                        "estimatesmartfee" => match b.fee {
                            Some(f) => result(json!({"feerate": f, "blocks": 2})),
                            None => error(-32601, "Method not found"),
                        },
                        "sendrawtransaction" => {
                            if b.send_drop_connection {
                                return; // the request arrived; the answer never does
                            }
                            if let Some((c, msg)) = b.send_error {
                                error(c, &msg)
                            } else if b.send_wrong_txid {
                                result(json!(format!("{:064x}", 5)))
                            } else {
                                // answer with the real txid of whatever was sent
                                let hex_tx = req["params"][0].as_str().unwrap_or("");
                                let tx: Transaction =
                                    doge::consensus::encode::deserialize_hex(hex_tx).unwrap();
                                result(json!(tx.compute_txid().to_string()))
                            }
                        }
                        "getrawtransaction" => {
                            if b.unknown_tx {
                                error(
                                    -5,
                                    "No such mempool or blockchain transaction. Use gettransaction for wallet transactions.",
                                )
                            } else {
                                result(
                                    json!({"txid": req["params"][0], "confirmations": b.tx_conf, "blockhash": block_hash(TIP - 5)}),
                                )
                            }
                        }
                        _ => error(-32601, "Method not found"),
                    };
                    let _ = stream.write_all(&http_response(200, "", &reply));
                    return;
                }
                // ---- SoChain-style REST
                let key = path.split('/').skip(3).take(1).collect::<String>();
                let n = count(&format!("rest:{key}"));
                if let Some(code) = b.sochain_fail {
                    let _ = stream.write_all(&http_response(code, "Retry-After: 0\r\n", "{}"));
                    return;
                }
                if n <= b.sochain_429_first && key == "network_info" {
                    let _ = stream.write_all(&http_response(429, "Retry-After: 0\r\n", "{}"));
                    return;
                }
                let ok = |d: Value| json!({"status": "success", "data": d}).to_string();
                let segs: Vec<&str> = path.split('/').collect();
                let reply = match key.as_str() {
                    "network_info" => {
                        ok(json!({"block_count": TIP, "best_block_hash": block_hash(TIP)}))
                    }
                    "block" => {
                        let h: u64 = segs.last().and_then(|s| s.parse().ok()).unwrap_or(0);
                        let hash = if h == 0 {
                            b.sochain_genesis
                                .clone()
                                .unwrap_or_else(|| TESTNET_GENESIS.to_owned())
                        } else {
                            block_hash(h)
                        };
                        ok(json!({"height": h, "hash": hash}))
                    }
                    "transactions"
                        if segs
                            .get(5)
                            .is_some_and(|a| b.history_on.iter().any(|h| h == a)) =>
                    {
                        ok(json!({"transactions": [{
                            "hash": format!("{:064x}", 77), "value_sent": "0.00000000",
                            "value_received": "1.00000000", "block": TIP - 20
                        }]}))
                    }
                    "unspent_outputs" | "transactions"
                        if segs.get(5) != Some(&addr.as_str())
                            || (key == "unspent_outputs" && segs.get(6) != Some(&"1")) =>
                    {
                        if key == "unspent_outputs" {
                            ok(json!({"outputs": []}))
                        } else {
                            ok(json!({"transactions": []}))
                        }
                    }
                    "unspent_outputs" => {
                        let mut hash = ft.clone();
                        if b.tamper_txid {
                            hash = format!("{:064x}", 9);
                        }
                        let script = if b.foreign_script {
                            "76a914000000000000000000000000000000000000000088ac".to_owned()
                        } else {
                            spk.clone()
                        };
                        ok(json!({"outputs": [{
                            "hash": hash, "index": 0, "script": script, "address": addr,
                            "value": b.claimed_value.clone().unwrap_or_else(|| "12.34567890".to_owned()),
                            "block": TIP - 10, "tx_hex": fh
                        }]}))
                    }
                    "transactions" => ok(json!({"transactions": [{
                        "hash": ft, "value_sent": "0.00000000", "value_received": "12.34567890", "block": TIP - 10
                    }]})),
                    "transaction" => {
                        if b.unknown_tx {
                            json!({"status": "fail", "data": {"error_message": "Transaction not found"}}).to_string()
                        } else {
                            ok(
                                json!({"hash": segs.last().unwrap(), "confirmations": b.tx_conf, "block_hash": block_hash(TIP - 5)}),
                            )
                        }
                    }
                    _ => {
                        json!({"status": "fail", "data": {"error_message": "Invalid API endpoint"}})
                            .to_string()
                    }
                };
                let _ = stream.write_all(&http_response(200, "", &reply));
            });
        }
    });
    Mock {
        base,
        hits,
        behaviour,
        funding_hex,
        funding_txid,
        address,
    }
}

fn account() -> (DogeAccount, String, [u8; 4]) {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(DogeNetwork::Testnet.kind(), &[0x42; 32]).unwrap();
    let acct = master
        .derive_priv(&secp, &DerivationPath::from_str("m/44'/3'/0'").unwrap())
        .unwrap();
    let xpub = Xpub::from_priv(&secp, &acct).to_string();
    let fp = master.fingerprint(&secp).to_bytes();
    (
        DogeAccount::from_xpub(DogeNetwork::Testnet, &xpub, fp).unwrap(),
        xpub,
        fp,
    )
}

fn engine(
    mock: &Mock,
    xpub: &str,
    fp: [u8; 4],
    tweak: impl FnOnce(&mut IndexerConfig),
) -> (DogeEngine, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = IndexerConfig::public_testnet();
    cfg.sochain_base = format!("{}/api/v3", mock.base);
    cfg.rpc_url = format!("{}/rpc", mock.base);
    cfg.request_timeout = Duration::from_secs(3);
    cfg.rpc_per_minute = 1000;
    cfg.read_retries = 2;
    tweak(&mut cfg);
    let e = DogeEngine::open_indexer(
        DogeNetwork::Testnet,
        xpub,
        fp,
        cfg,
        &dir.path().join("d.sqlite"),
    )
    .unwrap();
    (e, dir)
}

fn setup() -> (Mock, String, [u8; 4]) {
    let (acct, xpub, fp) = account();
    (start(&acct), xpub, fp)
}

fn hits(m: &Mock, k: &str) -> u32 {
    *m.hits.lock().unwrap().get(k).unwrap_or(&0)
}

fn set(m: &Mock, f: impl FnOnce(&mut Behaviour)) {
    f(&mut m.behaviour.lock().unwrap());
}

#[test]
fn honest_providers_sync_and_identity_is_checked_once() {
    let (m, xpub, fp) = setup();
    let (mut e, _d) = engine(&m, &xpub, fp, |_| {});
    let report = e.sync().unwrap();
    assert_eq!(report.tip_height, TIP);
    assert_eq!(e.utxos().len(), 1);
    assert_eq!(e.utxos()[0].value_sats, 1_234_567_890);
    assert_eq!(e.utxos()[0].confirmations, 11);
    assert_eq!(e.utxos()[0].outpoint.txid.to_string(), m.funding_txid);
    assert_eq!(e.history().len(), 1);
    assert_eq!(e.balance().confirmed_sats, 1_234_567_890);
    let genesis_checks = hits(&m, "rpc:getblockhash");
    e.sync().unwrap();
    assert_eq!(
        hits(&m, "rpc:getblockhash"),
        genesis_checks,
        "identity is memoised, not re-asked every sync"
    );
    assert!(m.funding_hex.len() > 10 && !m.address.is_empty());
}

#[test]
fn wrong_network_identity_is_refused_before_anything_is_read() {
    let (m, xpub, fp) = setup();
    set(&m, |b| b.sochain_genesis = Some(format!("{:064x}", 1)));
    let (mut e, _d) = engine(&m, &xpub, fp, |_| {});
    let msg = e.sync().unwrap_err().to_string();
    assert!(msg.contains("identity mismatch"), "{msg}");
    assert_eq!(hits(&m, "rest:unspent_outputs"), 0);

    let (m, xpub, fp) = setup();
    set(&m, |b| b.rpc_genesis = Some(format!("{:064x}", 2)));
    let (mut e, _d) = engine(&m, &xpub, fp, |_| {});
    assert!(
        e.sync()
            .unwrap_err()
            .to_string()
            .contains("identity mismatch")
    );
    assert_eq!(hits(&m, "rest:unspent_outputs"), 0);
}

#[test]
fn services_that_disagree_about_a_recent_block_are_rejected() {
    let (m, xpub, fp) = setup();
    set(&m, |b| b.rpc_block_differs = true);
    let (mut e, _d) = engine(&m, &xpub, fp, |_| {});
    let msg = e.sync().unwrap_err().to_string();
    assert!(msg.contains("contradiction"), "{msg}");
    assert!(e.utxos().is_empty());
}

#[test]
fn contradictory_or_forged_utxo_data_is_rejected() {
    for (name, tweak) in [
        (
            "claimed value differs from the transaction",
            (|b: &mut Behaviour| b.claimed_value = Some("99.00000000".into()))
                as fn(&mut Behaviour),
        ),
        ("txid does not match the raw transaction", |b| {
            b.tamper_txid = true
        }),
        ("script is not ours", |b| b.foreign_script = true),
        ("node says spent or unknown", |b| b.gettxout_null = true),
        ("node reports another value", |b| {
            b.gettxout_value = Some(1.0)
        }),
    ] {
        let (m, xpub, fp) = setup();
        set(&m, tweak);
        let (mut e, _d) = engine(&m, &xpub, fp, |_| {});
        let msg = e.sync().expect_err(name).to_string();
        assert!(msg.contains("contradiction"), "{name}: {msg}");
        assert!(
            e.utxos().is_empty(),
            "{name}: nothing may be spendable after a contradiction"
        );
    }
}

#[test]
fn a_rate_limited_read_is_retried_a_bounded_number_of_times() {
    let (m, xpub, fp) = setup();
    set(&m, |b| b.sochain_429_first = 2);
    let (mut e, _d) = engine(&m, &xpub, fp, |_| {});
    // block/0 comes first and is not limited; network_info answers 429 twice, then succeeds (2 retries allowed)
    e.sync().unwrap();
    assert!(hits(&m, "rest:network_info") >= 3);
}

#[test]
fn an_outage_fails_cleanly_after_bounded_retries() {
    let (m, xpub, fp) = setup();
    set(&m, |b| b.sochain_fail = Some(503));
    let (mut e, _d) = engine(&m, &xpub, fp, |_| {});
    let msg = e.sync().unwrap_err().to_string();
    assert!(msg.contains("indexer unavailable"), "{msg}");
    assert_eq!(hits(&m, "rest:block"), 3, "1 attempt + 2 retries, no more");
}

#[test]
fn the_request_budget_protects_the_free_tiers() {
    let (m, xpub, fp) = setup();
    let (mut e, _d) = engine(&m, &xpub, fp, |c| c.max_requests = 3);
    let msg = e.sync().unwrap_err().to_string();
    assert!(msg.contains("budget"), "{msg}");
}

#[test]
fn fee_comes_from_the_node_and_falls_back_to_the_recommended_fee() {
    let (m, xpub, fp) = setup();
    set(&m, |b| b.fee = Some(0.0111));
    let (e, _d) = engine(&m, &xpub, fp, |_| {});
    let f = e.fee_estimates();
    assert_eq!(f.normal_sat_vb, 1110);
    assert_eq!(f.source, "estimatesmartfee");
    let again = e.fee_estimates();
    assert_eq!(again.normal_sat_vb, 1110);
    assert_eq!(hits(&m, "rpc:estimatesmartfee"), 1, "cached");

    set(&m, |b| b.fee = None);
    let (e2, _d2) = engine(&m, &xpub, fp, |_| {});
    let f2 = e2.fee_estimates();
    assert_eq!(
        (f2.normal_sat_vb, f2.source.as_str()),
        (1000, "policy-recommended")
    );

    set(&m, |b| b.fee = Some(50.0)); // absurd answer
    let (e3, _d3) = engine(&m, &xpub, fp, |_| {});
    assert_eq!(e3.fee_estimates().source, "policy-recommended");
}

fn signed_hex(m: &Mock) -> String {
    m.funding_hex.clone() // any decodable transaction; the mock does not validate scripts
}

#[test]
fn broadcast_is_sent_exactly_once_and_an_uncertain_outcome_is_never_retried() {
    let (m, xpub, fp) = setup();
    let (e, _d) = engine(&m, &xpub, fp, |_| {});
    assert_eq!(e.broadcast_hex(&signed_hex(&m)).unwrap(), m.funding_txid);
    assert_eq!(hits(&m, "rpc:sendrawtransaction"), 1);

    // the connection dies after the node received the request
    set(&m, |b| b.send_drop_connection = true);
    let msg = e.broadcast_hex(&signed_hex(&m)).unwrap_err().to_string();
    assert!(msg.contains("outcome unknown"), "{msg}");
    assert_eq!(
        hits(&m, "rpc:sendrawtransaction"),
        2,
        "one more attempt by the caller, none by the backend"
    );

    // a different txid in the answer is an uncertain outcome too, never a success
    set(&m, |b| {
        b.send_drop_connection = false;
        b.send_wrong_txid = true;
    });
    let msg = e.broadcast_hex(&signed_hex(&m)).unwrap_err().to_string();
    assert!(msg.contains("do not rebroadcast"), "{msg}");

    // an explicit node rejection keeps the node's own error shape so the reservation layer can classify it
    set(&m, |b| {
        b.send_wrong_txid = false;
        b.send_error = Some((-26, "66: insufficient priority".to_owned()));
    });
    let msg = e.broadcast_hex(&signed_hex(&m)).unwrap_err().to_string();
    assert!(
        msg.contains("RPC error response") && msg.contains("code: -26"),
        "{msg}"
    );
    assert!(
        e.broadcast_hex("zz")
            .unwrap_err()
            .to_string()
            .contains("does not decode")
    );
    assert_eq!(hits(&m, "rpc:sendrawtransaction"), 4);
}

#[test]
fn transaction_status_is_cross_checked_and_unknown_transactions_say_so() {
    let (m, xpub, fp) = setup();
    let (e, _d) = engine(&m, &xpub, fp, |_| {});
    let status = e.transaction_status(&m.funding_txid).unwrap();
    assert_eq!(status["confirmations"], 7);

    set(&m, |b| b.unknown_tx = true);
    let msg = e
        .transaction_status(&m.funding_txid)
        .unwrap_err()
        .to_string();
    assert!(msg.contains("code: -5"), "{msg}");
    assert!(e.transaction_status("nothex").is_err());
}

#[test]
fn rpc_quota_is_respected_without_blocking_cross_checks() {
    let (m, xpub, fp) = setup();
    let (e, _d) = engine(&m, &xpub, fp, |c| c.rpc_per_minute = 1);
    // the single RPC slot of this minute is used by the node answer; the optional cross-check must not wait
    let start = std::time::Instant::now();
    let _ = e.transaction_status(&m.funding_txid).unwrap();
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(hits(&m, "rpc:getrawtransaction") <= 1);
}

#[test]
fn mainnet_cannot_use_the_public_indexer_backend() {
    let (_acct, xpub, fp) = account();
    let dir = tempfile::tempdir().unwrap();
    let main = Xpriv::new_master(DogeNetwork::Mainnet.kind(), &[7; 32]).unwrap();
    let secp = Secp256k1::new();
    let acct = main
        .derive_priv(&secp, &DerivationPath::from_str("m/44'/3'/0'").unwrap())
        .unwrap();
    let main_xpub = Xpub::from_priv(&secp, &acct).to_string();
    let r = DogeEngine::open_indexer(
        DogeNetwork::Mainnet,
        &main_xpub,
        fp,
        IndexerConfig::public_testnet(),
        &dir.path().join("x.sqlite"),
    );
    assert!(r.unwrap_err().to_string().contains("testnet only"));
    let _ = xpub;
}

#[test]
fn used_change_addresses_are_rediscovered_and_never_reused() {
    let (acct, xpub, fp) = account();
    let m = start(&acct);
    let (mut e, _d) = engine(&m, &xpub, fp, |_| {});
    assert_eq!(e.change_index(), 0);
    // change addresses 0, 1 and 3 already appear in history (a gap at 2 is possible after pruning)
    let used: Vec<String> = [0u32, 1, 3]
        .iter()
        .map(|i| acct.address(1, *i).unwrap().to_string())
        .collect();
    set(&m, |b| b.history_on = used.clone());
    // the window is only lookahead/4 wide; index 3 must be inside it for this to be visible
    e.sync().unwrap();
    assert_eq!(
        e.change_index(),
        4,
        "next change address is after the highest used one"
    );
    // it persists across a reopen and never moves backwards
    drop(e);
    set(&m, |b| b.history_on = Vec::new());
    let dir = _d.path().join("d.sqlite");
    let mut cfg = IndexerConfig::public_testnet();
    cfg.sochain_base = format!("{}/api/v3", m.base);
    cfg.rpc_url = format!("{}/rpc", m.base);
    cfg.request_timeout = Duration::from_secs(3);
    cfg.rpc_per_minute = 1000;
    let mut again = DogeEngine::open_indexer(DogeNetwork::Testnet, &xpub, fp, cfg, &dir).unwrap();
    assert_eq!(again.change_index(), 4);
    again.sync().unwrap();
    assert_eq!(again.change_index(), 4);
}
