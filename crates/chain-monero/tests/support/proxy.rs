//! A fault-injecting HTTP forwarder in front of a real daemon: it passes everything through, but for
//! `send_raw_transaction` it can deliver the request to the daemon and then swallow the answer, so the wallet sees a broken
//! connection although the transaction DID reach the network (the classic "unknown broadcast outcome").
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct FaultProxy {
    pub url: String,
    /// When set, the answer to `send_raw_transaction` is dropped after the daemon has produced it.
    pub drop_send_answer: Arc<AtomicBool>,
    /// When set, `send_raw_transaction` is not even forwarded (the daemon never sees it).
    pub block_send: Arc<AtomicBool>,
    pub sends_seen: Arc<AtomicUsize>,
}

fn read_message(s: &mut TcpStream, is_response: bool) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    let len = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok());
    let mut body = Vec::new();
    match len {
        Some(n) => {
            body.resize(n, 0);
            s.read_exact(&mut body).ok()?;
        }
        // a request without a length has no body; a response without one runs to the end of the connection
        None if is_response => {
            let _ = s.read_to_end(&mut body);
        }
        None => {}
    }
    Some((buf, body))
}

impl FaultProxy {
    pub fn start(upstream: &str) -> FaultProxy {
        let upstream = upstream.trim_start_matches("http://").to_owned();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let drop_send_answer = Arc::new(AtomicBool::new(false));
        let block_send = Arc::new(AtomicBool::new(false));
        let sends_seen = Arc::new(AtomicUsize::new(0));
        let (d, b, c) = (
            drop_send_answer.clone(),
            block_send.clone(),
            sends_seen.clone(),
        );
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(mut client) = conn else { continue };
                let (upstream, d, b, c) = (upstream.clone(), d.clone(), b.clone(), c.clone());
                std::thread::spawn(move || {
                    while let Some((head, body)) = read_message(&mut client, false) {
                        let is_send = head.starts_with(b"POST /send_raw_transaction");
                        if is_send {
                            c.fetch_add(1, Ordering::SeqCst);
                            if b.load(Ordering::SeqCst) {
                                return; // dropped before the daemon saw anything
                            }
                        }
                        let Ok(mut up) = TcpStream::connect(&upstream) else {
                            return;
                        };
                        if up.write_all(&head).is_err() || up.write_all(&body).is_err() {
                            return;
                        }
                        let Some((rhead, rbody)) = read_message(&mut up, true) else {
                            return;
                        };
                        if is_send && d.load(Ordering::SeqCst) {
                            return; // the daemon answered; the wallet never hears it
                        }
                        if client.write_all(&rhead).is_err() || client.write_all(&rbody).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        FaultProxy {
            url,
            drop_send_answer,
            block_send,
            sends_seen,
        }
    }
}
