//! Verify a mined (or captured) Zcash v5/v6 transaction OUTSIDE the wallet's database and signing path.
//!
//!   cargo run --release -p shadowallet-chain-zcash --example verify_tx -- <txid> [https://testnet.zec.rocks:443]
//!   cargo run --release -p shadowallet-chain-zcash --example verify_tx -- --file <raw-tx-file>
//!
//! It reads no wallet, no key and no database. Checks: parse with the official `zcash_primitives` deserializer, recompute
//! the txid from the parsed data, re-serialize to the identical bytes, verify the Orchard / Ironwood Halo 2 proofs, the
//! spend authorization signatures and the binding signature against the ZIP-244 signature hash (transactions without transparent parts), and show that a damaged
//! proof and a damaged signature are refused (so the verifier is not vacuous).
//!
//! HONEST LIMITS: these are the official Zcash libraries, the same family the wallet builds with; this is not a second
//! implementation of the consensus rules. Whether the anchor exists on the chain and the nullifiers are unspent is only
//! decided by a full node (observed as acceptance and mining). Shielded amounts are not public.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use orchard::bundle::{Authorized, BatchValidator};
use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
use zcash_client_backend::proto::service::TxFilter;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;
use zcash_protocol::value::ZatBalance;

type Bundle = orchard::Bundle<Authorized, ZatBalance>;

fn parse(raw: &[u8]) -> std::io::Result<Transaction> {
    // v5 and v6 carry their consensus branch id; the argument only matters for older formats.
    let mut rest = raw;
    let tx = Transaction::read(&mut rest, BranchId::Nu5)?;
    if !rest.is_empty() {
        return Err(std::io::Error::other(
            "trailing bytes after the transaction",
        ));
    }
    Ok(tx)
}

/// ZIP-244: for a transaction WITHOUT a transparent bundle, the signature hash of the shielded parts is the txid
/// digest. A transaction with transparent parts needs the spent outputs and is reported as not verified.
fn sighash(raw: &[u8]) -> [u8; 32] {
    let tx = parse(raw).expect("parsed before");
    assert!(
        tx.transparent_bundle().is_none(),
        "transparent parts: not verified by this tool"
    );
    *tx.txid().as_ref()
}

fn valid(vk: &VerifyingKey, bundle: &Bundle, sighash: [u8; 32]) -> bool {
    let mut batch = BatchValidator::new(vk);
    if batch.add_bundle(bundle, sighash).is_err() {
        return false;
    }
    batch.validate(rand_core::UnwrapErr(rand::rngs::SysRng))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (raw, expected_txid, mined, source) = if args[0] == "--file" {
        (
            std::fs::read(&args[1]).unwrap(),
            None,
            None,
            args[1].clone(),
        )
    } else {
        let url = args
            .get(1)
            .cloned()
            .unwrap_or_else(|| "https://testnet.zec.rocks:443".to_owned());
        let (mut client, _) =
            shadowallet_chain_zcash::connect(shadowallet_chain_zcash::TESTNET, &url)
                .await
                .unwrap();
        let mut hash = hex::decode(&args[0]).unwrap();
        hash.reverse();
        let r = client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash,
            })
            .await
            .unwrap()
            .into_inner();
        (r.data, Some(args[0].to_lowercase()), Some(r.height), url)
    };

    let tx = parse(&raw).expect("the official deserializer accepts the transaction");
    let txid = tx.txid().to_string();
    let mut again = Vec::new();
    tx.write(&mut again).unwrap();
    let version = match tx.version() {
        TxVersion::V5 => "5",
        TxVersion::V6 => "6",
        _ => "older",
    };
    println!("source: {source}");
    println!("mined_height_reported_by_server: {mined:?}");
    println!("raw_bytes: {}", raw.len());
    println!("version: {version}");
    println!(
        "consensus_branch_id: {:08x}",
        u32::from(tx.consensus_branch_id())
    );
    println!("expiry_height: {}", u32::from(tx.expiry_height()));
    println!("computed_txid: {txid}");
    let mut ok = true;
    if let Some(expected) = &expected_txid {
        println!("txid_matches_requested: {}", *expected == txid);
        ok &= *expected == txid;
    }
    println!("reserialization_identical: {}", again == raw);
    ok &= again == raw;
    println!(
        "transparent_bundle_present: {}",
        tx.transparent_bundle().is_some()
    );
    println!("sapling_bundle_present: {}", tx.sapling_bundle().is_some());

    let pools = [
        ("orchard", tx.orchard_bundle()),
        ("ironwood", tx.ironwood_bundle()),
    ];
    let mut verified = 0usize;
    if pools.iter().any(|(_, b)| b.is_some()) {
        let started = std::time::Instant::now();
        // The post-NU6.3 circuit is shared by both pools (branch 0x77190ad9 onward).
        let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
        println!("verifying_key_build_ms: {}", started.elapsed().as_millis());
        let digest = sighash(&raw);
        for (name, bundle) in pools {
            let Some(bundle) = bundle else {
                println!("{name}_bundle: absent");
                continue;
            };
            println!("{name}_actions: {}", bundle.actions().len());
            println!("{name}_anchor: {}", hex::encode(bundle.anchor().to_bytes()));
            println!(
                "{name}_nullifiers: {}",
                bundle
                    .actions()
                    .iter()
                    .map(|a| hex::encode(a.nullifier().to_bytes()))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!(
                "{name}_public_value_balance_zat: {}",
                i64::from(*bundle.value_balance())
            );
            let started = std::time::Instant::now();
            let good = valid(&vk, bundle, digest);
            println!(
                "{name}_proof_and_signatures_valid: {good} ({} ms)",
                started.elapsed().as_millis()
            );
            ok &= good;
            if good {
                verified += 1;
            }
            // Negative control 1: a different signature hash must be refused.
            let mut other = digest;
            other[0] ^= 1;
            let refused = !valid(&vk, bundle, other);
            println!("{name}_negative_wrong_sighash_refused: {refused}");
            ok &= refused;
        }
        // Negative control 2: one flipped byte inside a Halo 2 proof must be refused (by the parser or the verifier).
        let (_, bundle) = [
            ("orchard", tx.orchard_bundle()),
            ("ironwood", tx.ironwood_bundle()),
        ]
        .into_iter()
        .find(|(_, b)| b.is_some())
        .unwrap();
        let proof = bundle.unwrap().authorization().proof().as_ref().to_vec();
        let at = raw
            .windows(proof.len())
            .position(|w| w == proof.as_slice())
            .expect("the proof bytes are in the serialization");
        let mut damaged = raw.clone();
        damaged[at + proof.len() / 2] ^= 0x01;
        let refused = match parse(&damaged) {
            Err(_) => true,
            Ok(bad) => {
                let b = bad
                    .orchard_bundle()
                    .or_else(|| bad.ironwood_bundle())
                    .unwrap();
                !valid(&vk, b, sighash(&damaged))
            }
        };
        println!("negative_damaged_proof_refused: {refused}");
        ok &= refused;
        // Negative control 3: a truncated serialization must not parse.
        let truncated = parse(&raw[..raw.len() - 7]).is_err();
        println!("negative_truncated_serialization_refused: {truncated}");
        ok &= truncated;
    }
    println!("shielded_bundles_verified: {verified}");
    if tx.sapling_bundle().is_some() {
        println!("NOTE: a Sapling bundle is present and its proofs are NOT verified by this tool");
        ok = false;
    }
    println!(
        "VERDICT: {}",
        if ok && verified > 0 {
            "PASS"
        } else {
            "NOT PASSED"
        }
    );
    std::process::exit(i32::from(!(ok && verified > 0)));
}
