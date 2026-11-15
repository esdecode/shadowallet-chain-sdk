use dcr_rs::address::Address;
use dcr_rs::sighash::prefix_hash_all;
use dcr_rs::sign::sign_p2pkh_input_cached;
use dcr_rs::tx::{
    MAX_TX_IN_SEQUENCE, MsgTx, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX, OutPoint, TxIn, TxOut,
};

use crate::DecredError;
use crate::account::Account;
use crate::net::VerifiedNet;
use crate::rpc::DcrdRpc;
use crate::wallet::{Scan, Utxo};

/// Default relay fee: 10000 atoms per 1000 bytes (0.0001 DCR/kB), as enforced by dcrd.
pub const DEFAULT_FEE_RATE: i64 = 10_000;
/// Outputs below this value are dust at the default relay fee and are rejected by dcrd.
pub const DUST: i64 = 6_030;
/// Serialized size of a signature script for a compressed-key P2PKH input (push 72-byte DER + type, push 33-byte key).
const SIG_SCRIPT_MAX: usize = 107;

#[derive(Clone, Debug)]
pub struct PreparedSend {
    pub network: &'static str,
    pub to: String,
    pub amount: i64,
    pub fee: i64,
    pub change: Option<(String, i64)>,
    pub inputs: Vec<Utxo>,
    tx: MsgTx,
}

fn size_with(tx: &MsgTx) -> usize {
    let mut probe = tx.clone();
    for input in &mut probe.tx_in {
        input.signature_script = vec![0u8; SIG_SCRIPT_MAX];
    }
    probe.serialize_full().len()
}

fn fee_for(size: usize, rate_per_kb: i64) -> i64 {
    (size as i64 * rate_per_kb + 999) / 1000
}

fn outpoint_hash(txid: &str) -> Result<[u8; 32], DecredError> {
    let mut hash = [0u8; 32];
    hex::decode_to_slice(txid, &mut hash).map_err(|_| DecredError::Send("bad txid".into()))?;
    hash.reverse(); // dcrd displays hashes byte-reversed
    Ok(hash)
}

/// Largest-first coin selection with an exact size-based fee. Only confirmed, mature outputs are spent.
pub fn prepare_send(
    scan: &Scan,
    account: &Account,
    to: &str,
    amount: i64,
    fee_rate: i64,
) -> Result<PreparedSend, DecredError> {
    if account.net.is_mainnet {
        return Err(DecredError::Send(
            "Decred mainnet signing and broadcasting are disabled".into(),
        ));
    }
    if amount < DUST {
        return Err(DecredError::Send(format!(
            "amount is below the dust limit of {DUST} atoms"
        )));
    }
    if fee_rate < 1_000 {
        return Err(DecredError::Send(
            "fee rate is below the 1000 atoms/kB floor".into(),
        ));
    }
    let destination = Address::decode_for(to, account.net.network)
        .map_err(|e| DecredError::Address(format!("{e:?}")))?;
    let mut candidates: Vec<&Utxo> = scan
        .utxos
        .iter()
        .filter(|u| {
            u.confirmations >= 1
                && (!u.coinbase || u.confirmations >= scan.coinbase_maturity)
                && u.tree == 0
        })
        .collect();
    candidates.sort_by(|a, b| b.value.cmp(&a.value).then(a.txid.cmp(&b.txid)));
    let change_address = account.address(1, scan.next_internal)?;
    let change_script = Address::decode_for(&change_address, account.net.network)
        .map_err(|e| DecredError::Address(format!("{e:?}")))?
        .pk_script();
    let mut chosen: Vec<Utxo> = Vec::new();
    let mut total = 0i64;
    for utxo in candidates {
        chosen.push(utxo.clone());
        total += utxo.value;
        let mut tx = build(&chosen, &destination.pk_script(), amount, None)?;
        let fee_no_change = fee_for(size_with(&tx), fee_rate);
        if total < amount + fee_no_change {
            continue;
        }
        tx = build(
            &chosen,
            &destination.pk_script(),
            amount,
            Some((&change_script, 0)),
        )?;
        let fee_change = fee_for(size_with(&tx), fee_rate);
        let change = total - amount - fee_change;
        if change >= DUST {
            let tx = build(
                &chosen,
                &destination.pk_script(),
                amount,
                Some((&change_script, change)),
            )?;
            return Ok(PreparedSend {
                network: account.net.name,
                to: to.to_string(),
                amount,
                fee: fee_change,
                change: Some((change_address, change)),
                inputs: chosen,
                tx,
            });
        }
        // Change would be dust: it is added to the fee instead.
        let tx = build(&chosen, &destination.pk_script(), amount, None)?;
        return Ok(PreparedSend {
            network: account.net.name,
            to: to.to_string(),
            amount,
            fee: total - amount,
            change: None,
            inputs: chosen,
            tx,
        });
    }
    Err(DecredError::Send(
        "insufficient spendable funds (confirmed, mature outputs only)".into(),
    ))
}

fn build(
    inputs: &[Utxo],
    to_script: &[u8],
    amount: i64,
    change: Option<(&[u8], i64)>,
) -> Result<MsgTx, DecredError> {
    let tx_in = inputs
        .iter()
        .map(|u| {
            Ok(TxIn {
                previous_outpoint: OutPoint {
                    hash: outpoint_hash(&u.txid)?,
                    index: u.vout,
                    tree: u.tree,
                },
                sequence: MAX_TX_IN_SEQUENCE,
                value_in: u.value,
                block_height: NULL_BLOCK_HEIGHT,
                block_index: NULL_BLOCK_INDEX,
                signature_script: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, DecredError>>()?;
    let mut tx_out = vec![TxOut {
        value: amount,
        version: 0,
        pk_script: to_script.to_vec(),
    }];
    if let Some((script, value)) = change {
        tx_out.push(TxOut {
            value,
            version: 0,
            pk_script: script.to_vec(),
        });
    }
    Ok(MsgTx {
        version: 1,
        tx_in,
        tx_out,
        lock_time: 0,
        expiry: 0,
    })
}

/// Sign every input with its own derived key, verify the result locally, and broadcast. The caller must have passed
/// the Rust authorization boundary; `net` can only be a verified non-mainnet network.
pub async fn sign_and_broadcast(
    rpc: &DcrdRpc,
    net: &VerifiedNet,
    account: &Account,
    prepared: PreparedSend,
) -> Result<String, DecredError> {
    if net.0.is_mainnet || account.net != net.0 || prepared.network != net.0.name {
        return Err(DecredError::Send(
            "network mismatch between the verified node, account and review".into(),
        ));
    }
    let mut tx = prepared.tx.clone();
    let prefix = prefix_hash_all(&tx);
    for (i, utxo) in prepared.inputs.iter().enumerate() {
        let secret = account.secret(utxo.branch, utxo.index)?;
        tx.tx_in[i].signature_script =
            sign_p2pkh_input_cached(account.secp(), &tx, i, &utxo.script, &secret, &prefix)
                .map_err(|e| DecredError::Send(format!("signing failed: {e:?}")))?;
    }
    let raw = tx.serialize_full();
    // Round-trip: what is broadcast must parse back to exactly what was reviewed and signed.
    let parsed = MsgTx::parse_full(&raw)
        .map_err(|e| DecredError::Send(format!("signed transaction does not re-parse: {e:?}")))?;
    if parsed != tx || parsed.tx_out != prepared.tx.tx_out {
        return Err(DecredError::Send(
            "signed transaction differs from the reviewed one".into(),
        ));
    }
    let txid = rpc.send_raw(&hex::encode(&raw)).await?;
    let mut expected = tx.tx_hash();
    expected.reverse();
    if txid != hex::encode(expected) {
        return Err(DecredError::Rpc(
            "node returned a different txid than the one signed".into(),
        ));
    }
    Ok(txid)
}
