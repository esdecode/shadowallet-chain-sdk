//! Output selection, decoy selection (via monero-oxide), fee, CLSAG + Bulletproofs+ signing and publication.
//! All ring-signature and range-proof cryptography is monero-oxide's; nothing is implemented here.

use std::collections::HashMap;

use monero_wallet::{
    OutputWithDecoys, WalletOutput,
    address::MoneroAddress,
    interface::{FeePriority, ProvidesBlockchainMeta, ProvidesFeeRates, PublishTransaction},
    ringct::RctType,
    send::{Change, SendError, SignableTransaction},
    transaction::Transaction,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    MoneroAccount, MoneroError, MoneroStore, Node, SPEND_CONFIRMATIONS, TxRecord, parse_address,
};

/// Ring size of current Monero (hard fork 16 and later).
pub const RING_SIZE: u8 = 16;
/// Refuse fee rates above this many piconero per weight unit (a hostile node could otherwise drain the wallet in fees).
const MAX_FEE_PER_WEIGHT: u64 = 2_000_000;
const MAX_OUTPUTS: usize = 16;

/// A fully built but unsigned transaction and what the user reviews.
pub struct PreparedSend {
    signable: SignableTransaction,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub input_total: u64,
    pub input_ids: Vec<i64>,
    pub ring_size: u8,
    pub tip: u64,
}

fn node_err(e: impl std::fmt::Debug) -> MoneroError {
    MoneroError::Node(format!("{e:?}"))
}

/// Build (but do not sign) a transaction paying `amount` piconero to `to`.
/// Selected outputs are reserved until the send is published, failed or released.
pub async fn prepare_send(
    store: &MoneroStore,
    account: &MoneroAccount,
    node: &Node,
    to: &str,
    amount: u64,
    priority: FeePriority,
) -> Result<PreparedSend, MoneroError> {
    if node.net.is_mainnet {
        return Err(MoneroError::Send("mainnet signing is disabled".to_owned()));
    }
    if amount == 0 {
        return Err(MoneroError::Send(
            "the amount must be greater than zero".to_owned(),
        ));
    }
    let address: MoneroAddress = parse_address(node.net.network, to)?;
    let tip = node.daemon.latest_block_number().await.map_err(node_err)? as u64;
    let fee_rate = node
        .daemon
        .fee_rate(priority, MAX_FEE_PER_WEIGHT)
        .await
        .map_err(node_err)?;

    let mut spendable: Vec<_> = store
        .outputs()?
        .into_iter()
        .filter(|o| {
            o.spent_in.is_none()
                && !o.reserved
                && tip + 1 >= o.height + SPEND_CONFIRMATIONS as u64
                && o.timelock_height <= tip + 1
        })
        .collect();
    spendable.sort_by_key(|o| std::cmp::Reverse(o.amount));
    let available: u64 = spendable.iter().map(|o| o.amount).sum();

    let mut decoyed: HashMap<i64, OutputWithDecoys> = HashMap::new();
    let mut chosen = Vec::new();
    let mut last_err = None;
    for out in spendable.iter().take(MAX_OUTPUTS) {
        let mut cursor = std::io::Cursor::new(&out.blob);
        let wallet_output = WalletOutput::read(&mut cursor)
            .map_err(|e| MoneroError::Store(format!("stored output: {e}")))?;
        let with_decoys = OutputWithDecoys::new(
            &mut OsRng,
            &node.daemon,
            RING_SIZE,
            tip as usize,
            wallet_output,
        )
        .await
        .map_err(node_err)?;
        decoyed.insert(out.id, with_decoys);
        chosen.push(out.clone());
        let inputs: Vec<OutputWithDecoys> = chosen
            .iter()
            .filter_map(|c| decoyed.get(&c.id).cloned())
            .collect();
        let mut ovk = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(ovk.as_mut());
        match SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            ovk,
            inputs,
            vec![(address, amount)],
            Change::new(account.view_pair().clone(), None),
            vec![],
            fee_rate,
        ) {
            Ok(signable) => {
                let fee = signable.necessary_fee();
                let input_total: u64 = chosen.iter().map(|c| c.amount).sum();
                let change = input_total.saturating_sub(amount).saturating_sub(fee);
                let input_ids: Vec<i64> = chosen.iter().map(|c| c.id).collect();
                store.reserve(&input_ids, true)?;
                return Ok(PreparedSend {
                    signable,
                    to: to.trim().to_owned(),
                    amount,
                    fee,
                    change,
                    input_total,
                    input_ids,
                    ring_size: RING_SIZE,
                    tip,
                });
            }
            Err(SendError::NotEnoughFunds { .. }) => {
                last_err = Some(format!("selected {} output(s), still short", chosen.len()));
            }
            Err(other) => return Err(MoneroError::Send(other.to_string())),
        }
    }
    Err(MoneroError::Send(format!(
        "insufficient unlocked funds: {available} piconero spendable (outputs unlock after {SPEND_CONFIRMATIONS} confirmations){}",
        last_err.map(|e| format!("; {e}")).unwrap_or_default()
    )))
}

/// Sign with the account's spend key. The caller (the wallet's authorization boundary) must have been
/// explicitly authorized; mainnet is refused again here.
pub fn sign_prepared(
    account: &MoneroAccount,
    node: &Node,
    prepared: PreparedSend,
) -> Result<Transaction, MoneroError> {
    if node.net.is_mainnet {
        return Err(MoneroError::Send("mainnet signing is disabled".to_owned()));
    }
    prepared
        .signable
        .sign(&mut OsRng, account.spend_scalar())
        .map_err(|e| MoneroError::Send(e.to_string()))
}

/// Persist the transaction as pending BEFORE publishing it, then publish. A publish error that is not a definitive
/// rejection leaves the row pending (it may have reached the network); the caller reconciles later.
pub async fn publish_signed(
    store: &MoneroStore,
    node: &Node,
    tx: &Transaction,
    to: &str,
    amount: u64,
    fee: u64,
    now_ms: u64,
) -> Result<[u8; 32], MoneroError> {
    let txid = tx.hash();
    store.upsert_tx(&TxRecord {
        txid,
        direction: "out".to_owned(),
        amount,
        fee,
        height: None,
        status: "pending".to_owned(),
        counterparty: Some(to.to_owned()),
        created_ms: now_ms,
    })?;
    node.daemon
        .publish_transaction(tx)
        .await
        .map_err(|e| MoneroError::Node(format!("publish: {e:?}")))?;
    Ok(txid)
}
