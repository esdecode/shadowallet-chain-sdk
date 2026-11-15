//! Node connection (genesis identity verified), block scanning, spend detection and reorg rollback.

use std::collections::HashMap;

use monero_wallet::transaction::Timelock;
use monero_wallet::{
    Scanner,
    address::SubaddressIndex,
    block::Block,
    interface::{ProvidesBlockchain, ProvidesBlockchainMeta, ProvidesScannableBlocks},
    transaction::{Input, Transaction},
};

use crate::{
    MoneroAccount, MoneroError, MoneroNet, MoneroStore, OwnedOutput, SPEND_CONFIRMATIONS, TxRecord,
};

pub type Daemon = monero_daemon_rpc::MoneroDaemon<crate::ProxyTransport>;

/// A connected node that was verified to serve the expected network.
pub struct Node {
    pub net: MoneroNet,
    pub daemon: Daemon,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub from: u64,
    pub to: u64,
    pub tip: u64,
    pub new_outputs: u32,
    pub spent_outputs: u32,
    pub reorg_depth: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub total: u64,
    pub unlocked: u64,
    pub locked: u64,
    pub spendable_outputs: u32,
}

fn node_err(e: impl std::fmt::Debug) -> MoneroError {
    MoneroError::Node(format!("{e:?}"))
}

/// Connect to a node over HTTP(S) and verify that block 0 is this network's genesis block.
/// Third-party nodes learn your IP address and which blocks you request; see docs/shadowallet-privacy-features.md.
pub async fn connect(net: MoneroNet, url: &str, proxy: Option<&str>) -> Result<Node, MoneroError> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(MoneroError::Node("node URL must be http(s)".to_owned()));
    }
    let transport = crate::ProxyTransport::new(url, proxy).map_err(node_err)?;
    let daemon = Daemon::new(transport).await.map_err(node_err)?;
    let genesis = daemon.block_by_number(0).await.map_err(node_err)?;
    if genesis.hash() != net.genesis_hash {
        return Err(MoneroError::Network(format!(
            "the node does not serve {}: block 0 is {}",
            net.name,
            hex::encode(genesis.hash())
        )));
    }
    Ok(Node { net, daemon })
}

/// The node's current tip height.
pub async fn tip(node: &Node) -> Result<u64, MoneroError> {
    Ok(node.daemon.latest_block_number().await.map_err(node_err)? as u64)
}

fn timelock_height(t: Timelock) -> u64 {
    match t {
        Timelock::None => 0,
        Timelock::Block(h) => h as u64,
        // time-based locks are never treated as spendable by this wallet
        Timelock::Time(_) => i64::MAX as u64 / 2,
    }
}

/// Confirm that what we stored for `scanned` is still on the node's chain; roll back if not.
async fn check_reorg(store: &MoneroStore, node: &Node) -> Result<u32, MoneroError> {
    let mut scanned = store.scanned_height()?;
    let mut depth = 0u32;
    while scanned >= 0 {
        let Some(stored) = store.block_hash(scanned as u64)? else {
            break;
        };
        let on_chain: Block = node
            .daemon
            .block_by_number(scanned as usize)
            .await
            .map_err(node_err)?;
        if on_chain.hash() == stored {
            break;
        }
        depth += 1;
        scanned -= 1;
        if depth > 150 {
            return Err(MoneroError::Scan(
                "reorganization deeper than 150 blocks: refusing to continue".to_owned(),
            ));
        }
    }
    if depth > 0 {
        store.rollback_to(scanned.max(0) as u64)?;
    }
    Ok(depth)
}

/// Scan from the checkpoint to the node's tip (at most `max_blocks` blocks per call).
pub async fn sync(
    store: &MoneroStore,
    account: &MoneroAccount,
    node: &Node,
    max_blocks: usize,
) -> Result<SyncReport, MoneroError> {
    if max_blocks == 0 {
        return Err(MoneroError::Scan("max_blocks must be positive".to_owned()));
    }
    let tip = node.daemon.latest_block_number().await.map_err(node_err)? as u64;
    store.set_meta("tip", &tip.to_string())?;
    let reorg_depth = check_reorg(store, node).await?;
    let start = (store.scanned_height()? + 1).max(0) as u64;
    let mut report = SyncReport {
        from: start,
        to: start.saturating_sub(1),
        tip,
        reorg_depth,
        ..Default::default()
    };
    if start > tip {
        return Ok(report);
    }
    // unspent key images (updated as outputs are found): one lookup per input instead of a table scan
    let mut owned: HashMap<[u8; 32], u64> = store
        .outputs()?
        .into_iter()
        .filter(|o| o.spent_in.is_none())
        .map(|o| (o.key_image, o.amount))
        .collect();
    let mut scanner = Scanner::new(account.view_pair().clone());
    // Watch every issued address and a recovery lookahead. Never silently stop
    // at the twentieth address once additional receive addresses are issued.
    let watched_end = store.last_issued_subaddress()?.saturating_add(200).max(200);
    for i in 1..=watched_end {
        if let Some(index) = SubaddressIndex::new(0, i) {
            scanner.register_subaddress(index);
        }
    }
    let end = tip.min(start + max_blocks as u64 - 1);
    let mut next = start;
    while next <= end {
        let upper = end.min(next + 19);
        let blocks = node
            .daemon
            .contiguous_scannable_blocks(next as usize..=upper as usize)
            .await
            .map_err(node_err)?;
        for block in blocks {
            store.apply_block(|| {
                let number = block.block.number() as u64;
                let hash = block.block.hash();
                // 1. spends: any input whose key image belongs to one of our outputs
                let mut spent_value: HashMap<[u8; 32], u64> = HashMap::new();
                let mut fees: HashMap<[u8; 32], u64> = HashMap::new();
                for (txid, tx) in block
                    .block
                    .transactions
                    .iter()
                    .zip(block.transactions.iter())
                {
                    if let Transaction::V2 {
                        proofs: Some(proofs),
                        ..
                    } = tx
                    {
                        fees.insert(*txid, proofs.base.fee);
                    }
                    for input in &tx.prefix().inputs {
                        if let Input::ToKey { key_image, .. } = input {
                            let ki = key_image.to_bytes();
                            if let Some(amount) = owned.remove(&ki)
                                && store.mark_spent(&ki, txid)?
                            {
                                *spent_value.entry(*txid).or_default() += amount;
                                report.spent_outputs += 1;
                            }
                        }
                    }
                }
                // 2. receipts
                let found = scanner
                    .scan(block)
                    .map_err(|e| MoneroError::Scan(format!("{e:?}")))?
                    .ignore_additional_timelock();
                let mut received: HashMap<[u8; 32], u64> = HashMap::new();
                for out in found {
                    let key_image = account.key_image(out.key_offset(), out.key());
                    let amount = out.commitment().amount;
                    if let Some(sub) = out.subaddress() {
                        store.watch_subaddress(sub.address())?;
                    }
                    let owned_output = OwnedOutput {
                        id: 0,
                        txid: out.transaction(),
                        index_in_tx: out.index_in_transaction(),
                        amount,
                        height: number,
                        key_image,
                        subaddress: out.subaddress().map(|s| (s.account(), s.address())),
                        timelock_height: timelock_height(out.additional_timelock()),
                        blob: out.serialize(),
                        spent_in: None,
                        reserved: false,
                    };
                    if store.add_output(&owned_output)? {
                        report.new_outputs += 1;
                        owned.insert(owned_output.key_image, amount);
                        *received.entry(owned_output.txid).or_default() += amount;
                    }
                }
                // On seed-only recovery there is no saved send proposal. Reconstruct
                // net sent value from owned inputs minus change and the on-chain fee,
                // instead of displaying the entire selected input value as the payment.
                for (txid, gross) in spent_value {
                    let change = received.remove(&txid).unwrap_or(0);
                    let fee = fees.get(&txid).copied().unwrap_or(0);
                    let amount = gross
                        .checked_sub(change)
                        .and_then(|v| v.checked_sub(fee))
                        .ok_or_else(|| {
                            MoneroError::Scan("invalid outgoing value accounting".to_owned())
                        })?;
                    store.upsert_tx(&TxRecord {
                        txid,
                        direction: "out".to_owned(),
                        amount,
                        fee,
                        height: Some(number),
                        status: "confirmed".to_owned(),
                        counterparty: None,
                        created_ms: 0,
                    })?;
                    store.set_tx_status(&txid, "confirmed", Some(number))?;
                }
                for (txid, amount) in received {
                    store.upsert_tx(&TxRecord {
                        txid,
                        direction: "in".to_owned(),
                        amount,
                        fee: 0,
                        height: Some(number),
                        status: "confirmed".to_owned(),
                        counterparty: None,
                        created_ms: 0,
                    })?;
                }
                store.record_block(number, &hash)?;
                store.set_scanned(number)?;
                report.to = number;
                Ok(())
            })?;
        }
        next = upper + 1;
    }
    Ok(report)
}

/// Balances as of the stored tip. Outputs reserved by a prepared send are not counted as unlocked.
pub fn balance(store: &MoneroStore) -> Result<Balance, MoneroError> {
    let tip: u64 = store.meta("tip")?.and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut b = Balance::default();
    for o in store
        .outputs()?
        .into_iter()
        .filter(|o| o.spent_in.is_none())
    {
        b.total += o.amount;
        let confirmed = tip + 1 >= o.height + SPEND_CONFIRMATIONS as u64;
        let timelock_ok = o.timelock_height <= tip + 1;
        if confirmed && timelock_ok && !o.reserved {
            b.unlocked += o.amount;
            b.spendable_outputs += 1;
        } else {
            b.locked += o.amount;
        }
    }
    Ok(b)
}

/// Retained for compatibility: an absent transaction or a node error is NOT proof
/// that a signed transaction cannot still confirm. Pending inputs stay reserved
/// until their key images are observed on chain. Never release all wallet outputs
/// because one untrusted node failed to return a transaction.
pub async fn reconcile_pending(
    _store: &MoneroStore,
    _node: &Node,
    _now_ms: u64,
    _max_age_ms: u64,
) -> Result<u32, MoneroError> {
    Ok(0)
}
