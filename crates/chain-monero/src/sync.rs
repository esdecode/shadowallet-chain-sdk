//! Node connection (genesis identity verified), block scanning, spend detection and reorg rollback.

use std::collections::HashMap;

use monero_simple_request_rpc::SimpleRequestTransport;
use monero_wallet::transaction::Timelock;
use monero_wallet::{
    Scanner,
    address::SubaddressIndex,
    block::Block,
    interface::{
        ProvidesBlockchain, ProvidesBlockchainMeta, ProvidesScannableBlocks, ProvidesTransactions,
    },
    transaction::Input,
};

use crate::{
    MoneroAccount, MoneroError, MoneroNet, MoneroStore, OwnedOutput, SPEND_CONFIRMATIONS, TxRecord,
};

pub type Daemon = monero_daemon_rpc::MoneroDaemon<SimpleRequestTransport>;

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
pub async fn connect(net: MoneroNet, url: &str) -> Result<Node, MoneroError> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(MoneroError::Node("node URL must be http(s)".to_owned()));
    }
    let daemon = SimpleRequestTransport::new(url.to_owned())
        .await
        .map_err(node_err)?;
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
    for i in 1..=20u32 {
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
            let number = block.block.number() as u64;
            let hash = block.block.hash();
            // 1. spends: any input whose key image belongs to one of our outputs
            let mut spent_value: HashMap<[u8; 32], u64> = HashMap::new();
            for (txid, tx) in block
                .block
                .transactions
                .iter()
                .zip(block.transactions.iter())
            {
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
            for (txid, gross) in spent_value {
                store.upsert_tx(&TxRecord {
                    txid,
                    direction: "out".to_owned(),
                    amount: gross,
                    fee: 0,
                    height: Some(number),
                    status: "confirmed".to_owned(),
                    counterparty: None,
                    created_ms: 0,
                })?;
                store.set_tx_status(&txid, "confirmed", Some(number))?;
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

/// Settle outgoing transactions that never confirmed. A transaction the node no longer knows after `max_age_ms`
/// is marked failed and its outputs are released for spending again.
pub async fn reconcile_pending(
    store: &MoneroStore,
    node: &Node,
    now_ms: u64,
    max_age_ms: u64,
) -> Result<u32, MoneroError> {
    let mut released = 0;
    for rec in store
        .history(200)?
        .into_iter()
        .filter(|r| r.direction == "out" && r.status == "pending")
    {
        if now_ms.saturating_sub(rec.created_ms) < max_age_ms {
            continue;
        }
        if node.daemon.transaction(rec.txid).await.is_err() {
            store.set_tx_status(&rec.txid, "failed", None)?;
            store.unreserve_all()?;
            released += 1;
        }
    }
    Ok(released)
}
