//! Transaction history with explicit completeness labels.
//!
//! Standard Ethereum JSON-RPC has no arbitrary-address full-history method.
//! Local history is therefore labelled `OutgoingOnly`; callers must not
//! present it as complete incoming history. ERC-20 transfers are derived from
//! `Transfer` logs over an explicit block range.

use sha3::{Digest, Keccak256};

use crate::{Address, B256, U256};

use crate::{EvmError, EvmProvider, EvmStore, StoredTransaction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryCompleteness {
    /// Only transactions created by this wallet; incoming native transfers are
    /// absent unless an external indexer is supplied.
    OutgoingOnly,
    /// Indexed history supplied by a trusted indexer.
    Indexed,
    /// Some pages may be incomplete (indexer lag, pruned logs).
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryItem {
    pub tx_hash: Option<String>,
    pub nonce: u64,
    pub to: String,
    pub value_wei: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub direction: &'static str,
    pub completeness: HistoryCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryPage {
    pub items: Vec<HistoryItem>,
    pub next_before_id: Option<i64>,
    pub completeness: HistoryCompleteness,
}

/// A paginated history source. Implementations may be local or indexer-backed.
pub trait HistorySource {
    fn page(
        &self,
        chain_id: u64,
        address: &str,
        limit: u32,
        before_id: Option<i64>,
    ) -> Result<HistoryPage, EvmError>;

    fn completeness(&self) -> HistoryCompleteness;
}

pub struct LocalHistory<'a> {
    store: &'a EvmStore,
}

impl<'a> LocalHistory<'a> {
    pub fn new(store: &'a EvmStore) -> Self {
        Self { store }
    }
}

impl HistorySource for LocalHistory<'_> {
    fn page(
        &self,
        chain_id: u64,
        address: &str,
        limit: u32,
        before_id: Option<i64>,
    ) -> Result<HistoryPage, EvmError> {
        let rows: Vec<StoredTransaction> =
            self.store.history(chain_id, address, limit, before_id)?;
        let next_before_id = rows.last().map(|r| r.id);
        Ok(HistoryPage {
            items: rows
                .into_iter()
                .map(|r| HistoryItem {
                    tx_hash: r.tx_hash,
                    nonce: r.nonce,
                    to: r.to,
                    value_wei: r.value_wei,
                    status: r.status,
                    block_number: r.block_number,
                    direction: "outgoing",
                    completeness: HistoryCompleteness::OutgoingOnly,
                })
                .collect(),
            next_before_id,
            completeness: HistoryCompleteness::OutgoingOnly,
        })
    }

    fn completeness(&self) -> HistoryCompleteness {
        HistoryCompleteness::OutgoingOnly
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erc20Transfer {
    pub token: Address,
    pub from: Address,
    pub to: Address,
    pub amount: U256,
    pub block_number: u64,
    pub tx_hash: B256,
    pub log_index: u64,
}

pub fn transfer_topic() -> B256 {
    B256::from_slice(&Keccak256::digest(b"Transfer(address,address,uint256)"))
}

/// Fetch ERC-20 `Transfer` logs for one token over an explicit block range.
/// Logs may be pruned or reorged; callers must treat results as partial.
pub async fn erc20_transfers(
    provider: &EvmProvider,
    token: Address,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Erc20Transfer>, EvmError> {
    if from_block > to_block {
        return Err(EvmError::History("invalid block range".to_owned()));
    }
    let logs = provider
        .logs(token, from_block, to_block)
        .await
        .map_err(|e| EvmError::History(e.to_string()))?;
    let mut out = Vec::with_capacity(logs.len());
    for log in logs {
        let topics = &log.topics;
        if topics.len() != 3 || topics[0] != transfer_topic() {
            continue;
        }
        let data = log.data.as_ref();
        if data.len() < 32 {
            continue;
        }
        out.push(Erc20Transfer {
            token,
            from: Address::from_slice(&topics[1].as_bytes()[12..]),
            to: Address::from_slice(&topics[2].as_bytes()[12..]),
            amount: U256::from_big_endian(&data[..32]),
            block_number: log.block_number.unwrap_or_default(),
            tx_hash: log.transaction_hash.unwrap_or_default(),
            log_index: log.log_index.unwrap_or_default(),
        });
    }
    Ok(out)
}
