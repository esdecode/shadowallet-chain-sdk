//! Synchronization, balances, addresses and history.

use zcash_client_backend::data_api::{WalletRead, WalletWrite, wallet::ConfirmationsPolicy};

use crate::wallet::{Client, MemBlockCache};
use crate::{ADDRESS_REQUEST, ZcashError, ZcashWallet};

fn wallet(e: impl std::fmt::Debug) -> ZcashError {
    ZcashError::Wallet(format!("{e:?}"))
}

/// Scan the chain to the server's tip (compact blocks, note discovery, reorganization handling, Orchard and
/// transparent). Blocks are fetched in batches of `batch_size`; the commitment tree subtrees are fetched first.
pub async fn sync(
    w: &mut ZcashWallet,
    client: &mut Client,
    batch_size: u32,
) -> Result<(), ZcashError> {
    let cache = MemBlockCache::default();
    let params = w.net.params();
    zcash_client_backend::sync::run(
        client,
        &params,
        &cache,
        &mut w.db,
        batch_size.clamp(10, 1000),
    )
    .await
    .map_err(|e| ZcashError::Wallet(format!("sync: {e}")))?;
    enhance_transactions(w, client).await
}

/// Complete the reference compact-block scanner's requested raw transaction
/// enhancement and transparent spentness checks. A network failure is never
/// interpreted as proof that a pending transaction cannot confirm.
async fn enhance_transactions(w: &mut ZcashWallet, client: &mut Client) -> Result<(), ZcashError> {
    use zcash_client_backend::data_api::TransactionDataRequest;
    use zcash_client_backend::proto::service::{
        BlockId, BlockRange, TransparentAddressBlockFilter, TxFilter,
    };
    use zcash_keys::encoding::AddressCodec as _;
    let tip = update_tip(w, client).await?;
    for request in w.db.transaction_data_requests().map_err(wallet)? {
        match request {
            TransactionDataRequest::GetStatus(txid) | TransactionDataRequest::Enhancement(txid) => {
                let raw = client
                    .get_transaction(TxFilter {
                        block: None,
                        index: 0,
                        hash: txid.as_ref().to_vec(),
                    })
                    .await
                    .map_err(|e| ZcashError::Server(e.to_string()))?
                    .into_inner();
                let _actual = store_raw_transaction(w, &raw, tip, Some(txid))?;
            }
            TransactionDataRequest::TransactionsInvolvingAddress(query) => {
                if query
                    .request_at()
                    .is_some_and(|t| t > std::time::SystemTime::now())
                {
                    continue;
                }
                let end = query
                    .block_range_end()
                    .map(u32::from)
                    .unwrap_or(tip.saturating_add(1));
                let start = u32::from(query.block_range_start());
                if end <= start {
                    continue;
                }
                let mut stream = client
                    .get_taddress_transactions(TransparentAddressBlockFilter {
                        address: query.address().encode(&w.net.params()),
                        range: Some(BlockRange {
                            start: Some(BlockId {
                                height: u64::from(start),
                                hash: vec![],
                            }),
                            end: Some(BlockId {
                                height: u64::from(end - 1),
                                hash: vec![],
                            }),
                            ..Default::default()
                        }),
                    })
                    .await
                    .map_err(|e| ZcashError::Server(e.to_string()))?
                    .into_inner();
                while let Some(raw) = stream
                    .message()
                    .await
                    .map_err(|e| ZcashError::Server(e.to_string()))?
                {
                    if raw.height < u64::from(start) || raw.height >= u64::from(end) {
                        return Err(ZcashError::Server(
                            "transaction is outside the requested block range".to_owned(),
                        ));
                    }
                    store_raw_transaction(w, &raw, tip, None)?;
                }
                w.db.notify_address_checked(
                    query,
                    zcash_protocol::consensus::BlockHeight::from_u32(end - 1),
                )
                .map_err(wallet)?;
            }
        }
    }
    Ok(())
}

fn store_raw_transaction(
    w: &mut ZcashWallet,
    raw: &zcash_client_backend::proto::service::RawTransaction,
    tip: u32,
    expected: Option<zcash_protocol::TxId>,
) -> Result<zcash_protocol::TxId, ZcashError> {
    use zcash_client_backend::data_api::{
        TransactionStatus, wallet::decrypt_and_store_transaction,
    };
    use zcash_protocol::consensus::{BlockHeight, BranchId};
    let height = match raw.height {
        0 | u64::MAX => None,
        n if n <= u64::from(tip) => Some(BlockHeight::from_u32(n as u32)),
        _ => return Err(ZcashError::Server("invalid transaction height".to_owned())),
    };
    let params = w.net.params();
    let branch = BranchId::for_height(
        &params,
        height.unwrap_or(BlockHeight::from_u32(tip.saturating_add(1))),
    );
    let tx = zcash_primitives::transaction::Transaction::read(raw.data.as_slice(), branch)
        .map_err(|e| ZcashError::Server(format!("invalid transaction: {e}")))?;
    if expected.is_some_and(|id| id != tx.txid()) {
        return Err(ZcashError::Server(
            "server returned another transaction".to_owned(),
        ));
    }
    decrypt_and_store_transaction(&params, &mut w.db, &tx, height).map_err(wallet)?;
    w.db.set_transaction_status(
        tx.txid(),
        height
            .map(TransactionStatus::Mined)
            .unwrap_or(TransactionStatus::NotInMainChain),
    )
    .map_err(wallet)?;
    Ok(tx.txid())
}

/// Balances in zatoshi, split by what can be spent now and what is still pending.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balances {
    pub ironwood_spendable: u64,
    pub ironwood_pending: u64,
    pub orchard_spendable: u64,
    pub orchard_pending: u64,
    pub sapling_total: u64,
    pub transparent_spendable: u64,
    pub transparent_pending: u64,
    pub chain_tip: u32,
    pub fully_scanned: u32,
    /// Scan progress, 0..=1 000 000 (parts per million).
    pub scan_progress_ppm: u32,
}

pub fn balances(w: &ZcashWallet) -> Result<Balances, ZcashError> {
    let mut out = Balances::default();
    let Some(summary) =
        w.db.get_wallet_summary(ConfirmationsPolicy::default())
            .map_err(wallet)?
    else {
        return Ok(out);
    };
    out.chain_tip = u32::from(summary.chain_tip_height());
    out.fully_scanned = u32::from(summary.fully_scanned_height());
    let p = summary.progress().scan();
    out.scan_progress_ppm = (*p.numerator() * 1_000_000 / (*p.denominator()).max(1)) as u32;
    if let Some(b) = summary.account_balances().get(&w.account) {
        let i = b.ironwood_balance();
        out.ironwood_spendable = u64::from(i.spendable_value());
        out.ironwood_pending =
            u64::from(i.change_pending_confirmation()) + u64::from(i.value_pending_spendability());
        let o = b.orchard_balance();
        out.orchard_spendable = u64::from(o.spendable_value());
        out.orchard_pending =
            u64::from(o.change_pending_confirmation()) + u64::from(o.value_pending_spendability());
        out.sapling_total = u64::from(b.sapling_balance().total());
        let t = b.unshielded_balance();
        out.transparent_spendable = u64::from(t.spendable_value());
        out.transparent_pending =
            u64::from(t.change_pending_confirmation()) + u64::from(t.value_pending_spendability());
    }
    Ok(out)
}

/// The account's current unified address (Orchard + transparent), generating the first one if needed.
pub fn current_address(w: &mut ZcashWallet) -> Result<String, ZcashError> {
    let params = w.net.params();
    if let Some(a) =
        w.db.get_last_generated_address_matching(w.account, ADDRESS_REQUEST)
            .map_err(wallet)?
    {
        return Ok(a.encode(&params));
    }
    let (a, _) =
        w.db.get_next_available_address(w.account, ADDRESS_REQUEST)
            .map_err(wallet)?
            .ok_or_else(|| ZcashError::Wallet("no address could be generated".to_owned()))?;
    Ok(a.encode(&params))
}

/// A fresh diversified unified address (new receivers, same account): for a new payer.
pub fn new_address(w: &mut ZcashWallet) -> Result<String, ZcashError> {
    let params = w.net.params();
    let (a, _) =
        w.db.get_next_available_address(w.account, ADDRESS_REQUEST)
            .map_err(wallet)?
            .ok_or_else(|| ZcashError::Wallet("no address could be generated".to_owned()))?;
    Ok(a.encode(&params))
}

pub fn transparent_address_of(w: &ZcashWallet) -> Result<String, ZcashError> {
    crate::account::transparent_address(w.net, &w.ufvk)
}

/// One wallet transaction as the wallet database records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRow {
    pub txid: String,
    pub mined_height: Option<u32>,
    pub expired_unmined: bool,
    /// Net change of this account's balance, in zatoshi (negative = sent).
    pub balance_delta: i64,
    pub fee: Option<u64>,
    pub sent_notes: u32,
    pub received_notes: u32,
    pub block_time: Option<i64>,
}

/// Transaction history from the wallet database's `v_transactions` view (read-only second connection).
pub fn history(w: &ZcashWallet, limit: u32) -> Result<Vec<TxRow>, ZcashError> {
    let conn = rusqlite::Connection::open_with_flags(
        &w.db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(wallet)?;
    let account_uuid = w.account.expose_uuid();
    let mut stmt = conn
        .prepare(
            "SELECT txid, mined_height, expired_unmined, account_balance_delta, fee_paid, sent_note_count, received_note_count, block_time
             FROM v_transactions WHERE account_uuid = ?1 ORDER BY COALESCE(mined_height, 4294967295) DESC, tx_index DESC LIMIT ?2",
        )
        .map_err(wallet)?;
    let rows = stmt
        .query_map(
            rusqlite::params![account_uuid.as_bytes().to_vec(), limit],
            |r| {
                Ok(TxRow {
                    txid: canonical_txid(&r.get::<_, Vec<u8>>(0)?)?,
                    mined_height: r.get::<_, Option<i64>>(1)?.map(|h| h as u32),
                    expired_unmined: r.get::<_, i64>(2)? != 0,
                    balance_delta: r.get(3)?,
                    fee: r.get::<_, Option<i64>>(4)?.map(|f| f as u64),
                    sent_notes: r.get::<_, i64>(5)? as u32,
                    received_notes: r.get::<_, i64>(6)? as u32,
                    block_time: r.get(7)?,
                })
            },
        )
        .map_err(wallet)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wallet)
}

fn canonical_txid(bytes: &[u8]) -> Result<String, rusqlite::Error> {
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(zcash_protocol::TxId::from_bytes(raw).to_string())
}

/// Keep the wallet's view of the chain tip current (the server's tip), needed before balances and proposals.
pub async fn update_tip(w: &mut ZcashWallet, client: &mut Client) -> Result<u32, ZcashError> {
    let tip = crate::wallet::latest_height(client).await?;
    w.db.update_chain_tip(zcash_protocol::consensus::BlockHeight::from_u32(tip))
        .map_err(wallet)?;
    Ok(tip)
}

#[cfg(test)]
mod tests {
    #[test]
    fn history_ids_match_rpc_and_explorer_byte_order() {
        let bytes: Vec<u8> = (0..32).collect();
        assert_eq!(
            super::canonical_txid(&bytes).unwrap(),
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        );
        assert!(super::canonical_txid(&[0; 31]).is_err());
    }
}
