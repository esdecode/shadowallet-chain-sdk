//! Synchronization, balances, addresses and history.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;
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
    sync_cancellable(w, client, batch_size, &CancelToken::new())
        .await
        .map(|_| ())
}

/// Cooperative cancellation of a running [`sync_cancellable`]. Cheap to clone; every clone controls the same flag, so
/// the token can live outside any lock that the running scan holds.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<TokenInner>);

#[derive(Debug, Default)]
struct TokenInner {
    flag: AtomicBool,
    wake: Notify,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the scan to stop at its next safe boundary. Never interrupts anything by itself.
    pub fn cancel(&self) {
        self.0.flag.store(true, Ordering::SeqCst);
        self.0.wake.notify_waiters();
    }

    /// Arm the token for a new scan.
    pub fn reset(&self) {
        self.0.flag.store(false, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.flag.load(Ordering::SeqCst)
    }

    /// Resolves once `cancel` has been called (immediately if it already was).
    pub async fn cancelled(&self) {
        loop {
            let notified = self.0.wake.notified();
            tokio::pin!(notified);
            // Register interest before the flag check, so a `cancel` between the two cannot be missed.
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// How a [`sync_cancellable`] call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The wallet reached the server's tip (including the requested transaction enhancement).
    Complete,
    /// The caller asked to stop. Everything scanned so far is committed; the next call continues from it.
    Cancelled,
}

/// Like [`sync`], but stops when `cancel` is triggered. Safe by construction, nothing is terminated:
///  * the scan only waits on the network at `await` points; all wallet-database work (`scan_cached_blocks`, subtree
///    roots, chain tip, rewinds) is synchronous and runs to completion in one SQLite transaction, so a cancel can only
///    take effect between two such steps and never in the middle of one;
///  * blocks that were downloaded but not yet scanned live in an in-memory cache and are simply fetched again;
///  * the verified scan checkpoint (`fully_scanned` / scan queue) is the wallet database itself, so it survives a cancel
///    and also a killed process, and the next call resumes from it.
pub async fn sync_cancellable(
    w: &mut ZcashWallet,
    client: &mut Client,
    batch_size: u32,
    cancel: &CancelToken,
) -> Result<SyncOutcome, ZcashError> {
    if cancel.is_cancelled() {
        return Ok(SyncOutcome::Cancelled);
    }
    let cache = MemBlockCache::default();
    let params = w.net.params();
    tokio::select! {
        biased;
        result = zcash_client_backend::sync::run(
            client,
            &params,
            &cache,
            &mut w.db,
            batch_size.clamp(10, 1000),
        ) => result.map_err(|e| ZcashError::Wallet(format!("sync: {e}")))?,
        () = cancel.cancelled() => return Ok(SyncOutcome::Cancelled),
    }
    enhance_transactions(w, client, cancel).await
}

/// Complete the reference compact-block scanner's requested raw transaction
/// enhancement and transparent spentness checks. A network failure is never
/// interpreted as proof that a pending transaction cannot confirm.
async fn enhance_transactions(
    w: &mut ZcashWallet,
    client: &mut Client,
    cancel: &CancelToken,
) -> Result<SyncOutcome, ZcashError> {
    use zcash_client_backend::data_api::TransactionDataRequest;
    use zcash_client_backend::proto::service::{
        BlockId, BlockRange, TransparentAddressBlockFilter, TxFilter,
    };
    use zcash_keys::encoding::AddressCodec as _;
    let tip = update_tip(w, client).await?;
    for request in w.db.transaction_data_requests().map_err(wallet)? {
        // Every request is independent and stays queued in the database until it is answered, so stopping between two of
        // them loses nothing.
        if cancel.is_cancelled() {
            return Ok(SyncOutcome::Cancelled);
        }
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
                    // Stopping here leaves the address request unanswered (it is only marked checked below), so the
                    // whole range is requested again next time; storing a transaction twice is idempotent.
                    if cancel.is_cancelled() {
                        return Ok(SyncOutcome::Cancelled);
                    }
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
    Ok(SyncOutcome::Complete)
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
    let conn = crate::wallet::connect_db(&w.db_path, w.db_key.as_ref(), true)?;
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

#[cfg(test)]
mod cancel_tests {
    use super::CancelToken;
    use std::time::Duration;

    #[tokio::test]
    async fn a_cancel_before_waiting_is_not_lost() {
        let token = CancelToken::new();
        token.cancel();
        tokio::time::timeout(Duration::from_secs(1), token.cancelled())
            .await
            .expect("an already-cancelled token resolves at once");
    }

    #[tokio::test]
    async fn a_cancel_while_waiting_wakes_every_clone() {
        let token = CancelToken::new();
        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let t = token.clone();
                tokio::spawn(async move { t.cancelled().await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!token.is_cancelled());
        token.cancel();
        for w in waiters {
            tokio::time::timeout(Duration::from_secs(1), w)
                .await
                .expect("woken")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn reset_rearms_the_token() {
        let token = CancelToken::new();
        token.cancel();
        token.reset();
        assert!(!token.is_cancelled());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), token.cancelled())
                .await
                .is_err(),
            "a reset token does not resolve"
        );
    }
}
