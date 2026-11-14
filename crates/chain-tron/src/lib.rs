//! TRON for Shadowallet: Base58Check addresses, `m/44'/195'/0'/0/n` derivation, local protobuf
//! transaction construction and signing, TRX and TRC-20 transfers, resource (bandwidth/energy) fee
//! estimation, node access with network-identity verification, and a local transaction ledger.
//!
//! This crate never signs on its own authority: the caller (the wallet's Rust boundary) decides
//! whether a network may sign and holds the authorization. Transactions are built locally; the node
//! is never asked to construct one.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod account;
mod address;
mod network;
mod provider;
mod store;
pub mod tokens;
mod tx;

pub use account::{TronAccount, recover_signer};
pub use address::{ADDRESS_PREFIX, TronAddress};
pub use network::{MAINNET, NETWORKS, NILE, SHASTA, TronNetwork};
pub use provider::{
    ChainParams, ConstantCall, IncomingTransfer, NowBlock, Resources, TronProvider, TxInfo,
};
pub use store::{NewRecord, TronRecord, TronStore};
pub use tokens::{REGISTRY, TokenMeta, TokenTrust, VerifiedToken, format_units, parse_units};
pub use tx::{
    Action, BlockRef, DecodedTransaction, UnsignedTronTransaction, amount_word, describe_raw_data,
    trc20_transfer_data, word_to_decimal,
};

#[derive(Debug, thiserror::Error)]
pub enum TronError {
    #[error("invalid TRON address")]
    Address,
    #[error("key derivation failed")]
    Derivation,
    #[error("invalid amount")]
    Amount,
    #[error("node error: {0}")]
    Rpc(String),
    /// The node answered with an explicit refusal that cannot mean "already accepted".
    #[error("broadcast rejected by the node: {0}")]
    Rejected(String),
    #[error("network identity: {0}")]
    Network(String),
    #[error("transaction: {0}")]
    Transaction(String),
    #[error("token: {0}")]
    Token(String),
    #[error("store: {0}")]
    Store(String),
}

/// Transactions are valid for this long after the chain time they were built at.
pub const EXPIRATION_MS: u64 = 180_000;
/// A transaction included this many blocks ago is treated as final (about one minute on TRON).
pub const FINALITY_BLOCKS: u64 = 19;

/// Everything a reviewer sees, computed before anything is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TronProposal {
    pub unsigned: UnsignedTronTransaction,
    pub symbol: String,
    pub decimals: u8,
    /// Raw amount in the asset's smallest unit.
    pub amount_raw: String,
    pub bandwidth_bytes: u64,
    pub bandwidth_fee_sun: u64,
    pub energy_estimate: u64,
    pub energy_fee_sun: u64,
    pub activation_fee_sun: u64,
    pub fee_limit_sun: u64,
    /// Upper bound of TRX that may be burned (bandwidth + energy + activation).
    pub max_fee_sun: u64,
    pub recipient_activated: bool,
    pub token_trust: Option<TokenTrust>,
}

fn bandwidth_fee(bytes: u64, res: &Resources, params: &ChainParams) -> u64 {
    if res.free_bandwidth_available >= bytes || res.staked_bandwidth_available >= bytes {
        0
    } else {
        bytes * params.bandwidth_fee_sun
    }
}

/// Prepare a native TRX transfer. Fails closed when the balance cannot cover amount plus the worst-case fee.
pub async fn prepare_trx_transfer(
    provider: &TronProvider,
    owner: TronAddress,
    to: TronAddress,
    amount_sun: u64,
) -> Result<TronProposal, TronError> {
    let now = provider.now_block().await?;
    let params = provider.chain_params().await?;
    let balance = provider.balance_sun(&owner).await?.ok_or_else(|| {
        TronError::Transaction(
            "the sender account is not activated (no TRX received yet)".to_owned(),
        )
    })?;
    let recipient_activated = provider.balance_sun(&to).await?.is_some();
    let resources = provider.resources(&owner).await?;
    let unsigned = UnsignedTronTransaction {
        owner,
        action: Action::Trx { to, amount_sun },
        block: now.block,
        timestamp_ms: now.timestamp_ms,
        expiration_ms: now.timestamp_ms + EXPIRATION_MS,
        fee_limit_sun: 0,
    };
    let bytes = unsigned.bandwidth_bytes()?;
    let bandwidth_fee_sun = bandwidth_fee(bytes, &resources, &params);
    let activation_fee_sun = if recipient_activated {
        0
    } else {
        params.new_account_fee_sun
    };
    let max_fee_sun = bandwidth_fee_sun + activation_fee_sun;
    let need = amount_sun
        .checked_add(max_fee_sun)
        .ok_or(TronError::Amount)?;
    if balance < need {
        return Err(TronError::Transaction(format!(
            "insufficient TRX: balance {balance} sun, need {need} sun (amount + up to {max_fee_sun} sun fees)"
        )));
    }
    Ok(TronProposal {
        unsigned,
        symbol: "TRX".to_owned(),
        decimals: 6,
        amount_raw: amount_sun.to_string(),
        bandwidth_bytes: bytes,
        bandwidth_fee_sun,
        energy_estimate: 0,
        energy_fee_sun: 0,
        activation_fee_sun,
        fee_limit_sun: 0,
        max_fee_sun,
        recipient_activated,
        token_trust: None,
    })
}

/// Prepare a TRC-20 `transfer`. `amount_raw` is a decimal integer in the token's smallest unit.
pub async fn prepare_trc20_transfer(
    provider: &TronProvider,
    owner: TronAddress,
    contract: TronAddress,
    to: TronAddress,
    amount_raw: &str,
) -> Result<TronProposal, TronError> {
    let meta = provider.token_meta(&contract, &owner).await?;
    let word = amount_word(amount_raw)?;
    let balance = provider.trc20_balance(&contract, &owner).await?;
    if balance < word {
        return Err(TronError::Transaction(format!(
            "insufficient {} balance: {} < {}",
            meta.symbol,
            word_to_decimal(&balance),
            amount_raw
        )));
    }
    let now = provider.now_block().await?;
    let params = provider.chain_params().await?;
    let trx_balance = provider
        .balance_sun(&owner)
        .await?
        .ok_or_else(|| TronError::Transaction("the sender account is not activated".to_owned()))?;
    let resources = provider.resources(&owner).await?;
    // Simulate the exact call: a revert here means it would also fail on chain.
    let data = trc20_transfer_data(&to, &word);
    let sim = provider
        .constant_call(
            &owner,
            &contract,
            "transfer(address,uint256)",
            &hex::encode(&data[4..]),
        )
        .await
        .map_err(|e| TronError::Transaction(format!("the transfer would fail: {e}")))?;
    // Tokens that return `false` instead of reverting: a 32-byte zero answer is a refusal.
    if sim.result.len() == 32 && sim.result.iter().all(|b| *b == 0) {
        return Err(TronError::Transaction(
            "the token contract refuses this transfer (returned false)".to_owned(),
        ));
    }
    let energy_estimate = sim.energy_used;
    let energy_to_burn = energy_estimate.saturating_sub(resources.energy_available);
    let energy_fee_sun = energy_to_burn * params.energy_fee_sun;
    // The limit protects against a worse-than-simulated run, with headroom for state changes.
    let fee_limit_sun = (energy_estimate * params.energy_fee_sun * 12 / 10)
        .max(energy_fee_sun)
        .min(params.max_fee_limit_sun);
    let unsigned = UnsignedTronTransaction {
        owner,
        action: Action::Trc20 {
            contract,
            to,
            amount: word,
        },
        block: now.block,
        timestamp_ms: now.timestamp_ms,
        expiration_ms: now.timestamp_ms + EXPIRATION_MS,
        fee_limit_sun,
    };
    let bytes = unsigned.bandwidth_bytes()?;
    let bandwidth_fee_sun = bandwidth_fee(bytes, &resources, &params);
    let max_fee_sun = bandwidth_fee_sun + fee_limit_sun;
    if trx_balance < bandwidth_fee_sun + energy_fee_sun {
        return Err(TronError::Transaction(format!(
            "insufficient TRX for network fees: balance {trx_balance} sun, expected fees {} sun",
            bandwidth_fee_sun + energy_fee_sun
        )));
    }
    Ok(TronProposal {
        unsigned,
        symbol: meta.symbol,
        decimals: meta.decimals,
        amount_raw: word_to_decimal(&word),
        bandwidth_bytes: bytes,
        bandwidth_fee_sun,
        energy_estimate,
        energy_fee_sun,
        activation_fee_sun: 0,
        fee_limit_sun,
        max_fee_sun,
        recipient_activated: provider.balance_sun(&to).await?.is_some(),
        token_trust: Some(meta.trust),
    })
}

/// Settle one stored transaction against the node. Never rebroadcasts; never invents an outcome.
/// Returns the new status.
pub async fn reconcile_record(
    store: &TronStore,
    provider: &TronProvider,
    record: &TronRecord,
) -> Result<String, TronError> {
    let now = provider.now_block().await?;
    if let Some(info) = provider.tx_info(&record.txid).await? {
        let depth = now.block.number.saturating_sub(info.block_number);
        if !info.success {
            store.set_status(
                record.id,
                "failed",
                Some(info.block_number),
                info.failure.as_deref(),
            )?;
            return Ok("failed".to_owned());
        }
        if depth >= FINALITY_BLOCKS {
            store.set_status(record.id, "confirmed", Some(info.block_number), None)?;
            return Ok("confirmed".to_owned());
        }
        store.set_status(record.id, "pending", Some(info.block_number), None)?;
        return Ok("pending".to_owned());
    }
    // Unknown to the node. Only the expiration (measured in chain time) makes this final: after it, the
    // transaction can never be included, so the row is settled and nothing is lost or duplicated.
    if now.timestamp_ms > record.expiration_ms + 60_000 && !provider.tx_known(&record.txid).await? {
        store.set_status(
            record.id,
            "expired",
            None,
            Some("expired without inclusion"),
        )?;
        return Ok("expired".to_owned());
    }
    Ok(record.status.clone())
}
