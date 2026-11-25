//! Zcash for Shadowallet on the official librustzcash stack (no custom shielded cryptography).
//!
//! Scope: ZIP-32 accounts, unified addresses with Orchard + Sapling + transparent receivers, compact-block synchronization
//! through a lightwalletd server, note discovery, balances, history, ZIP-317 fees and shielded/transparent sends.
//! Sapling proving uses the official bundled parameters; Orchard proving uses the reference Halo 2 implementation.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod account;
mod net;
mod send;
mod sync;
mod wallet;

pub use account::{
    ADDRESS_REQUEST, account_id, full_viewing_key, spending_key, transparent_address,
    unified_address,
};
pub use net::{MAINNET, TESTNET, ZcashNet};
pub use send::{PreparedSend, SendReport, prepare_send, sign_and_broadcast};
pub use sync::{
    Balances, CancelToken, SyncOutcome, TxRow, balances, current_address, history, new_address,
    sync, sync_cancellable, transparent_address_of, update_tip,
};
pub use wallet::{
    Client, Db, MemBlockCache, ServerInfo, ZcashWallet, connect, latest_height, open_wallet,
    open_wallet_encrypted,
};

#[derive(Debug, thiserror::Error)]
pub enum ZcashError {
    #[error("key derivation failed")]
    Derivation,
    #[error("invalid Zcash address: {0}")]
    Address(String),
    #[error("server: {0}")]
    Server(String),
    #[error("network identity: {0}")]
    Network(String),
    #[error("wallet: {0}")]
    Wallet(String),
    #[error("send: {0}")]
    Send(String),
    /// The signed transaction was handed to the network layer and no answer came back: it MAY be on the network. The
    /// wallet database keeps it (its notes stay locked until it confirms or expires); it must not be sent again.
    #[error(
        "broadcast outcome unknown for transaction {txid}: {reason}. It may have reached the network: synchronize and check the history before sending again"
    )]
    BroadcastUncertain { txid: String, reason: String },
    /// The server answered and refused the signed transaction.
    #[error("the server refused transaction {txid} ({code}): {reason}")]
    BroadcastRejected {
        txid: String,
        code: i32,
        reason: String,
    },
}
