//! Monero for Shadowallet, built on monero-oxide (no custom ring-signature or confidential-transaction cryptography).
//!
//! * `account`: BIP-44 (`m/44'/128'/account'/0/0`) deterministic keys, primary address and subaddresses
//! * `network`: genesis identity of mainnet / stagenet / testnet
//! * `store`:   local SQLite wallet state (outputs, key images, history, scan checkpoint, recent block hashes)
//! * `sync`:    block scanning, spend detection by key image, reorg rollback
//! * `send`:    output selection, decoys, fee, CLSAG + Bulletproofs+ signing, publish

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod account;
mod network;
mod send;
mod store;
mod sync;

pub use account::{MoneroAccount, parse_address};
pub use network::{MAINNET, MoneroNet, NETS, STAGENET, TESTNET};
pub use send::{PreparedSend, RING_SIZE, prepare_send, publish_signed, sign_prepared};
pub use store::{MoneroStore, OwnedOutput, TxRecord};
pub use sync::{Balance, Node, SyncReport, balance, connect, reconcile_pending, sync, tip};

pub use monero_wallet::address::{MoneroAddress, Network, SubaddressIndex};
pub use monero_wallet::interface::FeePriority;

#[derive(Debug, thiserror::Error)]
pub enum MoneroError {
    #[error("key derivation failed")]
    Derivation,
    #[error("invalid Monero address: {0}")]
    Address(String),
    #[error("node error: {0}")]
    Node(String),
    #[error("network identity: {0}")]
    Network(String),
    #[error("scan error: {0}")]
    Scan(String),
    #[error("send error: {0}")]
    Send(String),
    #[error("store error: {0}")]
    Store(String),
}

/// Number of confirmations before received outputs may be spent (Monero's default lock).
pub const SPEND_CONFIRMATIONS: usize = 10;
