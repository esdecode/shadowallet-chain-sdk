//! Decred (DCR) for Shadowallet.
//!
//! Decred is UTXO-based but is not Bitcoin: every hash is BLAKE-256, transactions carry separate prefix and witness
//! serializations with the spent value inside the witness, the signature hash is Decred's own (not BIP143), HD keys use
//! dcrd's hardened-derivation variant, and the minimum relay fee is 10000 atoms per kB. Protocol bytes come from the
//! `dcr-rs` crate (exact pin, unaudited); this crate adds the dcrd RPC client, scanning, fees and spend construction.
//! Staking, mixing and governance are out of scope.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod account;
mod net;
mod rpc;
mod send;
mod wallet;

pub use account::Account;
pub use net::{DecredNet, NETS, SIMNET, TESTNET, VerifiedNet};
pub use rpc::DcrdRpc;
pub use send::{DEFAULT_FEE_RATE, DUST, PreparedSend, prepare_send, sign_and_broadcast};
pub use wallet::{HistoryRow, Scan, Utxo, scan};

/// Atoms per DCR.
pub const ATOMS_PER_DCR: i64 = 100_000_000;

#[derive(Debug, thiserror::Error)]
pub enum DecredError {
    #[error("key derivation failed: {0}")]
    Derivation(String),
    #[error("invalid Decred address: {0}")]
    Address(String),
    #[error("network identity: {0}")]
    Network(String),
    #[error("dcrd rpc: {0}")]
    Rpc(String),
    #[error("send: {0}")]
    Send(String),
}
