//! Nano (XNO) for Shadowallet.
//!
//! Nano is an account-chain (block lattice) ledger, not a UTXO ledger: every account owns a chain of *state blocks*; a
//! transfer is a `send` block on the sender chain and a separate `receive` (or `open`) block on the recipient chain.
//! Signatures are Ed25519 with Blake2b-512 in place of SHA-512; block hashes and work use Blake2b.
//! Only the standard `blake2` crate and `ed25519-dalek` primitives are used; no new cryptography is implemented here.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod address;
mod amount;
mod block;
mod keys;
mod network;
mod rpc;
mod wallet;
mod work;

pub use address::{decode_address, encode_address};
pub use amount::{RAW_PER_XNO, format_xno, parse_xno};
pub use block::{BlockKind, SignedBlock, StateBlock};
pub use keys::{
    Seed, derive_bip44_private_key, derive_private_key, public_key, sign_hash, slip10_ed25519,
    verify_hash,
};
pub use network::{BETA_NETWORK_ID, LIVE_NETWORK_ID, NanoNet, NetworkKind, TEST_NETWORK_ID};
pub use rpc::{AccountState, HistoryItem, NanoRpc, Receivable, Thresholds};
pub use wallet::{Prepared, Review, prepare_change, prepare_receive, prepare_send};
pub use work::{Difficulty, generate_work, work_value};

#[derive(Debug, thiserror::Error)]
pub enum NanoError {
    #[error("invalid seed: {0}")]
    Seed(String),
    #[error("invalid Nano address: {0}")]
    Address(String),
    #[error("invalid amount: {0}")]
    Amount(String),
    #[error("network identity: {0}")]
    Network(String),
    #[error("node rpc: {0}")]
    Rpc(String),
    #[error("block: {0}")]
    Block(String),
    #[error("signature check failed")]
    Signature,
}
