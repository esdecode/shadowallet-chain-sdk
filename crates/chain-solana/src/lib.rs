//! Solana and SPL token support for the Shadowallet Chain SDK.
//!
//! Scope (Phase 6): SLIP-0010 Ed25519 derivation, read-only JSON-RPC, legacy
//! transaction messages, native SOL transfers, SPL Token / (extension-free)
//! Token-2022 `TransferChecked`, and restricted external signing.
//!
//! Security model: secret material never leaves [`SolanaAccount`]. The only
//! signing entry point is [`SolanaAccount::sign_transfer`], which re-inspects
//! the exact message bytes against an allowlist (System transfer, ATA
//! create-idempotent, SPL `TransferChecked`) and the originally prepared
//! intent. There is no arbitrary-message signing API.

pub mod account;
pub mod error;
pub mod message;
pub mod network;
pub mod pubkey;
pub mod rpc;
pub mod transfer;

pub use account::{SolanaAccount, default_path};
pub use error::SolanaError;
pub use message::{AccountMeta, Instruction, Message, Transaction};
pub use network::SolanaNetwork;
pub use pubkey::{
    ASSOCIATED_TOKEN_PROGRAM, Pubkey, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
    associated_token_address, find_program_address,
};
pub use rpc::{
    HttpTransport, SignatureInfo, SolanaRpc, TokenAccount, Transport, TxEffect, TxStatus,
};
pub use transfer::{
    DecodedInstruction, PreparedTransfer, SignedTransfer, TransferIntent, TransferKind,
    inspect_message, prepare_native_transfer, prepare_spl_transfer,
};
