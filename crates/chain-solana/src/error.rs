use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SolanaError {
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid derivation: {0}")]
    Derivation(String),
    #[error("wrong network: {0}")]
    WrongNetwork(String),
    #[error("rpc transport failure: {0}")]
    Transport(String),
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("invalid rpc response: {0}")]
    InvalidResponse(String),
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("unsupported instruction or program: {0}")]
    UnsupportedInstruction(String),
    #[error("unsupported token program or extension: {0}")]
    UnsupportedToken(String),
    #[error("insufficient funds: {0}")]
    InsufficientFunds(String),
    #[error("transaction expired")]
    Expired,
    #[error("signing refused: {0}")]
    SigningRefused(String),
}
