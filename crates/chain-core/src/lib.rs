//! Chain-neutral SDK contracts.
//!
//! Deliberately free of UTXO, key-storage and application policy. A calling
//! wallet decides how keys are stored and when a transaction may be signed.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(String);

impl ChainId {
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(CoreError::InvalidChain);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(String);

impl NetworkId {
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        if value.is_empty() {
            return Err(CoreError::InvalidNetwork);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkClass {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationState {
    Pending,
    Confirmed { confirmations: u32, height: u64 },
    Dropped,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid chain id")]
    InvalidChain,
    #[error("invalid network id")]
    InvalidNetwork,
    #[error("invalid address")]
    InvalidAddress,
    #[error("wrong network")]
    WrongNetwork,
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
    #[error("provider failure: {0}")]
    Provider(String),
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
}

pub trait ChainInfo {
    fn chain_id(&self) -> &ChainId;
    fn networks(&self) -> &[NetworkId];
}

pub trait AddressCodec {
    fn validate_address(&self, address: &str, network: &NetworkId) -> Result<(), CoreError>;
}

pub trait BalanceProvider {
    fn balance(&self, network: &NetworkId) -> Result<Balance, CoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    pub confirmed: u128,
    pub pending: u128,
    pub spendable: u128,
    pub decimals: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    pub txid: String,
    pub height: Option<u64>,
    pub confirmations: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningAlgorithm {
    Secp256k1Ecdsa,
}

/// An approved signing request produced by the SDK. Digests are transaction
/// sighashes, never arbitrary user messages. The calling wallet is responsible
/// for authenticating the user and authorizing the exact request before
/// handing it to its signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    pub chain: ChainId,
    pub network: NetworkId,
    pub account_id: String,
    pub algorithm: SigningAlgorithm,
    /// Key identifiers (public keys, hex) parallel to `digests`.
    pub public_keys: Vec<String>,
    /// 32-byte digests, hex-encoded.
    pub digests: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    #[error("signer refused the request")]
    Refused,
    #[error("signer locked")]
    Locked,
    #[error("signer returned the wrong number of signatures")]
    CountMismatch,
}

/// External signing capability. The SDK never stores keys.
pub trait ExternalSigner {
    fn sign(&self, request: &SignRequest) -> Result<Vec<Vec<u8>>, SignError>;
}
