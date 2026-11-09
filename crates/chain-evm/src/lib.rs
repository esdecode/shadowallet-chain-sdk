//! EVM (Ethereum-compatible) account derivation, RPC access, ERC-20 helpers
//! and external transaction signing.
//!
//! The SDK is watch-only for account operations: it derives public addresses,
//! reads chain state and builds unsigned transactions. Private keys are used
//! only by the application signer after authorization.

use std::str::FromStr;

use bip32::{DerivationPath, XPrv};
pub use bytes::Bytes;
pub use primitive_types::{H160 as Address, H256 as B256, U256};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;

mod fee;
pub use fee::{FeeQuote, SelectedFees, quote_fees, select_fees};
mod store;
pub use store::{
    EvmStore, ReservedTransaction, StoredTransaction, TokenRecord, TransactionDraft,
    reconcile_receipt,
};
mod history;
pub use history::{
    Erc20Transfer, HistoryCompleteness, HistoryItem, HistoryPage, HistorySource, LocalHistory,
    erc20_transfers, transfer_topic,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvmError {
    #[error("derivation failed")]
    Derivation,
    #[error("invalid address")]
    InvalidAddress,
    #[error("unsupported chain profile")]
    UnknownChain,
    #[error("account is not registered for this chain")]
    UnknownAccount,
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("transaction error: {0}")]
    Transaction(String),
    #[error("insufficient funds for value and gas")]
    InsufficientFunds,
    #[error("fee or gas rejected by policy")]
    FeeRejected,
    #[error("unsupported fee model for this chain")]
    UnsupportedFeeModel,
    #[error("nonce reservation conflict")]
    NonceConflict,
    #[error("persistence error: {0}")]
    Store(String),
    #[error("history error: {0}")]
    History(String),
}

/// A validated EVM network profile. Profiles are data, not trust anchors:
/// the provider's `eth_chainId` is always checked against `chain_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeModel {
    Eip1559,
    Legacy,
    Eip1559WithL1DataFee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmChain {
    pub name: &'static str,
    pub chain_id: u64,
    pub native_symbol: &'static str,
    pub native_decimals: u8,
    pub eip1559: bool,
    pub fee_model: FeeModel,
    pub confirmations: u64,
}

pub const ETHEREUM: EvmChain = EvmChain {
    name: "ethereum",
    chain_id: 1,
    native_symbol: "ETH",
    native_decimals: 18,
    eip1559: true,
    fee_model: FeeModel::Eip1559,
    confirmations: 12,
};
pub const SEPOLIA: EvmChain = EvmChain {
    name: "sepolia",
    chain_id: 11_155_111,
    native_symbol: "ETH",
    native_decimals: 18,
    eip1559: true,
    fee_model: FeeModel::Eip1559,
    confirmations: 6,
};
pub const POLYGON: EvmChain = EvmChain {
    name: "polygon",
    chain_id: 137,
    native_symbol: "POL",
    native_decimals: 18,
    eip1559: true,
    fee_model: FeeModel::Eip1559,
    confirmations: 64,
};
pub const BSC: EvmChain = EvmChain {
    name: "bsc",
    chain_id: 56,
    native_symbol: "BNB",
    native_decimals: 18,
    eip1559: false,
    fee_model: FeeModel::Legacy,
    confirmations: 15,
};
pub const ARBITRUM: EvmChain = EvmChain {
    name: "arbitrum",
    chain_id: 42_161,
    native_symbol: "ETH",
    native_decimals: 18,
    eip1559: true,
    fee_model: FeeModel::Eip1559WithL1DataFee,
    confirmations: 1,
};
pub const OPTIMISM: EvmChain = EvmChain {
    name: "optimism",
    chain_id: 10,
    native_symbol: "ETH",
    native_decimals: 18,
    eip1559: true,
    fee_model: FeeModel::Eip1559WithL1DataFee,
    confirmations: 1,
};
pub const BASE: EvmChain = EvmChain {
    name: "base",
    chain_id: 8453,
    native_symbol: "ETH",
    native_decimals: 18,
    eip1559: true,
    fee_model: FeeModel::Eip1559WithL1DataFee,
    confirmations: 1,
};
pub const ANVIL: EvmChain = EvmChain {
    name: "anvil",
    chain_id: 31_337,
    native_symbol: "ETH",
    native_decimals: 18,
    eip1559: true,
    fee_model: FeeModel::Eip1559,
    confirmations: 1,
};

pub const PROFILES: &[EvmChain] = &[
    ETHEREUM, SEPOLIA, POLYGON, BSC, ARBITRUM, OPTIMISM, BASE, ANVIL,
];

impl EvmChain {
    pub fn by_id(chain_id: u64) -> Option<&'static Self> {
        PROFILES.iter().find(|p| p.chain_id == chain_id)
    }

    pub fn by_name(name: &str) -> Option<&'static Self> {
        PROFILES.iter().find(|p| p.name == name)
    }
}

/// Deterministic EVM account derived from BIP-39 seed bytes.
#[derive(Debug, Clone)]
pub struct EvmAccount {
    pub chain: EvmChain,
    pub index: u32,
    pub address: Address,
    secret: Option<SecretKey>,
}

impl EvmAccount {
    /// Derive `m/44'/60'/0'/0/index` from BIP-39 seed bytes. The seed never
    /// crosses the SDK boundary as a mnemonic; callers are trusted signers.
    pub fn from_seed(chain: EvmChain, seed: &[u8], index: u32) -> Result<Self, EvmError> {
        let path = DerivationPath::from_str(&format!("m/44'/60'/0'/0/{index}"))
            .map_err(|_| EvmError::Derivation)?;
        let child = XPrv::derive_from_path(seed, &path).map_err(|_| EvmError::Derivation)?;
        let bytes = child.private_key().to_bytes();
        let secret = SecretKey::from_byte_array(bytes.into()).map_err(|_| EvmError::Derivation)?;
        Ok(Self {
            chain,
            index,
            address: address_from_secret(&secret),
            secret: Some(secret),
        })
    }

    /// Construct from a raw secp256k1 key (tests/local signer use).
    pub fn from_private_key(chain: EvmChain, key: &[u8; 32], index: u32) -> Result<Self, EvmError> {
        let secret = SecretKey::from_byte_array(*key).map_err(|_| EvmError::Derivation)?;
        Ok(Self {
            chain,
            index,
            address: address_from_secret(&secret),
            secret: Some(secret),
        })
    }

    /// Public address only (watch-only use).
    pub fn address_only(chain: EvmChain, address: Address) -> Self {
        Self {
            chain,
            index: 0,
            address,
            secret: None,
        }
    }

    /// Sign a 32-byte digest. Only the application signer may call this after
    /// explicit authorization.
    pub fn sign_digest(&self, digest: [u8; 32]) -> Result<[u8; 65], EvmError> {
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| EvmError::Transaction("watch-only account cannot sign".to_owned()))?;
        let secp = Secp256k1::signing_only();
        let message = Message::from_digest(digest);
        let signature = secp.sign_ecdsa_recoverable(message, secret);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&compact);
        out[64] = i32::from(recovery_id) as u8;
        Ok(out)
    }
}

fn address_from_secret(secret: &SecretKey) -> Address {
    let secp = Secp256k1::signing_only();
    let public = PublicKey::from_secret_key(&secp, secret);
    let hash = Keccak256::digest(&public.serialize_uncompressed()[1..]);
    Address::from_slice(&hash[12..])
}

/// Return the EIP-55 checksummed address.
pub fn checksum_address(address: Address) -> String {
    let lower = hex::encode(address.as_bytes());
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in lower.chars().enumerate() {
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if ch.is_ascii_alphabetic() && nibble >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn address_hex(address: Address) -> String {
    format!("0x{}", hex::encode(address.as_bytes()))
}

pub fn hash_hex(hash: B256) -> String {
    format!("0x{}", hex::encode(hash.as_bytes()))
}

/// Transaction destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    Call(Address),
    Create,
}

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// A receipt parsed from JSON-RPC public fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionReceipt {
    pub transaction_hash: B256,
    pub status: bool,
    pub block_number: Option<u64>,
    pub contract_address: Option<Address>,
    pub logs: Vec<RpcLog>,
}

/// A log parsed from `eth_getLogs` / receipt JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_number: Option<u64>,
    pub transaction_hash: Option<B256>,
    pub log_index: Option<u64>,
}

/// Read-only EVM provider over JSON-RPC.
///
/// The provider is intentionally independent of Alloy's signer/network stack so
/// that the signing graph does not pull an advisory-affected secp256k1 backend.
#[derive(Debug, Clone)]
pub struct EvmProvider {
    pub chain: EvmChain,
    url: String,
    client: reqwest::Client,
    id: Arc<AtomicU64>,
}

fn parse_hex_u64(value: &Value) -> Result<u64, EvmError> {
    let text = value
        .as_str()
        .ok_or_else(|| EvmError::Rpc("expected hex string".to_owned()))?;
    u64::from_str_radix(text.trim_start_matches("0x"), 16)
        .map_err(|_| EvmError::Rpc(format!("invalid hex u64: {text}")))
}

fn parse_hex_u128(value: &Value) -> Result<u128, EvmError> {
    let text = value
        .as_str()
        .ok_or_else(|| EvmError::Rpc("expected hex string".to_owned()))?;
    u128::from_str_radix(text.trim_start_matches("0x"), 16)
        .map_err(|_| EvmError::Rpc(format!("invalid hex u128: {text}")))
}

fn parse_hex_u256(value: &Value) -> Result<U256, EvmError> {
    let text = value
        .as_str()
        .ok_or_else(|| EvmError::Rpc("expected hex string".to_owned()))?;
    U256::from_str_radix(text.trim_start_matches("0x"), 16)
        .map_err(|_| EvmError::Rpc(format!("invalid hex U256: {text}")))
}

fn parse_hex_bytes(value: &Value) -> Result<Bytes, EvmError> {
    let text = value
        .as_str()
        .ok_or_else(|| EvmError::Rpc("expected hex string".to_owned()))?;
    hex::decode(text.trim_start_matches("0x"))
        .map(Bytes::from)
        .map_err(|_| EvmError::Rpc(format!("invalid hex bytes: {text}")))
}

fn parse_address(value: &Value) -> Result<Address, EvmError> {
    let text = value
        .as_str()
        .ok_or_else(|| EvmError::Rpc("expected address".to_owned()))?;
    text.parse::<Address>()
        .map_err(|_| EvmError::Rpc(format!("invalid address: {text}")))
}

fn parse_b256(value: &Value) -> Result<B256, EvmError> {
    let text = value
        .as_str()
        .ok_or_else(|| EvmError::Rpc("expected hash".to_owned()))?;
    text.parse::<B256>()
        .map_err(|_| EvmError::Rpc(format!("invalid hash: {text}")))
}

fn hex_u256(value: U256) -> String {
    format!("0x{value:x}")
}

fn parse_log(value: &Value) -> Result<RpcLog, EvmError> {
    let topics = value
        .get("topics")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(parse_b256).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();
    Ok(RpcLog {
        address: parse_address(value.get("address").unwrap_or(&Value::Null))?,
        topics,
        data: parse_hex_bytes(value.get("data").unwrap_or(&Value::Null))?,
        block_number: value.get("blockNumber").and_then(|v| parse_hex_u64(v).ok()),
        transaction_hash: value
            .get("transactionHash")
            .and_then(|v| parse_b256(v).ok()),
        log_index: value.get("logIndex").and_then(|v| parse_hex_u64(v).ok()),
    })
}

impl EvmProvider {
    /// Create a provider and verify `eth_chainId` matches the profile.
    pub async fn connect(chain: EvmChain, url: &str) -> Result<Self, EvmError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| EvmError::Rpc(e.to_string()))?;
        let provider = Self {
            chain,
            url: url.to_owned(),
            client,
            id: Arc::new(AtomicU64::new(1)),
        };
        let remote: String = provider.rpc("eth_chainId", json!([])).await?;
        let remote = u64::from_str_radix(remote.trim_start_matches("0x"), 16)
            .map_err(|_| EvmError::Rpc("invalid eth_chainId".to_owned()))?;
        if remote != chain.chain_id {
            return Err(EvmError::Rpc(format!(
                "chain id mismatch: expected {}, provider reported {remote}",
                chain.chain_id
            )));
        }
        Ok(provider)
    }

    async fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, EvmError> {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let response = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| EvmError::Rpc(e.to_string()))?;
        let status = response.status();
        if status.as_u16() == 429 {
            return Err(EvmError::Rpc("rate limited by RPC provider".to_owned()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| EvmError::Rpc(e.to_string()))?;
        if body.len() > 2 * 1024 * 1024 {
            return Err(EvmError::Rpc("RPC response exceeds 2 MiB".to_owned()));
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|e| EvmError::Rpc(format!("malformed RPC JSON: {e}")))?;
        if let Some(error) = value.get("error") {
            return Err(EvmError::Rpc(error.to_string()));
        }
        if !status.is_success() {
            return Err(EvmError::Rpc(format!("HTTP {status}")));
        }
        serde_json::from_value(value.get("result").cloned().unwrap_or(Value::Null))
            .map_err(|e| EvmError::Rpc(format!("malformed {method} result: {e}")))
    }

    pub async fn block_number(&self) -> Result<u64, EvmError> {
        let value: Value = self.rpc("eth_blockNumber", json!([])).await?;
        parse_hex_u64(&value)
    }

    pub async fn latest_base_fee(&self) -> Result<u128, EvmError> {
        let block: Value = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        match block.get("baseFeePerGas") {
            Some(value) if !value.is_null() => parse_hex_u128(value),
            _ => Ok(0),
        }
    }

    pub async fn native_balance(&self, address: Address) -> Result<U256, EvmError> {
        let value: Value = self
            .rpc("eth_getBalance", json!([address_hex(address), "latest"]))
            .await?;
        parse_hex_u256(&value)
    }

    pub async fn pending_nonce(&self, address: Address) -> Result<u64, EvmError> {
        let value: Value = self
            .rpc(
                "eth_getTransactionCount",
                json!([address_hex(address), "pending"]),
            )
            .await?;
        parse_hex_u64(&value)
    }

    pub async fn gas_price(&self) -> Result<u128, EvmError> {
        let value: Value = self.rpc("eth_gasPrice", json!([])).await?;
        parse_hex_u128(&value)
    }

    pub async fn eip1559_fees(&self) -> Result<(u128, u128), EvmError> {
        let base = self.latest_base_fee().await?;
        let priority: u128 = self
            .rpc::<Value>("eth_maxPriorityFeePerGas", json!([]))
            .await
            .ok()
            .and_then(|value| parse_hex_u128(&value).ok())
            .unwrap_or(1_000_000_000);
        Ok((base.saturating_mul(2).saturating_add(priority), priority))
    }

    pub async fn estimate_gas(
        &self,
        from: Address,
        to: Option<Address>,
        value: U256,
        input: &[u8],
    ) -> Result<u64, EvmError> {
        let mut tx = json!({
            "from": address_hex(from),
            "value": hex_u256(value),
            "data": format!("0x{}", hex::encode(input)),
        });
        if let Some(to) = to {
            tx["to"] = json!(address_hex(to));
        }
        let value: Value = self.rpc("eth_estimateGas", json!([tx])).await?;
        parse_hex_u64(&value)
    }

    pub async fn call(&self, to: Address, input: &[u8]) -> Result<Bytes, EvmError> {
        let tx = json!({
            "to": address_hex(to),
            "data": format!("0x{}", hex::encode(input)),
        });
        let value: Value = self.rpc("eth_call", json!([tx, "latest"])).await?;
        parse_hex_bytes(&value)
    }

    pub async fn broadcast(&self, raw: &[u8]) -> Result<B256, EvmError> {
        let value: Value = self
            .rpc(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(raw))]),
            )
            .await?;
        parse_b256(&value)
    }

    pub async fn logs(
        &self,
        token: Address,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<RpcLog>, EvmError> {
        let filter = json!({
            "address": address_hex(token),
            "fromBlock": format!("0x{from_block:x}"),
            "toBlock": format!("0x{to_block:x}"),
        });
        let values: Vec<Value> = self.rpc("eth_getLogs", json!([filter])).await?;
        values.iter().map(parse_log).collect()
    }

    pub async fn receipt(&self, hash: B256) -> Result<Option<TransactionReceipt>, EvmError> {
        let value: Value = self
            .rpc("eth_getTransactionReceipt", json!([hash_hex(hash)]))
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        let status = value
            .get("status")
            .map(parse_hex_u64)
            .transpose()?
            .unwrap_or(0)
            == 1;
        let logs = value
            .get("logs")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(parse_log).collect::<Result<Vec<_>, _>>())
            .transpose()?
            .unwrap_or_default();
        Ok(Some(TransactionReceipt {
            transaction_hash: value
                .get("transactionHash")
                .map(parse_b256)
                .transpose()?
                .unwrap_or(hash),
            status,
            block_number: value.get("blockNumber").and_then(|v| parse_hex_u64(v).ok()),
            contract_address: value
                .get("contractAddress")
                .filter(|v| !v.is_null())
                .map(parse_address)
                .transpose()?,
            logs,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmTxType {
    Eip1559,
    Legacy,
}

/// Canonical unsigned transaction plus its signing digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedEvmTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub to: TxKind,
    pub value: U256,
    pub input: Bytes,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub gas_price: Option<u128>,
    pub tx_type: EvmTxType,
}

fn append_u256(stream: &mut rlp::RlpStream, value: U256) {
    let bytes = value.to_big_endian();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(32);
    stream.append(&&bytes[start..]);
}

fn append_u64(stream: &mut rlp::RlpStream, value: u64) {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(8);
    stream.append(&&bytes[start..]);
}

fn append_address(stream: &mut rlp::RlpStream, address: Address) {
    stream.append(&address.as_bytes());
}

fn append_to(stream: &mut rlp::RlpStream, to: TxKind) {
    match to {
        TxKind::Call(address) => append_address(stream, address),
        TxKind::Create => {
            stream.append_empty_data();
        }
    }
}

fn signature_rs(signature: &[u8]) -> Result<([u8; 32], [u8; 32], u8), EvmError> {
    if signature.len() != 65 {
        return Err(EvmError::Transaction(
            "expected 65-byte signature".to_owned(),
        ));
    }
    let compact: [u8; 64] = signature[..64]
        .try_into()
        .map_err(|_| EvmError::Transaction("malformed signature".to_owned()))?;
    let parsed = secp256k1::ecdsa::Signature::from_compact(&compact)
        .map_err(|e| EvmError::Transaction(e.to_string()))?;
    let original = parsed.serialize_compact();
    let mut normalized = parsed;
    normalized.normalize_s();
    if normalized.serialize_compact() != original {
        return Err(EvmError::Transaction(
            "high-S signature is not canonical".to_owned(),
        ));
    }
    let parity = match signature[64] {
        0 | 27 => 0,
        1 | 28 => 1,
        other => {
            return Err(EvmError::Transaction(format!(
                "invalid signature parity {other}"
            )));
        }
    };
    let mut r = [0u8; 32];
    r.copy_from_slice(&compact[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&compact[32..]);
    Ok((r, s, parity))
}

impl UnsignedEvmTransaction {
    fn eip1559_payload(&self, signed: Option<([u8; 32], [u8; 32], u8)>) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new_list(if signed.is_some() { 12 } else { 9 });
        append_u64(&mut stream, self.chain_id);
        append_u64(&mut stream, self.nonce);
        append_u64(&mut stream, self.max_priority_fee_per_gas as u64);
        append_u64(&mut stream, self.max_fee_per_gas as u64);
        append_u64(&mut stream, self.gas_limit);
        append_to(&mut stream, self.to);
        append_u256(&mut stream, self.value);
        stream.append(&&self.input[..]);
        stream.begin_list(0); // access list
        if let Some((r, s, parity)) = signed {
            append_u64(&mut stream, u64::from(parity));
            stream.append(&&r[..]);
            stream.append(&&s[..]);
        }
        let body = stream.out().to_vec();
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(0x02);
        out.extend_from_slice(&body);
        out
    }

    fn legacy_payload(&self, signed: Option<([u8; 32], [u8; 32], u8)>) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new_list(9);
        append_u64(&mut stream, self.nonce);
        append_u64(
            &mut stream,
            self.gas_price.unwrap_or(self.max_fee_per_gas) as u64,
        );
        append_u64(&mut stream, self.gas_limit);
        append_to(&mut stream, self.to);
        append_u256(&mut stream, self.value);
        stream.append(&&self.input[..]);
        match signed {
            Some((r, s, parity)) => {
                let v = self
                    .chain_id
                    .checked_mul(2)
                    .and_then(|v| v.checked_add(35 + u64::from(parity)))
                    .ok_or(EvmError::Transaction("legacy v overflow".to_owned()))
                    .unwrap_or(0);
                append_u64(&mut stream, v);
                stream.append(&&r[..]);
                stream.append(&&s[..]);
            }
            None => {
                append_u64(&mut stream, self.chain_id);
                stream.append_empty_data();
                stream.append_empty_data();
            }
        }
        stream.out().to_vec()
    }

    /// Canonical unsigned signing payload (EIP-1559 type byte + RLP, or legacy
    /// EIP-155 RLP).
    pub fn signing_payload(&self) -> Vec<u8> {
        match self.tx_type {
            EvmTxType::Eip1559 => self.eip1559_payload(None),
            EvmTxType::Legacy => self.legacy_payload(None),
        }
    }

    /// Digest that the application signer must sign.
    pub fn signature_hash(&self) -> B256 {
        B256::from_slice(&Keccak256::digest(self.signing_payload()))
    }

    /// Finalize with a 65-byte r||s||v signature into EIP-2718 bytes.
    pub fn finalize(&self, signature: &[u8]) -> Result<Vec<u8>, EvmError> {
        let (r, s, parity) = signature_rs(signature)?;
        Ok(match self.tx_type {
            EvmTxType::Eip1559 => self.eip1559_payload(Some((r, s, parity))),
            EvmTxType::Legacy => self.legacy_payload(Some((r, s, parity))),
        })
    }
}

/// Build an unsigned contract deployment (used by development tests).
pub async fn prepare_deployment(
    provider: &EvmProvider,
    from: Address,
    bytecode: Vec<u8>,
) -> Result<UnsignedEvmTransaction, EvmError> {
    let nonce = provider.pending_nonce(from).await?;
    let gas_limit = provider
        .estimate_gas(from, None, U256::zero(), &bytecode)
        .await?;
    if gas_limit > fee::MAX_DEPLOY_GAS_LIMIT {
        return Err(EvmError::FeeRejected);
    }
    let fees = select_fees(provider, gas_limit).await?;
    let max_cost = fees.max_total_cost(U256::zero())?;
    if provider.native_balance(from).await? < max_cost {
        return Err(EvmError::InsufficientFunds);
    }
    Ok(UnsignedEvmTransaction {
        chain_id: provider.chain.chain_id,
        nonce,
        to: TxKind::Create,
        value: U256::zero(),
        input: Bytes::from(bytecode),
        gas_limit: fees.gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        gas_price: fees.gas_price,
        tx_type: fees.tx_type,
    })
}

/// Build an unsigned EIP-1559 native transfer using an already reserved nonce.
pub async fn prepare_native_transfer_with_nonce(
    provider: &EvmProvider,
    from: Address,
    to: Address,
    value: U256,
    nonce: u64,
) -> Result<UnsignedEvmTransaction, EvmError> {
    let gas_limit = provider.estimate_gas(from, Some(to), value, &[]).await?;
    if gas_limit > fee::MAX_GAS_LIMIT {
        return Err(EvmError::FeeRejected);
    }
    let fees = select_fees(provider, gas_limit).await?;
    let max_cost = fees.max_total_cost(value)?;
    if provider.native_balance(from).await? < max_cost {
        return Err(EvmError::InsufficientFunds);
    }
    Ok(UnsignedEvmTransaction {
        chain_id: provider.chain.chain_id,
        nonce,
        to: TxKind::Call(to),
        value,
        input: Bytes::new(),
        gas_limit: fees.gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        gas_price: fees.gas_price,
        tx_type: fees.tx_type,
    })
}

/// Build an unsigned EIP-1559 native transfer. No signing occurs here.
pub async fn prepare_native_transfer(
    provider: &EvmProvider,
    from: Address,
    to: Address,
    value: U256,
) -> Result<UnsignedEvmTransaction, EvmError> {
    let nonce = provider.pending_nonce(from).await?;
    prepare_native_transfer_with_nonce(provider, from, to, value, nonce).await
}

fn selector(signature: &str) -> [u8; 4] {
    let hash = Keccak256::digest(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

fn padded_address(address: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address.as_bytes());
    out
}

fn padded_u256(value: U256) -> [u8; 32] {
    value.to_big_endian()
}

fn decode_u256(data: &[u8], field: &str) -> Result<U256, EvmError> {
    if data.len() < 32 {
        return Err(EvmError::Rpc(format!("malformed {field}")));
    }
    Ok(U256::from_big_endian(&data[..32]))
}

fn decode_string(data: &[u8], field: &str) -> Result<String, EvmError> {
    if data.len() >= 64 {
        let offset = U256::from_big_endian(&data[..32]);
        if let Ok(offset) = usize::try_from(offset)
            && offset <= data.len()
            && data.len() - offset >= 32
        {
            let length = U256::from_big_endian(&data[offset..offset + 32]);
            if let Ok(length) = usize::try_from(length) {
                let start = offset + 32;
                if length <= data.len().saturating_sub(start)
                    && let Ok(value) = std::str::from_utf8(&data[start..start + length])
                {
                    return Ok(value.to_owned());
                }
            }
        }
    }
    // Legacy tokens return bytes32 instead of a dynamic string.
    if data.len() == 32 {
        let end = data.iter().position(|b| *b == 0).unwrap_or(32);
        if let Ok(value) = std::str::from_utf8(&data[..end]) {
            return Ok(value.to_owned());
        }
    }
    Err(EvmError::Rpc(format!("malformed {field}")))
}

/// Canonical ERC-20 `transfer(address,uint256)` calldata.
pub fn erc20_transfer_calldata(to: Address, amount: U256) -> Vec<u8> {
    let mut call = Vec::with_capacity(68);
    call.extend_from_slice(&selector("transfer(address,uint256)"));
    call.extend_from_slice(&padded_address(to));
    call.extend_from_slice(&padded_u256(amount));
    call
}

/// Canonical ERC-20 `balanceOf(address)` calldata.
pub fn erc20_balance_of_calldata(owner: Address) -> Vec<u8> {
    let mut call = Vec::with_capacity(36);
    call.extend_from_slice(&selector("balanceOf(address)"));
    call.extend_from_slice(&padded_address(owner));
    call
}

/// Decode an ABI-encoded string (dynamic string or legacy bytes32).
pub fn decode_erc20_string(data: &[u8]) -> Result<String, EvmError> {
    decode_string(data, "string")
}

/// ERC-20 token identified by `(chain_id, contract)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Erc20Token {
    pub chain_id: u64,
    pub contract: Address,
}

impl Erc20Token {
    pub async fn balance_of(
        &self,
        provider: &EvmProvider,
        owner: Address,
    ) -> Result<U256, EvmError> {
        let data = provider
            .call(self.contract, &erc20_balance_of_calldata(owner))
            .await?;
        decode_u256(&data, "balanceOf")
    }

    pub async fn decimals(&self, provider: &EvmProvider) -> Result<u8, EvmError> {
        let data = provider
            .call(self.contract, &selector("decimals()"))
            .await?;
        let value = decode_u256(&data, "decimals")?;
        u8::try_from(value.low_u64()).map_err(|_| EvmError::Rpc("invalid decimals".to_owned()))
    }

    pub async fn symbol(&self, provider: &EvmProvider) -> Result<String, EvmError> {
        let data = provider.call(self.contract, &selector("symbol()")).await?;
        decode_string(&data, "symbol")
    }

    pub async fn name(&self, provider: &EvmProvider) -> Result<String, EvmError> {
        let data = provider.call(self.contract, &selector("name()")).await?;
        decode_string(&data, "name")
    }

    /// Read and persist public token metadata keyed by chain + contract.
    pub async fn cache_metadata(
        &self,
        provider: &EvmProvider,
        store: &EvmStore,
    ) -> Result<TokenRecord, EvmError> {
        let decimals = self.decimals(provider).await?;
        let symbol = self.symbol(provider).await?;
        let name = self.name(provider).await.ok();
        let record = TokenRecord {
            chain_id: self.chain_id,
            contract: checksum_address(self.contract),
            symbol: Some(symbol),
            name,
            decimals: Some(decimals),
        };
        store.upsert_token(&record)?;
        Ok(record)
    }

    /// Validate a mined receipt for a canonical `Transfer` event.
    pub fn validate_transfer_receipt(
        &self,
        receipt: &TransactionReceipt,
        from: Address,
        to: Address,
        amount: U256,
    ) -> bool {
        receipt.status
            && receipt.logs.iter().any(|log| {
                let topics = &log.topics;
                if log.address != self.contract || topics.len() != 3 {
                    return false;
                }
                let data = log.data.as_ref();
                if data.len() < 32 {
                    return false;
                }
                Address::from_slice(&topics[1].as_bytes()[12..]) == from
                    && Address::from_slice(&topics[2].as_bytes()[12..]) == to
                    && U256::from_big_endian(&data[..32]) == amount
            })
    }
}

/// Build an unsigned ERC-20 transfer with canonical calldata.
pub async fn prepare_erc20_transfer_with_nonce(
    provider: &EvmProvider,
    from: Address,
    token: Erc20Token,
    to: Address,
    amount: U256,
    nonce: u64,
) -> Result<UnsignedEvmTransaction, EvmError> {
    if token.chain_id != provider.chain.chain_id {
        return Err(EvmError::UnknownChain);
    }
    let input = Bytes::from(erc20_transfer_calldata(to, amount));
    let gas_limit = provider
        .estimate_gas(from, Some(token.contract), U256::zero(), &input)
        .await?;
    if gas_limit > fee::MAX_GAS_LIMIT {
        return Err(EvmError::FeeRejected);
    }
    let fees = select_fees(provider, gas_limit).await?;
    let max_cost = fees.max_total_cost(U256::zero())?;
    if provider.native_balance(from).await? < max_cost {
        return Err(EvmError::InsufficientFunds);
    }
    Ok(UnsignedEvmTransaction {
        chain_id: provider.chain.chain_id,
        nonce,
        to: TxKind::Call(token.contract),
        value: U256::zero(),
        input,
        gas_limit: fees.gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        gas_price: fees.gas_price,
        tx_type: fees.tx_type,
    })
}

/// Build an unsigned ERC-20 transfer using an already reserved nonce.
pub async fn prepare_erc20_transfer(
    provider: &EvmProvider,
    from: Address,
    token: Erc20Token,
    to: Address,
    amount: U256,
) -> Result<UnsignedEvmTransaction, EvmError> {
    let nonce = provider.pending_nonce(from).await?;
    prepare_erc20_transfer_with_nonce(provider, from, token, to, amount, nonce).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn known_anvil_key_maps_to_expected_address() {
        let key = [
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ];
        let account = EvmAccount::from_private_key(ANVIL, &key, 0).unwrap();
        assert_eq!(
            checksum_address(account.address).to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn chain_profiles_are_unique_and_lookupable() {
        let mut ids: Vec<u64> = PROFILES.iter().map(|p| p.chain_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), PROFILES.len());
        assert_eq!(EvmChain::by_name("anvil").unwrap().chain_id, 31_337);
        assert!(EvmChain::by_id(999_999).is_none());
    }

    #[test]
    fn deterministic_account_derivation() {
        let a = EvmAccount::from_seed(ANVIL, &[0x42; 64], 0).unwrap();
        let b = EvmAccount::from_seed(ANVIL, &[0x42; 64], 0).unwrap();
        assert_eq!(a.address, b.address);
        let c = EvmAccount::from_seed(ANVIL, &[0x42; 64], 1).unwrap();
        assert_ne!(a.address, c.address);
    }
}
