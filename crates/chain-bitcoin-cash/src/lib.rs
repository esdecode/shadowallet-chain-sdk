//! Isolated Bitcoin Cash signing proof of concept (Phase 4C.6).
//!
//! Scope: BIP44 P2PKH address derivation, CashAddr encoding/decoding,
//! transaction construction, BCH `SIGHASH_ALL|SIGHASH_FORKID` preimage,
//! deterministic ECDSA signing, local verification and serialization.
//!
//! This crate does **not** implement a BCH wallet: there is no backend,
//! persistence, peering, CashTokens or P2SH support. Elliptic-curve
//! arithmetic is delegated to `secp256k1` (via the `bitcoin` crate). Bitcoin
//! signing logic is not reused; the fork-aware preimage below is BCH-specific.

pub mod engine;

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::{
    Amount, CompressedPublicKey, Network, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use shadowallet_chain_core::{SignRequest, SigningAlgorithm};
use thiserror::Error;

/// `SIGHASH_ALL` combined with the BCH replay-protection bit.
pub const SIGHASH_ALL_FORKID: u32 = 0x41;
/// Fork ID 0 is used by Bitcoin Cash since the 2017 UAHF.
pub const BCH_FORK_ID: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BchNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl BchNetwork {
    pub const fn network(self) -> Network {
        match self {
            Self::Mainnet => Network::Bitcoin,
            Self::Testnet => Network::Testnet,
            Self::Regtest => Network::Regtest,
        }
    }

    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Mainnet => "bitcoincash",
            Self::Testnet => "bchtest",
            Self::Regtest => "bchreg",
        }
    }

    pub const fn network_id(self) -> &'static str {
        match self {
            Self::Mainnet => "bitcoin-cash-mainnet",
            Self::Testnet => "bitcoin-cash-testnet",
            Self::Regtest => "bitcoin-cash-regtest",
        }
    }

    pub fn parse(value: &str) -> Result<Self, BchError> {
        match value {
            "mainnet" | "bitcoin-cash-mainnet" => Ok(Self::Mainnet),
            "testnet" | "bitcoin-cash-testnet" => Ok(Self::Testnet),
            "regtest" | "bitcoin-cash-regtest" => Ok(Self::Regtest),
            _ => Err(BchError::UnknownNetwork),
        }
    }

    pub const fn kind(self) -> bitcoin::NetworkKind {
        match self {
            Self::Mainnet => bitcoin::NetworkKind::Main,
            Self::Testnet | Self::Regtest => bitcoin::NetworkKind::Test,
        }
    }

    fn from_prefix(prefix: &str) -> Result<Self, BchError> {
        match prefix {
            "bitcoincash" => Ok(Self::Mainnet),
            "bchtest" => Ok(Self::Testnet),
            "bchreg" => Ok(Self::Regtest),
            _ => Err(BchError::UnknownNetwork),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    P2pkh,
    P2sh,
}

impl AddressKind {
    const fn version(self) -> u8 {
        match self {
            Self::P2pkh => 0x00,
            Self::P2sh => 0x08,
        }
    }

    fn from_version(version: u8) -> Result<Self, BchError> {
        match version >> 3 {
            0 => Ok(Self::P2pkh),
            1 => Ok(Self::P2sh),
            _ => Err(BchError::InvalidAddress(
                "unsupported address type".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CashAddress {
    pub network: BchNetwork,
    pub kind: AddressKind,
    pub hash: Vec<u8>,
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u64; 5] = [
    0x0098_f2bc_8e61,
    0x0079_b76d_99e2,
    0x00f3_3e5f_b3c4,
    0x00ae_2eab_e2a8,
    0x001e_4f43_e470,
];

fn polymod(values: &[u8]) -> u64 {
    let mut checksum: u64 = 1;
    for value in values {
        let top = (checksum >> 35) as u8;
        checksum = ((checksum & 0x0007_ffff_ffff) << 5) ^ u64::from(*value);
        for (bit, generator) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum ^ 1
}

fn expand_prefix(prefix: &str) -> Vec<u8> {
    let mut out = prefix.bytes().map(|b| b & 0x1f).collect::<Vec<_>>();
    out.push(0);
    out
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, BchError> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let max_value: u32 = (1 << to) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for value in data {
        if u32::from(*value) >> from != 0 {
            return Err(BchError::InvalidAddress("value out of range".to_owned()));
        }
        accumulator = (accumulator << from) | u32::from(*value);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((accumulator >> bits) & max_value) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((accumulator << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || ((accumulator << (to - bits)) & max_value) != 0 {
        return Err(BchError::InvalidAddress("invalid padding".to_owned()));
    }
    Ok(out)
}

impl CashAddress {
    pub fn new(network: BchNetwork, kind: AddressKind, hash: Vec<u8>) -> Result<Self, BchError> {
        if hash.len() != 20 {
            return Err(BchError::InvalidAddress(
                "only 160-bit hashes are supported in this PoC".to_owned(),
            ));
        }
        Ok(Self {
            network,
            kind,
            hash,
        })
    }

    pub fn encode(&self) -> String {
        let mut payload = Vec::with_capacity(1 + self.hash.len());
        // Only 160-bit hashes are constructible, so the size bits are zero.
        payload.push(self.kind.version());
        payload.extend_from_slice(&self.hash);
        let data = convert_bits(&payload, 8, 5, true).unwrap_or_default();
        let prefix = expand_prefix(self.network.prefix());
        let mut checksum_input = prefix.clone();
        checksum_input.extend_from_slice(&data);
        checksum_input.extend_from_slice(&[0u8; 8]);
        let checksum = polymod(&checksum_input);
        let mut encoded = String::with_capacity(self.network.prefix().len() + 1 + data.len() + 8);
        encoded.push_str(self.network.prefix());
        encoded.push(':');
        for value in &data {
            encoded.push(CHARSET[*value as usize] as char);
        }
        for index in 0..8 {
            let value = ((checksum >> (5 * (7 - index))) & 0x1f) as usize;
            encoded.push(CHARSET[value] as char);
        }
        encoded
    }

    pub fn decode(value: &str) -> Result<Self, BchError> {
        if value.is_empty() {
            return Err(BchError::InvalidAddress("empty address".to_owned()));
        }
        if value.chars().any(char::is_uppercase) && value.chars().any(char::is_lowercase) {
            return Err(BchError::InvalidAddress(
                "mixed-case address is not allowed".to_owned(),
            ));
        }
        let lowered = value.to_ascii_lowercase();
        let (prefix, payload) = match lowered.split_once(':') {
            Some((prefix, payload)) => (prefix, payload),
            None => (BchNetwork::Mainnet.prefix(), lowered.as_str()),
        };
        let network = BchNetwork::from_prefix(prefix)?;
        if payload.len() < 8 {
            return Err(BchError::InvalidAddress("payload too short".to_owned()));
        }
        let mut values = expand_prefix(prefix);
        for character in payload.bytes() {
            let Some(index) = CHARSET.iter().position(|c| *c == character) else {
                return Err(BchError::InvalidAddress(
                    "invalid base32 character".to_owned(),
                ));
            };
            values.push(index as u8);
        }
        if polymod(&values) != 0 {
            return Err(BchError::InvalidAddress("checksum mismatch".to_owned()));
        }
        let data = &values[expand_prefix(prefix).len()..];
        let decoded = convert_bits(&data[..data.len() - 8], 5, 8, false)?;
        let (version, hash) = decoded
            .split_first()
            .ok_or_else(|| BchError::InvalidAddress("empty payload".to_owned()))?;
        let kind = AddressKind::from_version(*version)?;
        if hash.len() != 20 || version & 0x07 != 0 {
            return Err(BchError::InvalidAddress(
                "only 160-bit hashes are supported in this PoC".to_owned(),
            ));
        }
        Ok(Self {
            network,
            kind,
            hash: hash.to_vec(),
        })
    }

    pub fn script_pubkey(&self) -> Result<ScriptBuf, BchError> {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&self.hash);
        let pubkey_hash = PubkeyHash::from_byte_array(hash);
        Ok(match self.kind {
            AddressKind::P2pkh => ScriptBuf::new_p2pkh(&pubkey_hash),
            AddressKind::P2sh => {
                let script_hash = bitcoin::ScriptHash::from_byte_array(hash);
                ScriptBuf::new_p2sh(&script_hash)
            }
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BchError {
    #[error("unknown network")]
    UnknownNetwork,
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("address belongs to a different network")]
    WrongNetwork,
    #[error("derivation failed")]
    Derivation,
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("fee rejected: {0}")]
    Fee(String),
    #[error("transaction error: {0}")]
    Transaction(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("signature verification failed")]
    InvalidSignature,
}

/// Conservative fee envelope. BCH relay policy is node-configured; this is a
/// safety bound, not a claim about network policy.
pub const BCH_FEE_POLICY: shadowallet_chain_utxo::FeePolicy = shadowallet_chain_utxo::FeePolicy {
    min_sat_vb: 1,
    max_sat_vb: 10_000,
    max_fee_sats: 100_000_000,
    max_fee_percent: 10,
};

const P2PKH_INPUT_SIZE: u64 = 148;
const P2PKH_OUTPUT_SIZE: u64 = 34;
const TX_OVERHEAD_SIZE: u64 = 10;
const DUST_SATS: u64 = 546;

pub fn estimate_size(inputs: usize, outputs: usize) -> u64 {
    TX_OVERHEAD_SIZE
        .saturating_add(P2PKH_INPUT_SIZE.saturating_mul(inputs as u64))
        .saturating_add(P2PKH_OUTPUT_SIZE.saturating_mul(outputs as u64))
}

/// Public (watch-only) BCH account operations used by the engine and builder.
pub trait BchPublicAccount {
    fn network(&self) -> BchNetwork;
    fn account_id(&self) -> String;
    fn public_key(&self, keychain: u32, index: u32) -> Result<CompressedPublicKey, BchError>;
    fn pubkey_hash(&self, keychain: u32, index: u32) -> Result<[u8; 20], BchError> {
        Ok(self
            .public_key(keychain, index)?
            .pubkey_hash()
            .to_byte_array())
    }
    fn address(&self, keychain: u32, index: u32) -> Result<CashAddress, BchError> {
        let hash = self.pubkey_hash(keychain, index)?;
        CashAddress::new(self.network(), AddressKind::P2pkh, hash.to_vec())
    }
    fn validate_address(&self, value: &str) -> Result<CashAddress, BchError> {
        let address = CashAddress::decode(value)?;
        if address.network != self.network() {
            return Err(BchError::WrongNetwork);
        }
        if address.kind != AddressKind::P2pkh {
            return Err(BchError::InvalidAddress(
                "only P2PKH destinations are supported".to_owned(),
            ));
        }
        Ok(address)
    }
}

/// Watch-only BCH account derived from an account-level xpub (`m/44'/145'/0'`).
#[derive(Debug, Clone)]
pub struct BchWatchAccount {
    pub network: BchNetwork,
    pub fingerprint: [u8; 4],
    xpub: Xpub,
}

impl BchWatchAccount {
    pub fn from_xpub(
        network: BchNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
    ) -> Result<Self, BchError> {
        let xpub = Xpub::from_str(xpub).map_err(|_| BchError::Derivation)?;
        if xpub.network != network.kind() {
            return Err(BchError::WrongNetwork);
        }
        Ok(Self {
            network,
            fingerprint,
            xpub,
        })
    }

    pub fn account_id(&self) -> String {
        self.fingerprint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

impl BchPublicAccount for BchWatchAccount {
    fn network(&self) -> BchNetwork {
        self.network
    }

    fn account_id(&self) -> String {
        self.account_id()
    }

    fn public_key(&self, keychain: u32, index: u32) -> Result<CompressedPublicKey, BchError> {
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str(&format!("m/{keychain}/{index}"))
            .map_err(|_| BchError::Derivation)?;
        let child = self
            .xpub
            .derive_pub(&secp, &path)
            .map_err(|_| BchError::Derivation)?;
        Ok(CompressedPublicKey(child.public_key))
    }
}

pub struct BchAccount {
    pub network: BchNetwork,
    pub fingerprint: String,
    pub fingerprint_raw: [u8; 4],
    account_xprv: Xpriv,
}

impl std::fmt::Debug for BchAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BchAccount")
            .field("network", &self.network)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl BchPublicAccount for BchAccount {
    fn network(&self) -> BchNetwork {
        self.network
    }

    fn account_id(&self) -> String {
        self.fingerprint.clone()
    }

    fn public_key(&self, keychain: u32, index: u32) -> Result<CompressedPublicKey, BchError> {
        let (_, public) = self.derive(keychain, index)?;
        Ok(public)
    }
}

impl BchAccount {
    pub fn from_seed(network: BchNetwork, seed: &[u8]) -> Result<Self, BchError> {
        let secp = Secp256k1::new();
        let master =
            Xpriv::new_master(network.network(), seed).map_err(|_| BchError::Derivation)?;
        let path = DerivationPath::from_str("m/44'/145'/0'").map_err(|_| BchError::Derivation)?;
        let account = master
            .derive_priv(&secp, &path)
            .map_err(|_| BchError::Derivation)?;
        let fingerprint = master.fingerprint(&secp);
        Ok(Self {
            network,
            fingerprint: fingerprint.to_string(),
            fingerprint_raw: fingerprint.to_bytes(),
            account_xprv: account,
        })
    }

    fn secp(&self) -> Secp256k1<All> {
        Secp256k1::new()
    }

    pub fn account_xpub(&self) -> Xpub {
        Xpub::from_priv(&self.secp(), &self.account_xprv)
    }

    pub fn sign_digest(
        &self,
        keychain: u32,
        index: u32,
        digest: [u8; 32],
    ) -> Result<Vec<u8>, BchError> {
        let secp = self.secp();
        let (secret, public) = self.derive(keychain, index)?;
        let message = Message::from_digest(digest);
        let signature = secp.sign_ecdsa(&message, &secret);
        secp.verify_ecdsa(&message, &signature, &public.0)
            .map_err(|_| BchError::InvalidSignature)?;
        Ok(signature.serialize_der().to_vec())
    }

    fn derive(
        &self,
        keychain: u32,
        index: u32,
    ) -> Result<(SecretKey, CompressedPublicKey), BchError> {
        let secp = self.secp();
        let path = DerivationPath::from_str(&format!("m/{keychain}/{index}"))
            .map_err(|_| BchError::Derivation)?;
        let child = self
            .account_xprv
            .derive_priv(&secp, &path)
            .map_err(|_| BchError::Derivation)?;
        let secret = SecretKey::from_slice(&child.private_key.secret_bytes())
            .map_err(|_| BchError::Derivation)?;
        let public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
        Ok((secret, CompressedPublicKey(public)))
    }

    pub fn pubkey_hash(&self, keychain: u32, index: u32) -> Result<[u8; 20], BchError> {
        let (_, public) = self.derive(keychain, index)?;
        Ok(public.pubkey_hash().to_byte_array())
    }

    pub fn address(&self, keychain: u32, index: u32) -> Result<CashAddress, BchError> {
        let hash = self.pubkey_hash(keychain, index)?;
        CashAddress::new(self.network, AddressKind::P2pkh, hash.to_vec())
    }

    /// Validate a CashAddr against this account's network and type.
    pub fn validate_address(&self, value: &str) -> Result<CashAddress, BchError> {
        let address = CashAddress::decode(value)?;
        if address.network != self.network {
            return Err(BchError::WrongNetwork);
        }
        if address.kind != AddressKind::P2pkh {
            return Err(BchError::InvalidAddress(
                "only P2PKH destinations are supported in this PoC".to_owned(),
            ));
        }
        Ok(address)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub keychain: u32,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct UnsignedTransfer {
    pub transaction: Transaction,
    pub fee_sats: u64,
    pub change_sats: u64,
    pub selected: Vec<Utxo>,
}

pub fn build_unsigned<A: BchPublicAccount>(
    account: &A,
    utxos: &[Utxo],
    destination: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    change_index: u32,
) -> Result<UnsignedTransfer, BchError> {
    let destination = account.validate_address(destination)?;
    if amount_sats == 0 {
        return Err(BchError::Transaction("zero amount".to_owned()));
    }
    BCH_FEE_POLICY
        .check(fee_rate_sat_vb, 0, Some(amount_sats))
        .map_err(|e| BchError::Fee(e.to_string()))?;

    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by_key(|u| std::cmp::Reverse(u.value_sats));
    let mut selected: Vec<Utxo> = Vec::new();
    let mut total = 0u64;
    let mut fee_sats = 0u64;
    let mut funded = false;
    for utxo in sorted {
        total = total.saturating_add(utxo.value_sats);
        selected.push(*utxo);
        let provisional = fee_rate_sat_vb.saturating_mul(estimate_size(selected.len(), 2));
        if total >= amount_sats.saturating_add(provisional) {
            fee_sats = provisional;
            funded = true;
            break;
        }
    }
    if !funded {
        return Err(BchError::InsufficientFunds);
    }
    let mut change_sats = total - amount_sats - fee_sats;
    if change_sats > 0 && change_sats < DUST_SATS {
        fee_sats = fee_sats.saturating_add(change_sats);
        change_sats = 0;
    }
    BCH_FEE_POLICY
        .check(fee_rate_sat_vb, fee_sats, Some(amount_sats))
        .map_err(|e| BchError::Fee(e.to_string()))?;

    let inputs = selected
        .iter()
        .map(|utxo| TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        })
        .collect::<Vec<_>>();
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: destination.script_pubkey()?,
    }];
    if change_sats > 0 {
        let change = account.address(1, change_index)?;
        outputs.push(TxOut {
            value: Amount::from_sat(change_sats),
            script_pubkey: change.script_pubkey()?,
        });
    }
    let transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };
    Ok(UnsignedTransfer {
        transaction,
        fee_sats,
        change_sats,
        selected,
    })
}

/// Build the exact BCH ForkID digests for external authorization/signing.
pub fn signing_request<A: BchPublicAccount>(
    account: &A,
    unsigned: &UnsignedTransfer,
) -> Result<SignRequest, BchError> {
    if !unsigned
        .transaction
        .input
        .iter()
        .all(|input| input.script_sig.is_empty() && input.witness.is_empty())
    {
        return Err(BchError::Transaction("premature signature".to_owned()));
    }
    let mut digests = Vec::with_capacity(unsigned.selected.len());
    let mut public_keys = Vec::with_capacity(unsigned.selected.len());
    for (position, utxo) in unsigned.selected.iter().enumerate() {
        let public = account.public_key(utxo.keychain, utxo.index)?;
        let script = ScriptBuf::new_p2pkh(&public.pubkey_hash());
        let digest = sighash_all_forkid(
            &unsigned.transaction,
            position,
            &script,
            utxo.value_sats,
            BCH_FORK_ID,
        )?;
        digests.push(hex::encode(digest));
        public_keys.push(public.to_string());
    }
    Ok(SignRequest {
        chain: shadowallet_chain_core::ChainId::parse("bitcoin-cash")
            .map_err(|e| BchError::Transaction(format!("{e:?}")))?,
        network: shadowallet_chain_core::NetworkId::parse(account.network().network_id())
            .map_err(|e| BchError::Transaction(format!("{e:?}")))?,
        account_id: account.account_id(),
        algorithm: SigningAlgorithm::Secp256k1Ecdsa,
        public_keys,
        digests,
    })
}

/// Finalize with externally produced DER signatures (SIGHASH_ALL|FORKID).
pub fn finalize_transfer<A: BchPublicAccount>(
    account: &A,
    unsigned: &UnsignedTransfer,
    signatures: &[Vec<u8>],
) -> Result<Transaction, BchError> {
    if signatures.len() != unsigned.selected.len() {
        return Err(BchError::Transaction("signature count mismatch".to_owned()));
    }
    let secp = Secp256k1::verification_only();
    let mut transaction = unsigned.transaction.clone();
    for (position, utxo) in unsigned.selected.iter().enumerate() {
        let public = account.public_key(utxo.keychain, utxo.index)?;
        let script = ScriptBuf::new_p2pkh(&public.pubkey_hash());
        let digest = sighash_all_forkid(
            &transaction,
            position,
            &script,
            utxo.value_sats,
            BCH_FORK_ID,
        )?;
        let signature = bitcoin::secp256k1::ecdsa::Signature::from_der(&signatures[position])
            .map_err(|_| BchError::InvalidSignature)?;
        secp.verify_ecdsa(&Message::from_digest(digest), &signature, &public.0)
            .map_err(|_| BchError::InvalidSignature)?;
        let mut sig_bytes = signatures[position].clone();
        sig_bytes.push(SIGHASH_ALL_FORKID as u8);
        let sig_push = PushBytesBuf::try_from(sig_bytes)
            .map_err(|_| BchError::Signing("signature push".to_owned()))?;
        let pubkey_push = PushBytesBuf::from(public.to_bytes());
        transaction.input[position].script_sig = Builder::new()
            .push_slice(sig_push)
            .push_slice(pubkey_push)
            .into_script();
    }
    Ok(transaction)
}

fn serialized_hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut buffer = Vec::new();
    for part in parts {
        buffer.extend_from_slice(part);
    }
    sha256d::Hash::hash(&buffer).to_byte_array()
}

/// BCH fork-aware digest (`SIGHASH_ALL|SIGHASH_FORKID`, fork id 0).
///
/// The preimage is the BIP143-style structure with the fork id folded into the
/// final 4-byte sighash field. The caller must pass the script code of the
/// output being spent (P2PKH here).
pub fn sighash_all_forkid(
    transaction: &Transaction,
    input_index: usize,
    script_code: &ScriptBuf,
    amount_sats: u64,
    fork_id: u32,
) -> Result<[u8; 32], BchError> {
    let input = transaction
        .input
        .get(input_index)
        .ok_or_else(|| BchError::Transaction("input index out of range".to_owned()))?;

    let mut prevouts = Vec::new();
    let mut sequences = Vec::new();
    let mut outputs = Vec::new();
    for txin in &transaction.input {
        prevouts.extend_from_slice(&bitcoin::consensus::encode::serialize(
            &txin.previous_output,
        ));
        sequences.extend_from_slice(&txin.sequence.to_consensus_u32().to_le_bytes());
    }
    for output in &transaction.output {
        outputs.extend_from_slice(&bitcoin::consensus::encode::serialize(output));
    }
    let hash_prevouts = serialized_hash(&[prevouts.as_slice()]);
    let hash_sequence = serialized_hash(&[sequences.as_slice()]);
    let hash_outputs = serialized_hash(&[outputs.as_slice()]);

    let mut preimage = Vec::with_capacity(156);
    preimage.extend_from_slice(&transaction.version.0.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&bitcoin::consensus::encode::serialize(
        &input.previous_output,
    ));
    preimage.extend_from_slice(&bitcoin::consensus::encode::serialize(script_code));
    preimage.extend_from_slice(&amount_sats.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_consensus_u32().to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&transaction.lock_time.to_consensus_u32().to_le_bytes());
    let sighash_type = (fork_id << 8) | SIGHASH_ALL_FORKID;
    preimage.extend_from_slice(&sighash_type.to_le_bytes());
    Ok(sha256d::Hash::hash(&preimage).to_byte_array())
}

/// Sign every P2PKH input and verify each signature locally before returning.
pub fn sign_transfer(
    account: &BchAccount,
    unsigned: &UnsignedTransfer,
) -> Result<Transaction, BchError> {
    if unsigned.transaction.input.len() != unsigned.selected.len() {
        return Err(BchError::Transaction("input/utxo mismatch".to_owned()));
    }
    let secp = Secp256k1::new();
    let mut transaction = unsigned.transaction.clone();
    for (position, utxo) in unsigned.selected.iter().enumerate() {
        if transaction.input[position].previous_output != utxo.outpoint {
            return Err(BchError::Transaction("utxo substitution".to_owned()));
        }
        let (secret, public) = account.derive(utxo.keychain, utxo.index)?;
        let script_code = ScriptBuf::new_p2pkh(&public.pubkey_hash());
        let digest = sighash_all_forkid(
            &transaction,
            position,
            &script_code,
            utxo.value_sats,
            BCH_FORK_ID,
        )?;
        let message = Message::from_digest(digest);
        let signature = secp.sign_ecdsa(&message, &secret);
        secp.verify_ecdsa(&message, &signature, &public.0)
            .map_err(|_| BchError::InvalidSignature)?;
        let mut signature_bytes = signature.serialize_der().to_vec();
        signature_bytes.push(SIGHASH_ALL_FORKID as u8);
        let signature_push = PushBytesBuf::try_from(signature_bytes)
            .map_err(|_| BchError::Signing("signature push".to_owned()))?;
        let pubkey_push = PushBytesBuf::from(public.to_bytes());
        transaction.input[position].script_sig = Builder::new()
            .push_slice(signature_push)
            .push_slice(pubkey_push)
            .into_script();
    }
    Ok(transaction)
}

fn script_pushes(script: &ScriptBuf) -> Result<Vec<Vec<u8>>, BchError> {
    let mut pushes = Vec::new();
    for instruction in script.instructions() {
        match instruction.map_err(|_| BchError::Transaction("bad script".to_owned()))? {
            bitcoin::script::Instruction::PushBytes(bytes) => {
                pushes.push(bytes.as_bytes().to_vec());
            }
            _ => {
                return Err(BchError::Transaction(
                    "unexpected opcode in P2PKH scriptSig".to_owned(),
                ));
            }
        }
    }
    Ok(pushes)
}

/// Independent local verification: rebuilds each preimage from the signed
/// transaction and checks the DER signature against the pushed public key.
pub fn verify_transfer(
    unsigned: &UnsignedTransfer,
    transaction: &Transaction,
) -> Result<(), BchError> {
    if transaction.input.len() != unsigned.selected.len() {
        return Err(BchError::Transaction("input/utxo mismatch".to_owned()));
    }
    let secp = Secp256k1::verification_only();
    for (position, utxo) in unsigned.selected.iter().enumerate() {
        let pushes = script_pushes(&transaction.input[position].script_sig.clone())?;
        if pushes.len() != 2 {
            return Err(BchError::Transaction("signature script shape".to_owned()));
        }
        let mut signature_bytes = pushes[0].clone();
        if signature_bytes.pop() != Some(SIGHASH_ALL_FORKID as u8) {
            return Err(BchError::InvalidSignature);
        }
        let signature = bitcoin::secp256k1::ecdsa::Signature::from_der(&signature_bytes)
            .map_err(|_| BchError::InvalidSignature)?;
        let public = bitcoin::secp256k1::PublicKey::from_slice(&pushes[1])
            .map_err(|_| BchError::InvalidSignature)?;
        let script_code = ScriptBuf::new_p2pkh(&CompressedPublicKey(public).pubkey_hash());
        let digest = sighash_all_forkid(
            transaction,
            position,
            &script_code,
            utxo.value_sats,
            BCH_FORK_ID,
        )?;
        secp.verify_ecdsa(&Message::from_digest(digest), &signature, &public)
            .map_err(|_| BchError::InvalidSignature)?;
    }
    Ok(())
}

pub fn serialize_transaction(transaction: &Transaction) -> Vec<u8> {
    bitcoin::consensus::encode::serialize(transaction)
}

pub fn deserialize_transaction(bytes: &[u8]) -> Result<Transaction, BchError> {
    bitcoin::consensus::encode::deserialize(bytes).map_err(|e| BchError::Transaction(e.to_string()))
}

/// SHA-256 of a serialized transaction, useful as an immutable commitment in a
/// future authorization layer.
pub fn transaction_commitment(transaction: &Transaction) -> [u8; 32] {
    bitcoin::hashes::sha256::Hash::hash(&serialize_transaction(transaction)).to_byte_array()
}
