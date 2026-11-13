//! Watch-only Dogecoin integration.
//!
//! Public derivation, unsigned legacy P2PKH construction and verification of
//! externally produced ECDSA signatures. No seed or private key is stored.

pub mod engine;
pub mod indexer;

use std::str::FromStr;

use doge::bip32::{DerivationPath, Xpub};
use doge::consensus::encode::{deserialize, serialize_hex};
use doge::dogecoin::{Address, Network};
use doge::hashes::Hash;
use doge::script::PushBytesBuf;
use doge::secp256k1::{Message, Secp256k1};
use doge::sighash::SighashCache;
use doge::{
    Amount, EcdsaSighashType, NetworkKind, OutPoint, PubkeyHash, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use shadowallet_chain_core::{ChainId, NetworkId, SignRequest, SigningAlgorithm};
use shadowallet_chain_utxo::{FeePolicy, FeePolicyError, Utxo};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DogeNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl DogeNetwork {
    pub const fn network(self) -> Network {
        match self {
            Self::Mainnet => Network::Dogecoin,
            Self::Testnet => Network::Testnet,
            Self::Regtest => Network::Regtest,
        }
    }

    pub const fn kind(self) -> NetworkKind {
        match self {
            Self::Mainnet => NetworkKind::Main,
            Self::Testnet | Self::Regtest => NetworkKind::Test,
        }
    }

    pub const fn network_id(self) -> &'static str {
        match self {
            Self::Mainnet => "dogecoin-mainnet",
            Self::Testnet => "dogecoin-testnet",
            Self::Regtest => "dogecoin-regtest",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DogecoinSdkError> {
        match value {
            "mainnet" | "dogecoin-mainnet" => Ok(Self::Mainnet),
            "testnet" | "dogecoin-testnet" => Ok(Self::Testnet),
            "regtest" | "dogecoin-regtest" => Ok(Self::Regtest),
            _ => Err(DogecoinSdkError::UnknownNetwork),
        }
    }
}

/// Safety envelope in koinu. Not a verified Core relay/dust policy.
pub const DOGECOIN_FEE_POLICY: FeePolicy = FeePolicy {
    min_sat_vb: 1,
    max_sat_vb: 10_000,
    max_fee_sats: 1_000_000_000,
    max_fee_percent: 10,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DogecoinSdkError {
    #[error("unknown network")]
    UnknownNetwork,
    #[error("invalid xpub")]
    InvalidXpub,
    #[error("xpub belongs to a different network")]
    WrongXpubNetwork,
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("address belongs to a different network")]
    WrongNetwork,
    #[error("invalid derivation path")]
    Derivation,
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("zero amount")]
    ZeroAmount,
    #[error("fee rejected by policy: {0}")]
    Fee(#[from] FeePolicyError),
    #[error("invalid transaction: {0}")]
    Transaction(String),
    #[error("signature count mismatch")]
    SignatureCount,
    #[error("invalid external signature")]
    InvalidSignature,
    #[error("premature signature in unsigned transaction")]
    PrematureSignature,
}

#[derive(Debug, Clone)]
pub struct DogeAccount {
    pub network: DogeNetwork,
    pub fingerprint: [u8; 4],
    xpub: Xpub,
}

impl DogeAccount {
    pub fn from_xpub(
        network: DogeNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
    ) -> Result<Self, DogecoinSdkError> {
        let xpub = Xpub::from_str(xpub).map_err(|_| DogecoinSdkError::InvalidXpub)?;
        if xpub.network != network.kind() {
            return Err(DogecoinSdkError::WrongXpubNetwork);
        }
        Ok(Self {
            network,
            fingerprint,
            xpub,
        })
    }

    #[allow(clippy::expect_used)]
    pub fn chain_id() -> ChainId {
        ChainId::parse("dogecoin").expect("static chain id")
    }

    #[allow(clippy::expect_used)]
    pub fn network_id(&self) -> NetworkId {
        NetworkId::parse(self.network.network_id()).expect("static network id")
    }

    pub fn account_id(&self) -> String {
        hex::encode(self.fingerprint)
    }

    pub fn public_key(&self, keychain: u32, index: u32) -> Result<PublicKey, DogecoinSdkError> {
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str(&format!("m/{keychain}/{index}"))
            .map_err(|_| DogecoinSdkError::Derivation)?;
        let child = self
            .xpub
            .derive_pub(&secp, &path)
            .map_err(|_| DogecoinSdkError::Derivation)?;
        Ok(PublicKey::new(child.public_key))
    }

    pub fn address(&self, keychain: u32, index: u32) -> Result<Address, DogecoinSdkError> {
        Ok(Address::p2pkh(
            self.public_key(keychain, index)?,
            self.network.network(),
        ))
    }

    pub fn validate_address(&self, address: &str) -> Result<Address, DogecoinSdkError> {
        let unchecked = Address::from_str(address)
            .map_err(|e| DogecoinSdkError::InvalidAddress(e.to_string()))?;
        unchecked
            .require_network(self.network.network())
            .map_err(|_| DogecoinSdkError::WrongNetwork)
    }
}

#[derive(Debug, Clone)]
pub struct UnsignedTransfer {
    pub transaction: Transaction,
    pub fee_sats: u64,
    pub change_sats: u64,
    pub selected: Vec<Utxo>,
}

impl UnsignedTransfer {
    pub fn hex(&self) -> String {
        serialize_hex(&self.transaction)
    }

    pub fn is_unsigned(&self) -> bool {
        self.transaction
            .input
            .iter()
            .all(|input| input.script_sig.is_empty() && input.witness.is_empty())
    }
}

fn outpoint(value: &Utxo) -> Result<OutPoint, DogecoinSdkError> {
    let txid = Txid::from_str(&value.txid)
        .map_err(|_| DogecoinSdkError::Transaction("invalid txid".to_owned()))?;
    Ok(OutPoint {
        txid,
        vout: value.vout,
    })
}

const P2PKH_INPUT_SIZE: u64 = 148;
const P2PKH_OUTPUT_SIZE: u64 = 34;
const TX_OVERHEAD_SIZE: u64 = 10;
const CHANGE_DUST_SATS: u64 = 1_000_000;

pub fn estimate_size(inputs: usize, outputs: usize) -> u64 {
    TX_OVERHEAD_SIZE
        .saturating_add(P2PKH_INPUT_SIZE.saturating_mul(inputs as u64))
        .saturating_add(P2PKH_OUTPUT_SIZE.saturating_mul(outputs as u64))
}

pub fn prepare_transfer(
    account: &DogeAccount,
    utxos: &[Utxo],
    destination: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    change_index: u32,
) -> Result<UnsignedTransfer, DogecoinSdkError> {
    let destination = account.validate_address(destination)?;
    if amount_sats == 0 {
        return Err(DogecoinSdkError::ZeroAmount);
    }
    DOGECOIN_FEE_POLICY.check(fee_rate_sat_vb, 0, Some(amount_sats))?;
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by_key(|u| std::cmp::Reverse(u.value_sats));
    let mut selected: Vec<Utxo> = Vec::new();
    let mut total = 0u64;
    let mut fee_sats = 0u64;
    let mut funded = false;
    for utxo in sorted {
        total = total.saturating_add(utxo.value_sats);
        selected.push(utxo.clone());
        let provisional = fee_rate_sat_vb.saturating_mul(estimate_size(selected.len(), 2));
        if total >= amount_sats.saturating_add(provisional) {
            fee_sats = provisional;
            funded = true;
            break;
        }
    }
    if !funded {
        return Err(DogecoinSdkError::InsufficientFunds);
    }
    let mut change_sats = total - amount_sats - fee_sats;
    if change_sats > 0 && change_sats < CHANGE_DUST_SATS {
        fee_sats = fee_sats.saturating_add(change_sats);
        change_sats = 0;
    }
    DOGECOIN_FEE_POLICY.check(fee_rate_sat_vb, fee_sats, Some(amount_sats))?;

    let mut inputs = Vec::with_capacity(selected.len());
    for utxo in &selected {
        inputs.push(TxIn {
            previous_output: outpoint(utxo)?,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: destination.script_pubkey(),
    }];
    if change_sats > 0 {
        outputs.push(TxOut {
            value: Amount::from_sat(change_sats),
            script_pubkey: account.address(1, change_index)?.script_pubkey(),
        });
    }

    Ok(UnsignedTransfer {
        transaction: Transaction {
            version: doge::transaction::Version::TWO,
            lock_time: doge::absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        },
        fee_sats,
        change_sats,
        selected,
    })
}

fn spend_script(account: &DogeAccount, utxo: &Utxo) -> Result<ScriptBuf, DogecoinSdkError> {
    Ok(ScriptBuf::new_p2pkh(&PubkeyHash::hash(
        &account.public_key(utxo.keychain, utxo.index)?.to_bytes(),
    )))
}

pub fn signing_request(
    account: &DogeAccount,
    unsigned: &UnsignedTransfer,
) -> Result<SignRequest, DogecoinSdkError> {
    if !unsigned.is_unsigned() {
        return Err(DogecoinSdkError::PrematureSignature);
    }
    if unsigned.transaction.input.len() != unsigned.selected.len() {
        return Err(DogecoinSdkError::Transaction(
            "input/utxo mismatch".to_owned(),
        ));
    }
    let mut digests = Vec::with_capacity(unsigned.selected.len());
    let mut public_keys = Vec::with_capacity(unsigned.selected.len());
    for (position, utxo) in unsigned.selected.iter().enumerate() {
        let public = account.public_key(utxo.keychain, utxo.index)?;
        let spk = spend_script(account, utxo)?;
        let cache = SighashCache::new(&unsigned.transaction);
        let sighash = cache
            .legacy_signature_hash(position, &spk, EcdsaSighashType::All.to_u32())
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        digests.push(hex::encode(sighash.to_byte_array()));
        public_keys.push(public.to_string());
    }
    Ok(SignRequest {
        chain: DogeAccount::chain_id(),
        network: account.network_id(),
        account_id: account.account_id(),
        algorithm: SigningAlgorithm::Secp256k1Ecdsa,
        public_keys,
        digests,
    })
}

pub fn finalize_transfer(
    account: &DogeAccount,
    unsigned: &UnsignedTransfer,
    signatures: &[Vec<u8>],
) -> Result<Transaction, DogecoinSdkError> {
    if signatures.len() != unsigned.selected.len() {
        return Err(DogecoinSdkError::SignatureCount);
    }
    if !unsigned.is_unsigned() {
        return Err(DogecoinSdkError::PrematureSignature);
    }
    let secp = Secp256k1::new();
    let mut tx = unsigned.transaction.clone();
    for (position, utxo) in unsigned.selected.iter().enumerate() {
        let public = account.public_key(utxo.keychain, utxo.index)?;
        let spk = spend_script(account, utxo)?;
        let cache = SighashCache::new(&tx);
        let sighash = cache
            .legacy_signature_hash(position, &spk, EcdsaSighashType::All.to_u32())
            .map_err(|e| DogecoinSdkError::Transaction(e.to_string()))?;
        let signature = doge::secp256k1::ecdsa::Signature::from_der(&signatures[position])
            .map_err(|_| DogecoinSdkError::InvalidSignature)?;
        let message = Message::from_digest(sighash.to_byte_array());
        secp.verify_ecdsa(&message, &signature, &public.inner)
            .map_err(|_| DogecoinSdkError::InvalidSignature)?;
        let mut sig_bytes = signatures[position].clone();
        sig_bytes.push(EcdsaSighashType::All as u8);
        let sig_push =
            PushBytesBuf::try_from(sig_bytes).map_err(|_| DogecoinSdkError::InvalidSignature)?;
        let pk_push = PushBytesBuf::try_from(public.to_bytes())
            .map_err(|_| DogecoinSdkError::InvalidSignature)?;
        tx.input[position].script_sig = doge::script::Builder::new()
            .push_slice(sig_push)
            .push_slice(pk_push)
            .into_script();
    }
    Ok(tx)
}

pub fn parse_unsigned(hex: &str) -> Result<Transaction, DogecoinSdkError> {
    let bytes =
        hex::decode(hex).map_err(|_| DogecoinSdkError::Transaction("invalid hex".to_owned()))?;
    deserialize(&bytes).map_err(|_| DogecoinSdkError::Transaction("invalid transaction".to_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use doge::bip32::Xpriv;
    use doge::secp256k1::{Secp256k1, SecretKey};
    use shadowallet_chain_core::{ExternalSigner, SignError, SignRequest};

    fn account() -> DogeAccount {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(DogeNetwork::Regtest.kind(), &[0x24; 32]).unwrap();
        let path = DerivationPath::from_str("m/44'/3'/0'").unwrap();
        let account = master.derive_priv(&secp, &path).unwrap();
        let xpub = Xpub::from_priv(&secp, &account);
        DogeAccount::from_xpub(
            DogeNetwork::Regtest,
            &xpub.to_string(),
            master.fingerprint(&secp).to_bytes(),
        )
        .unwrap()
    }

    fn utxo(value: u64, index: u32) -> Utxo {
        Utxo {
            txid: format!("{:064x}", index + 7),
            vout: 0,
            value_sats: value,
            confirmations: 2,
            keychain: 0,
            index,
        }
    }

    struct DevSigner {
        seed: [u8; 32],
    }

    impl ExternalSigner for DevSigner {
        fn sign(&self, request: &SignRequest) -> Result<Vec<Vec<u8>>, SignError> {
            let secp = Secp256k1::new();
            let master = Xpriv::new_master(DogeNetwork::Regtest.kind(), &self.seed).unwrap();
            let account = master
                .derive_priv(&secp, &DerivationPath::from_str("m/44'/3'/0'").unwrap())
                .unwrap();
            Ok(request
                .digests
                .iter()
                .enumerate()
                .map(|(index, digest)| {
                    let path = DerivationPath::from_str(&format!("m/0/{index}")).unwrap();
                    let child = account.derive_priv(&secp, &path).unwrap();
                    let secret = SecretKey::from_slice(&child.private_key.secret_bytes()).unwrap();
                    let bytes: [u8; 32] = hex::decode(digest).unwrap().try_into().unwrap();
                    let message = Message::from_digest(bytes);
                    secp.sign_ecdsa(&message, &secret).serialize_der().to_vec()
                })
                .collect())
        }
    }

    #[test]
    fn address_and_unsigned_build_are_deterministic() {
        let a = account();
        let unsigned = prepare_transfer(
            &a,
            &[utxo(10_000_000, 0)],
            &a.address(0, 9).unwrap().to_string(),
            5_000_000,
            1,
            0,
        )
        .unwrap();
        assert!(unsigned.is_unsigned());
        assert_eq!(unsigned.change_sats, 4_999_774);
        assert_eq!(unsigned.transaction.output.len(), 2);
    }

    #[test]
    fn external_signer_flow_verifies_and_finalizes() {
        let a = account();
        let unsigned = prepare_transfer(
            &a,
            &[utxo(10_000_000, 0)],
            &a.address(0, 9).unwrap().to_string(),
            5_000_000,
            1,
            0,
        )
        .unwrap();
        let request = signing_request(&a, &unsigned).unwrap();
        let signatures = DevSigner { seed: [0x24; 32] }.sign(&request).unwrap();
        let signed = finalize_transfer(&a, &unsigned, &signatures).unwrap();
        assert!(!signed.input[0].script_sig.is_empty());
    }

    #[test]
    fn modified_output_invalidates_external_signature() {
        let a = account();
        let unsigned = prepare_transfer(
            &a,
            &[utxo(10_000_000, 0)],
            &a.address(0, 9).unwrap().to_string(),
            5_000_000,
            1,
            0,
        )
        .unwrap();
        let request = signing_request(&a, &unsigned).unwrap();
        let signatures = DevSigner { seed: [0x24; 32] }.sign(&request).unwrap();
        let mut tampered = unsigned.clone();
        tampered.transaction.output[0].value = Amount::from_sat(6_000_000);
        assert_eq!(
            finalize_transfer(&a, &tampered, &signatures).unwrap_err(),
            DogecoinSdkError::InvalidSignature
        );
    }
}
