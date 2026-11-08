//! Watch-only Litecoin integration.
//!
//! The SDK derives public addresses, builds unsigned P2WPKH transactions and
//! verifies/finalizes externally produced ECDSA signatures. It never stores a
//! seed or private key, and it cannot sign by itself.

pub mod engine;

use std::str::FromStr;

use litecoin::bip32::{DerivationPath, Xpub};
use litecoin::consensus::encode::{deserialize, serialize_hex};
use litecoin::hashes::Hash;
use litecoin::secp256k1::{Message, Secp256k1};
use litecoin::sighash::SighashCache;
use litecoin::{
    Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, NetworkKind, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use shadowallet_chain_core::{ChainId, NetworkId, SignRequest, SigningAlgorithm};
use shadowallet_chain_utxo::{FeePolicy, FeePolicyError, Utxo};
use thiserror::Error;

/// Litecoin networks supported by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LtcNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl LtcNetwork {
    pub const fn network(self) -> Network {
        match self {
            Self::Mainnet => Network::Bitcoin,
            Self::Testnet => Network::Testnet4,
            Self::Regtest => Network::Regtest,
        }
    }

    pub const fn network_id(self) -> &'static str {
        match self {
            Self::Mainnet => "litecoin-mainnet",
            Self::Testnet => "litecoin-testnet",
            Self::Regtest => "litecoin-regtest",
        }
    }

    pub const fn kind(self) -> NetworkKind {
        match self {
            Self::Mainnet => NetworkKind::Main,
            Self::Testnet | Self::Regtest => NetworkKind::Test,
        }
    }

    pub fn parse(value: &str) -> Result<Self, LitecoinSdkError> {
        match value {
            "mainnet" | "litecoin-mainnet" => Ok(Self::Mainnet),
            "testnet" | "litecoin-testnet" => Ok(Self::Testnet),
            "regtest" | "litecoin-regtest" => Ok(Self::Regtest),
            _ => Err(LitecoinSdkError::UnknownNetwork),
        }
    }
}

/// Conservative safety envelope, not a network-policy claim.
pub const LITECOIN_FEE_POLICY: FeePolicy = FeePolicy {
    min_sat_vb: 1,
    max_sat_vb: 1_000,
    max_fee_sats: 10_000_000,
    max_fee_percent: 10,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LitecoinSdkError {
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

/// Watch-only account identified by an account-level xpub.
#[derive(Debug, Clone)]
pub struct LtcAccount {
    pub network: LtcNetwork,
    pub fingerprint: [u8; 4],
    xpub: Xpub,
}

impl LtcAccount {
    /// Build a watch-only account. `xpub` must be an account-level key
    /// (`m/84'/coin'/0'`) for the selected network.
    pub fn from_xpub(
        network: LtcNetwork,
        xpub: &str,
        fingerprint: [u8; 4],
    ) -> Result<Self, LitecoinSdkError> {
        let xpub = Xpub::from_str(xpub).map_err(|_| LitecoinSdkError::InvalidXpub)?;
        if xpub.network != network.kind() {
            return Err(LitecoinSdkError::WrongXpubNetwork);
        }
        Ok(Self {
            network,
            fingerprint,
            xpub,
        })
    }

    #[allow(clippy::expect_used)]
    pub fn chain_id() -> ChainId {
        ChainId::parse("litecoin").expect("static chain id")
    }

    #[allow(clippy::expect_used)]
    pub fn network_id(&self) -> NetworkId {
        NetworkId::parse(self.network.network_id()).expect("static network id")
    }

    pub fn account_id(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            self.fingerprint[0], self.fingerprint[1], self.fingerprint[2], self.fingerprint[3]
        )
    }

    /// Derive a public key for keychain/index (0 external, 1 change).
    pub fn public_key(
        &self,
        keychain: u32,
        index: u32,
    ) -> Result<CompressedPublicKey, LitecoinSdkError> {
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str(&format!("m/{keychain}/{index}"))
            .map_err(|_| LitecoinSdkError::Derivation)?;
        let child = self
            .xpub
            .derive_pub(&secp, &path)
            .map_err(|_| LitecoinSdkError::Derivation)?;
        Ok(CompressedPublicKey(child.public_key))
    }

    pub fn address(&self, keychain: u32, index: u32) -> Result<Address, LitecoinSdkError> {
        Ok(Address::p2wpkh(
            &self.public_key(keychain, index)?,
            self.network.network(),
        ))
    }

    pub fn validate_address(&self, address: &str) -> Result<Address, LitecoinSdkError> {
        let unchecked = Address::from_str(address)
            .map_err(|e| LitecoinSdkError::InvalidAddress(e.to_string()))?;
        unchecked
            .require_network(self.network.network())
            .map_err(|_| LitecoinSdkError::WrongNetwork)
    }
}

/// Unsigned transfer ready for external review and signing.
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
            .all(|input| input.witness.is_empty() && input.script_sig.is_empty())
    }
}

fn outpoint(value: &Utxo) -> Result<OutPoint, LitecoinSdkError> {
    let txid = Txid::from_str(&value.txid)
        .map_err(|_| LitecoinSdkError::Transaction("invalid txid".to_owned()))?;
    Ok(OutPoint {
        txid,
        vout: value.vout,
    })
}

/// Conservative P2WPKH virtual-size model for fee selection.
const P2WPKH_INPUT_VSIZE: u64 = 68;
const P2WPKH_OUTPUT_VSIZE: u64 = 31;
const TX_OVERHEAD_VSIZE: u64 = 11;
const CHANGE_DUST_SATS: u64 = 546;

pub fn estimate_vsize(inputs: usize, outputs: usize) -> u64 {
    TX_OVERHEAD_VSIZE
        .saturating_add(P2WPKH_INPUT_VSIZE.saturating_mul(inputs as u64))
        .saturating_add(P2WPKH_OUTPUT_VSIZE.saturating_mul(outputs as u64))
}

/// Build an unsigned P2WPKH transfer. No key material is used. The absolute
/// fee is derived from `fee_rate_sat_vb` and a conservative vsize estimate.
pub fn prepare_transfer(
    account: &LtcAccount,
    utxos: &[Utxo],
    destination: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    change_index: u32,
) -> Result<UnsignedTransfer, LitecoinSdkError> {
    let destination = account.validate_address(destination)?;
    if amount_sats == 0 {
        return Err(LitecoinSdkError::ZeroAmount);
    }
    LITECOIN_FEE_POLICY.check(fee_rate_sat_vb, 0, Some(amount_sats))?;
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by_key(|u| std::cmp::Reverse(u.value_sats));
    let mut selected: Vec<Utxo> = Vec::new();
    let mut total = 0u64;
    let mut fee_sats = 0u64;
    let mut funded = false;
    for utxo in sorted {
        total = total.saturating_add(utxo.value_sats);
        selected.push(utxo.clone());
        let provisional = fee_rate_sat_vb.saturating_mul(estimate_vsize(selected.len(), 2));
        if total >= amount_sats.saturating_add(provisional) {
            fee_sats = provisional;
            funded = true;
            break;
        }
    }
    if !funded {
        return Err(LitecoinSdkError::InsufficientFunds);
    }
    let mut change_sats = total - amount_sats - fee_sats;
    if change_sats > 0 && change_sats < CHANGE_DUST_SATS {
        fee_sats = fee_sats.saturating_add(change_sats);
        change_sats = 0;
    }
    LITECOIN_FEE_POLICY.check(fee_rate_sat_vb, fee_sats, Some(amount_sats))?;

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
            version: litecoin::transaction::Version::TWO,
            lock_time: litecoin::absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
            mw_tx: None,
            is_hog_ex: false,
        },
        fee_sats,
        change_sats,
        selected,
    })
}

fn spend_script(account: &LtcAccount, utxo: &Utxo) -> Result<ScriptBuf, LitecoinSdkError> {
    Ok(Address::p2wpkh(
        &account.public_key(utxo.keychain, utxo.index)?,
        account.network.network(),
    )
    .script_pubkey())
}

/// Build the exact transaction-specific signing request. Digests are BIP143
/// P2WPKH SIGHASH_ALL hashes over the committed unsigned bytes.
pub fn signing_request(
    account: &LtcAccount,
    unsigned: &UnsignedTransfer,
) -> Result<SignRequest, LitecoinSdkError> {
    if !unsigned.is_unsigned() {
        return Err(LitecoinSdkError::PrematureSignature);
    }
    if unsigned.transaction.input.len() != unsigned.selected.len() {
        return Err(LitecoinSdkError::Transaction(
            "input/utxo mismatch".to_owned(),
        ));
    }
    let mut digests = Vec::with_capacity(unsigned.selected.len());
    let mut public_keys = Vec::with_capacity(unsigned.selected.len());
    for (position, utxo) in unsigned.selected.iter().enumerate() {
        let public = account.public_key(utxo.keychain, utxo.index)?;
        let spk = spend_script(account, utxo)?;
        let mut cache = SighashCache::new(&unsigned.transaction);
        let sighash = cache
            .p2wpkh_signature_hash(
                position,
                &spk,
                Amount::from_sat(utxo.value_sats),
                EcdsaSighashType::All,
            )
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        digests.push(hex::encode(sighash.to_byte_array()));
        public_keys.push(public.to_string());
    }
    Ok(SignRequest {
        chain: LtcAccount::chain_id(),
        network: account.network_id(),
        account_id: account.account_id(),
        algorithm: SigningAlgorithm::Secp256k1Ecdsa,
        public_keys,
        digests,
    })
}

/// Finalize with externally produced DER signatures (SIGHASH_ALL implied).
/// Every signature is verified against the SDK-derived public key before the
/// transaction is returned.
pub fn finalize_transfer(
    account: &LtcAccount,
    unsigned: &UnsignedTransfer,
    signatures: &[Vec<u8>],
) -> Result<Transaction, LitecoinSdkError> {
    if signatures.len() != unsigned.selected.len() {
        return Err(LitecoinSdkError::SignatureCount);
    }
    if !unsigned.is_unsigned() {
        return Err(LitecoinSdkError::PrematureSignature);
    }
    let secp = Secp256k1::new();
    let mut tx = unsigned.transaction.clone();
    for (position, utxo) in unsigned.selected.iter().enumerate() {
        let public = account.public_key(utxo.keychain, utxo.index)?;
        let spk = spend_script(account, utxo)?;
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2wpkh_signature_hash(
                position,
                &spk,
                Amount::from_sat(utxo.value_sats),
                EcdsaSighashType::All,
            )
            .map_err(|e| LitecoinSdkError::Transaction(e.to_string()))?;
        let signature = litecoin::secp256k1::ecdsa::Signature::from_der(&signatures[position])
            .map_err(|_| LitecoinSdkError::InvalidSignature)?;
        let message = Message::from_digest(sighash.to_byte_array());
        secp.verify_ecdsa(&message, &signature, &public.0)
            .map_err(|_| LitecoinSdkError::InvalidSignature)?;
        let mut sig_bytes = signatures[position].clone();
        sig_bytes.push(EcdsaSighashType::All as u8);
        tx.input[position].witness = Witness::from_slice(&[sig_bytes, public.to_bytes().to_vec()]);
    }
    Ok(tx)
}

/// Deserialize a prepared unsigned transaction for independent review.
pub fn parse_unsigned(hex: &str) -> Result<Transaction, LitecoinSdkError> {
    let bytes =
        hex::decode(hex).map_err(|_| LitecoinSdkError::Transaction("invalid hex".to_owned()))?;
    deserialize(&bytes).map_err(|_| LitecoinSdkError::Transaction("invalid transaction".to_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use litecoin::bip32::Xpriv;
    use litecoin::secp256k1::{Secp256k1, SecretKey};
    use shadowallet_chain_core::{ExternalSigner, SignError, SignRequest};

    fn account() -> LtcAccount {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(LtcNetwork::Regtest.kind(), &[0x42; 32]).unwrap();
        let path = DerivationPath::from_str("m/84'/2'/0'").unwrap();
        let account = master.derive_priv(&secp, &path).unwrap();
        let xpub = Xpub::from_priv(&secp, &account);
        LtcAccount::from_xpub(
            LtcNetwork::Regtest,
            &xpub.to_string(),
            master.fingerprint(&secp).to_bytes(),
        )
        .unwrap()
    }

    fn utxo(value: u64, index: u32) -> Utxo {
        Utxo {
            txid: format!("{:064x}", index + 1),
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
            let master = Xpriv::new_master(LtcNetwork::Regtest.kind(), &self.seed).unwrap();
            let account = master
                .derive_priv(&secp, &DerivationPath::from_str("m/84'/2'/0'").unwrap())
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
        assert!(a.address(0, 0).unwrap().to_string().starts_with("rltc1"));
        let unsigned = prepare_transfer(
            &a,
            &[utxo(100_000, 0)],
            &a.address(0, 9).unwrap().to_string(),
            50_000,
            1,
            0,
        )
        .unwrap();
        assert!(unsigned.is_unsigned());
        assert_eq!(unsigned.change_sats, 49_859);
        assert_eq!(unsigned.transaction.output.len(), 2);
        assert!(!unsigned.hex().is_empty());
    }

    #[test]
    fn external_signer_flow_verifies_and_finalizes() {
        let a = account();
        let unsigned = prepare_transfer(
            &a,
            &[utxo(100_000, 0)],
            &a.address(0, 9).unwrap().to_string(),
            50_000,
            1,
            0,
        )
        .unwrap();
        let request = signing_request(&a, &unsigned).unwrap();
        assert_eq!(request.digests.len(), 1);
        let signer = DevSigner { seed: [0x42; 32] };
        let signatures = signer.sign(&request).unwrap();
        let signed = finalize_transfer(&a, &unsigned, &signatures).unwrap();
        assert!(!signed.input[0].witness.is_empty());
    }

    #[test]
    fn modified_output_invalidates_external_signature() {
        let a = account();
        let unsigned = prepare_transfer(
            &a,
            &[utxo(100_000, 0)],
            &a.address(0, 9).unwrap().to_string(),
            50_000,
            1,
            0,
        )
        .unwrap();
        let request = signing_request(&a, &unsigned).unwrap();
        let signer = DevSigner { seed: [0x42; 32] };
        let signatures = signer.sign(&request).unwrap();
        let mut tampered = unsigned.clone();
        tampered.transaction.output[0].value = Amount::from_sat(60_000);
        assert_eq!(
            finalize_transfer(&a, &tampered, &signatures).unwrap_err(),
            LitecoinSdkError::InvalidSignature
        );
    }

    #[test]
    fn wrong_signature_count_fails_closed() {
        let a = account();
        let unsigned = prepare_transfer(
            &a,
            &[utxo(100_000, 0)],
            &a.address(0, 9).unwrap().to_string(),
            50_000,
            1,
            0,
        )
        .unwrap();
        assert_eq!(
            finalize_transfer(&a, &unsigned, &[]).unwrap_err(),
            LitecoinSdkError::SignatureCount
        );
    }
}
