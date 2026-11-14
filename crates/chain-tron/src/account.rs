use std::str::FromStr;

use bip32::{DerivationPath, XPrv};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

use crate::{TronAddress, TronError};

/// A TRON account at `m/44'/195'/0'/0/index` (SLIP-44 coin type 195).
pub struct TronAccount {
    pub index: u32,
    pub address: TronAddress,
    secret: SecretKey,
}

impl Drop for TronAccount {
    fn drop(&mut self) {
        self.secret.non_secure_erase();
    }
}

fn address_of_public(public: &PublicKey) -> TronAddress {
    let hash = Keccak256::digest(&public.serialize_uncompressed()[1..]);
    let mut raw = [0u8; 20];
    raw.copy_from_slice(&hash[12..]);
    TronAddress::from_evm_bytes(&raw)
}

impl TronAccount {
    pub fn from_seed(seed: &[u8], index: u32) -> Result<Self, TronError> {
        let path = DerivationPath::from_str(&format!("m/44'/195'/0'/0/{index}"))
            .map_err(|_| TronError::Derivation)?;
        let child = XPrv::derive_from_path(seed, &path).map_err(|_| TronError::Derivation)?;
        let secret = SecretKey::from_byte_array(child.private_key().to_bytes().into())
            .map_err(|_| TronError::Derivation)?;
        let address = address_of_public(&PublicKey::from_secret_key(
            &Secp256k1::signing_only(),
            &secret,
        ));
        Ok(Self {
            index,
            address,
            secret,
        })
    }

    pub fn from_private_key(key: &[u8; 32]) -> Result<Self, TronError> {
        let secret = SecretKey::from_byte_array(*key).map_err(|_| TronError::Derivation)?;
        let address = address_of_public(&PublicKey::from_secret_key(
            &Secp256k1::signing_only(),
            &secret,
        ));
        Ok(Self {
            index: 0,
            address,
            secret,
        })
    }

    /// Sign a 32-byte transaction id; result is `r || s || recovery_id` as TRON expects.
    pub fn sign_txid(&self, txid: [u8; 32]) -> [u8; 65] {
        let sig = Secp256k1::signing_only()
            .sign_ecdsa_recoverable(Message::from_digest(txid), &self.secret);
        let (rid, compact) = sig.serialize_compact();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&compact);
        out[64] = i32::from(rid) as u8;
        out
    }
}

/// Recover the signer address from a signature over `txid` (checked before anything is broadcast).
pub fn recover_signer(txid: [u8; 32], signature: &[u8; 65]) -> Result<TronAddress, TronError> {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    let rid = RecoveryId::try_from(i32::from(signature[64]))
        .map_err(|_| TronError::Transaction("bad recovery id".to_owned()))?;
    let sig = RecoverableSignature::from_compact(&signature[..64], rid)
        .map_err(|_| TronError::Transaction("bad signature".to_owned()))?;
    let public = Secp256k1::verification_only()
        .recover_ecdsa(Message::from_digest(txid), &sig)
        .map_err(|_| TronError::Transaction("signature does not recover".to_owned()))?;
    Ok(address_of_public(&public))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip39_vector_derives_the_known_tron_address() {
        // Mnemonic "abandon ... about" at m/44'/195'/0'/0/0 (published TRON derivation vector).
        let m = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let a = TronAccount::from_seed(&m.to_seed(""), 0).unwrap();
        assert_eq!(a.address.to_base58(), "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
    }

    #[test]
    fn same_key_as_evm_has_the_same_20_byte_body() {
        // private key 1 -> Ethereum 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
        let mut k = [0u8; 32];
        k[31] = 1;
        let a = TronAccount::from_private_key(&k).unwrap();
        assert_eq!(
            hex::encode(a.address.body()),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
        assert_eq!(a.address.0[0], 0x41);
    }

    #[test]
    fn signature_recovers_to_the_signer() {
        let a = TronAccount::from_seed(&[7u8; 64], 3).unwrap();
        let sig = a.sign_txid([9u8; 32]);
        assert_eq!(recover_signer([9u8; 32], &sig).unwrap(), a.address);
        assert_ne!(recover_signer([8u8; 32], &sig).unwrap(), a.address);
    }
}
