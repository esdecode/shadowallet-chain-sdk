use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign, raw_verify};
use ed25519_dalek::{Signature, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::NanoError;

type Blake2b256 = Blake2b<U32>;

/// A 32-byte Nano wallet seed (shown to users as 64 hex digits). Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 32]);

impl Seed {
    pub fn from_hex(text: &str) -> Result<Self, NanoError> {
        let text = text.trim();
        if text.len() != 64 {
            return Err(NanoError::Seed(
                "a Nano seed is exactly 64 hex digits".into(),
            ));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(text, &mut out)
            .map_err(|_| NanoError::Seed("not hexadecimal".into()))?;
        Ok(Self(out))
    }

    pub fn generate() -> Result<Self, NanoError> {
        let mut out = [0u8; 32];
        getrandom::getrandom(&mut out)
            .map_err(|e| NanoError::Seed(format!("no system randomness: {e}")))?;
        Ok(Self(out))
    }

    pub fn to_hex_upper(&self) -> String {
        hex::encode_upper(self.0)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Private key of account `index`: Blake2b-256(seed || index as big-endian u32).
pub fn derive_private_key(seed: &Seed, index: u32) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(seed.0);
    h.update(index.to_be_bytes());
    h.finalize().into()
}

fn expand(private: &[u8; 32]) -> ExpandedSecretKey {
    let mut digest = [0u8; 64];
    digest.copy_from_slice(&Blake2b512::digest(private));
    let esk = ExpandedSecretKey::from_bytes(&digest);
    digest.zeroize();
    esk
}

/// Ed25519 public key with Blake2b-512 as the key-expansion hash (Nano's variant).
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    VerifyingKey::from(&expand(private)).to_bytes()
}

/// Sign a 32-byte block hash.
pub fn sign_hash(private: &[u8; 32], hash: &[u8; 32]) -> [u8; 64] {
    let esk = expand(private);
    let vk = VerifyingKey::from(&esk);
    raw_sign::<Blake2b512>(&esk, hash, &vk).to_bytes()
}

pub fn verify_hash(
    public: &[u8; 32],
    hash: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), NanoError> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| NanoError::Signature)?;
    raw_verify::<Blake2b512>(&vk, hash, &Signature::from_bytes(signature))
        .map_err(|_| NanoError::Signature)
}

/// BIP-39 route used by Ledger, Nault and Cake Wallet: SLIP-0010 Ed25519 (hardened only) at `m/44'/165'/index'`.
/// The 32-byte leaf is used directly as the Nano private key. `bip39_seed` is the 64-byte BIP-39 seed.
pub fn derive_bip44_private_key(bip39_seed: &[u8], index: u32) -> Result<[u8; 32], NanoError> {
    if index >= 0x8000_0000 {
        return Err(NanoError::Seed("account index must be below 2^31".into()));
    }
    slip10_ed25519(bip39_seed, &[44, 165, index])
}

/// SLIP-0010 Ed25519 derivation of an arbitrary hardened path (used to check the implementation against the
/// official SLIP-0010 test vectors).
pub fn slip10_ed25519(seed: &[u8], hardened_path: &[u32]) -> Result<[u8; 32], NanoError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let mut mac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
        .map_err(|_| NanoError::Seed("hmac key".into()))?;
    mac.update(seed);
    let mut node: [u8; 64] = mac.finalize().into_bytes().into();
    for child in hardened_path {
        let mut data = vec![0u8];
        data.extend_from_slice(&node[..32]);
        data.extend_from_slice(&(child | 0x8000_0000).to_be_bytes());
        let mut mac = Hmac::<Sha512>::new_from_slice(&node[32..])
            .map_err(|_| NanoError::Seed("hmac key".into()))?;
        mac.update(&data);
        node = mac.finalize().into_bytes().into();
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&node[..32]);
    Ok(out)
}
