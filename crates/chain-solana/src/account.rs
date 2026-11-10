//! SLIP-0010 Ed25519 derivation and restricted signing.
//!
//! Default path: `m/44'/501'/{account}'/0'` (the path used by the Solana CLI
//! `prompt:?key=N/0` recovery and by Phantom/Solflare for account N). All
//! segments are hardened, as Ed25519 SLIP-0010 requires.

use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::error::SolanaError;
use crate::message::Transaction;
use crate::pubkey::Pubkey;
use crate::transfer::{PreparedTransfer, SignedTransfer};

type HmacSha512 = Hmac<Sha512>;
const HARDENED: u32 = 0x8000_0000;

pub fn default_path(account: u32) -> [u32; 4] {
    [44, 501, account, 0]
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<[u8; 64]>, SolanaError> {
    let mut mac =
        HmacSha512::new_from_slice(key).map_err(|_| SolanaError::Derivation("hmac key".into()))?;
    for part in parts {
        mac.update(part);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

/// SLIP-0010 ed25519 derivation. Every index is treated as hardened.
fn slip10_ed25519(seed: &[u8], path: &[u32]) -> Result<Zeroizing<[u8; 32]>, SolanaError> {
    if !(16..=64).contains(&seed.len()) {
        return Err(SolanaError::Derivation("seed must be 16..=64 bytes".into()));
    }
    let mut node = hmac(b"ed25519 seed", &[seed])?;
    for index in path {
        if index & HARDENED != 0 {
            return Err(SolanaError::Derivation("index must be below 2^31".into()));
        }
        let hardened = (index | HARDENED).to_be_bytes();
        let next = hmac(&node[32..], &[&[0u8], &node[..32], &hardened])?;
        node = next;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&node[..32]);
    Ok(key)
}

/// A Solana account whose secret never leaves this struct.
pub struct SolanaAccount {
    signing: SigningKey,
    public: Pubkey,
}

impl std::fmt::Debug for SolanaAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolanaAccount")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl SolanaAccount {
    /// Derive account `index` from a BIP-39 seed (64 bytes).
    pub fn from_seed(seed: &[u8], index: u32) -> Result<Self, SolanaError> {
        let secret = slip10_ed25519(seed, &default_path(index))?;
        let signing = SigningKey::from_bytes(&secret);
        let public = Pubkey(signing.verifying_key().to_bytes());
        Ok(Self { signing, public })
    }

    pub fn public(&self) -> Pubkey {
        self.public
    }

    pub fn address(&self) -> String {
        self.public.to_base58()
    }

    /// The only signing entry point. It re-verifies the exact message bytes
    /// against the reviewed intent and the allowlist, checks that this account
    /// is the sender and fee payer, and refuses networks where signing is
    /// disabled. There is deliberately no arbitrary-message API.
    pub fn sign_transfer(
        &self,
        prepared: &PreparedTransfer,
    ) -> Result<SignedTransfer, SolanaError> {
        if !prepared.intent.network.signing_enabled() {
            return Err(SolanaError::SigningRefused(format!(
                "signing is disabled on {}",
                prepared.intent.network.id()
            )));
        }
        prepared.verify()?;
        if prepared.intent.from != self.public {
            return Err(SolanaError::SigningRefused(
                "sender is not this account".into(),
            ));
        }
        let signature = self.signing.sign(&prepared.message_bytes).to_bytes();
        let transaction = Transaction {
            signatures: vec![signature],
            message: prepared.message.clone(),
        };
        transaction.verify_signatures()?;
        Ok(SignedTransfer {
            signature: bs58::encode(signature).into_string(),
            raw: transaction.serialize(),
        })
    }
}

impl Drop for SolanaAccount {
    fn drop(&mut self) {
        // SigningKey zeroizes itself (feature `zeroize`); belt and braces for
        // the public copy is unnecessary. Keep the impl to document intent.
        self.public.0.zeroize();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// SLIP-0010 test vector 1 for ed25519 (seed 000102…0f).
    #[test]
    fn slip10_vector_1() {
        let seed = hex("000102030405060708090a0b0c0d0e0f");
        let master = hmac(b"ed25519 seed", &[&seed]).unwrap();
        assert_eq!(
            master[..32],
            hex("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")[..]
        );
        assert_eq!(
            master[32..],
            hex("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")[..]
        );
        // Child derivation is checked against `solana-keygen` in
        // tests/derivation_oracle.rs (independent implementation).
    }

    #[test]
    fn rejects_bad_seed_and_indices() {
        assert!(slip10_ed25519(&[0; 8], &[0]).is_err());
        assert!(slip10_ed25519(&[0; 64], &[HARDENED]).is_err());
    }

    #[test]
    fn deterministic_and_account_separated() {
        let seed = [7u8; 64];
        let a0 = SolanaAccount::from_seed(&seed, 0).unwrap();
        let a0b = SolanaAccount::from_seed(&seed, 0).unwrap();
        let a1 = SolanaAccount::from_seed(&seed, 1).unwrap();
        assert_eq!(a0.public(), a0b.public());
        assert_ne!(a0.public(), a1.public());
        assert!(a0.public().is_on_curve());
    }
}
