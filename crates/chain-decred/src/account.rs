use dcr_rs::address::Address;
use dcr_rs::hd::{BRANCH_EXTERNAL, BRANCH_INTERNAL, ExtPrivKey};
use dcr_rs::secp256k1::{All, Secp256k1, SecretKey};

use crate::DecredError;
use crate::net::DecredNet;

/// One BIP-44 account (`m/44'/coin'/account'`) of a Decred wallet. Derivation follows dcrd's `hdkeychain` variant, so
/// it matches dcrwallet and Decrediton for a BIP-39 seed. (Decrediton's native 33-word PGP seed is a different recovery
/// format and is not supported.)
pub struct Account {
    pub net: DecredNet,
    secp: Secp256k1<All>,
    key: ExtPrivKey,
}

fn derivation(e: dcr_rs::Error) -> DecredError {
    DecredError::Derivation(format!("{e:?}"))
}

impl Account {
    /// `bip39_seed` is the 64-byte BIP-39 seed held by the vault.
    pub fn from_seed(bip39_seed: &[u8], net: DecredNet, account: u32) -> Result<Self, DecredError> {
        let secp = Secp256k1::new();
        let master = ExtPrivKey::master_from_seed(bip39_seed, net.network).map_err(derivation)?;
        let key = master.account_key(&secp, account).map_err(derivation)?;
        Ok(Self { net, secp, key })
    }

    pub fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    /// P2PKH address string at `branch/index` (0 = external, 1 = internal change).
    pub fn address(&self, branch: u32, index: u32) -> Result<String, DecredError> {
        Ok(Address::from_pubkey(&self.pubkey(branch, index)?, self.net.network).encode())
    }

    pub fn pubkey(&self, branch: u32, index: u32) -> Result<[u8; 33], DecredError> {
        if branch != BRANCH_EXTERNAL && branch != BRANCH_INTERNAL {
            return Err(DecredError::Derivation("branch must be 0 or 1".into()));
        }
        let child = self
            .key
            .address_key(&self.secp, branch, index)
            .map_err(derivation)?;
        Ok(child.compressed_pubkey(&self.secp))
    }

    pub(crate) fn secret(&self, branch: u32, index: u32) -> Result<SecretKey, DecredError> {
        Ok(self
            .key
            .address_key(&self.secp, branch, index)
            .map_err(derivation)?
            .secret)
    }
}
