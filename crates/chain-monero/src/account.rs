use std::str::FromStr;

use bip32::{DerivationPath, XPrv};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use monero_wallet::{
    ViewPair,
    address::{MoneroAddress, Network, SubaddressIndex},
    ed25519::{Point, Scalar},
};
use sha3::{Digest, Keccak256};
use zeroize::{Zeroize, Zeroizing};

use crate::MoneroError;

/// A Monero account. Keys are derived from the wallet's BIP-39 seed bytes, so the recovery phrase alone restores
/// it: path `m/44'/128'/account'/0/0` (secp256k1 BIP-32, as hardware wallets do), then
/// `spend = keccak256(child key) mod l` and `view = keccak256(spend) mod l` (Monero's own view-key rule).
/// This is NOT a Monero 25-word seed; the spend/view keys can be exported to other Monero wallets.
pub struct MoneroAccount {
    pub network: Network,
    pub index: u32,
    spend: Zeroizing<Scalar>,
    pair: ViewPair,
}

fn reduce(bytes: [u8; 32]) -> Scalar {
    Scalar::from(curve25519_dalek::Scalar::from_bytes_mod_order(bytes))
}

impl MoneroAccount {
    pub fn from_seed(network: Network, seed: &[u8], index: u32) -> Result<Self, MoneroError> {
        let path = DerivationPath::from_str(&format!("m/44'/128'/{index}'/0/0"))
            .map_err(|_| MoneroError::Derivation)?;
        let child = XPrv::derive_from_path(seed, &path).map_err(|_| MoneroError::Derivation)?;
        let mut digest: [u8; 32] = Keccak256::digest(child.private_key().to_bytes()).into();
        let spend = reduce(digest);
        digest.zeroize();
        Self::from_spend_scalar(network, index, spend)
    }

    /// From a raw 32-byte spend secret, e.g. an imported key (reduced modulo the group order).
    pub fn from_spend_key(network: Network, spend_secret: [u8; 32]) -> Result<Self, MoneroError> {
        Self::from_spend_scalar(network, 0, reduce(spend_secret))
    }

    fn from_spend_scalar(network: Network, index: u32, spend: Scalar) -> Result<Self, MoneroError> {
        let spend_point = Point::from(spend.into() * ED25519_BASEPOINT_POINT);
        let view = Zeroizing::new(Scalar::hash(Zeroizing::new(<[u8; 32]>::from(spend))));
        let pair = ViewPair::new(spend_point, view).map_err(|_| MoneroError::Derivation)?;
        Ok(Self {
            network,
            index,
            spend: Zeroizing::new(spend),
            pair,
        })
    }

    pub fn view_pair(&self) -> &ViewPair {
        &self.pair
    }

    /// The spend scalar. Only the signing boundary may call this.
    pub fn spend_scalar(&self) -> &Zeroizing<Scalar> {
        &self.spend
    }

    pub fn primary_address(&self) -> MoneroAddress {
        self.pair.legacy_address(self.network)
    }

    /// Subaddress `(account 0, index)`; index 0 is the primary address.
    pub fn address_at(&self, index: u32) -> MoneroAddress {
        match SubaddressIndex::new(0, index) {
            Some(i) => self.pair.subaddress(self.network, i),
            None => self.primary_address(),
        }
    }

    /// Key image of an owned output: `(spend + key_offset) * hash_to_point(output key)`. Needs the spend key, so it is
    /// computed here (inside the signing boundary), never in the view-only part of the wallet.
    pub fn key_image(&self, key_offset: Scalar, output_key: Point) -> [u8; 32] {
        let spend: curve25519_dalek::Scalar = (*self.spend).into();
        let offset: curve25519_dalek::Scalar = key_offset.into();
        let input_key: Zeroizing<curve25519_dalek::Scalar> = Zeroizing::new(spend + offset);
        let image = Point::biased_hash(output_key.compress().to_bytes()).into() * *input_key;
        Point::from(image).compress().to_bytes()
    }

    /// Hex of the private view key (needed to watch the wallet elsewhere; reveals incoming history).
    pub fn view_key_hex(&self) -> Zeroizing<String> {
        let view = Scalar::hash(Zeroizing::new(<[u8; 32]>::from(*self.spend)));
        Zeroizing::new(hex::encode(<[u8; 32]>::from(view)))
    }

    /// Hex of the private spend key (full control of the funds: shown only after an explicit user action).
    pub fn spend_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(<[u8; 32]>::from(*self.spend)))
    }
}

/// Parse an address for the expected network (a stagenet address is refused on mainnet and vice versa).
pub fn parse_address(network: Network, text: &str) -> Result<MoneroAddress, MoneroError> {
    MoneroAddress::from_str(network, text.trim())
        .map_err(|e| MoneroError::Address(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Vec<u8> {
        let m = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        m.to_seed("").to_vec()
    }

    #[test]
    fn derivation_is_deterministic_and_network_specific() {
        let a = MoneroAccount::from_seed(Network::Stagenet, &seed(), 0).unwrap();
        let b = MoneroAccount::from_seed(Network::Stagenet, &seed(), 0).unwrap();
        assert_eq!(
            a.primary_address().to_string(),
            b.primary_address().to_string()
        );
        let c = MoneroAccount::from_seed(Network::Stagenet, &seed(), 1).unwrap();
        assert_ne!(
            a.primary_address().to_string(),
            c.primary_address().to_string()
        );
        let m = MoneroAccount::from_seed(Network::Mainnet, &seed(), 0).unwrap();
        assert_ne!(
            a.primary_address().to_string(),
            m.primary_address().to_string()
        );
        assert!(
            a.primary_address().to_string().starts_with('5'),
            "stagenet primary addresses start with 5"
        );
        assert!(
            m.primary_address().to_string().starts_with('4'),
            "mainnet primary addresses start with 4"
        );
        assert_eq!(a.primary_address().to_string().len(), 95);
    }

    #[test]
    fn subaddresses_differ_and_have_the_right_prefix() {
        let a = MoneroAccount::from_seed(Network::Stagenet, &seed(), 0).unwrap();
        let s1 = a.address_at(1).to_string();
        let s2 = a.address_at(2).to_string();
        assert_ne!(s1, s2);
        assert_ne!(s1, a.primary_address().to_string());
        assert!(
            s1.starts_with('7'),
            "stagenet subaddresses start with 7: {s1}"
        );
        assert_eq!(a.address_at(0).to_string(), a.primary_address().to_string());
    }

    #[test]
    fn address_network_is_enforced() {
        let a = MoneroAccount::from_seed(Network::Stagenet, &seed(), 0).unwrap();
        let text = a.primary_address().to_string();
        assert!(parse_address(Network::Stagenet, &text).is_ok());
        assert!(parse_address(Network::Mainnet, &text).is_err());
        assert!(parse_address(Network::Stagenet, "garbage").is_err());
        let mut broken = text.clone();
        broken.replace_range(10..11, if &text[10..11] == "A" { "B" } else { "A" });
        assert!(
            parse_address(Network::Stagenet, &broken).is_err(),
            "checksum must be verified"
        );
    }

    #[test]
    fn view_key_follows_monero_rule_and_export_roundtrips() {
        let a = MoneroAccount::from_seed(Network::Stagenet, &seed(), 0).unwrap();
        let spend = hex::decode(&*a.spend_key_hex()).unwrap();
        let mut spend32 = [0u8; 32];
        spend32.copy_from_slice(&spend);
        let want =
            curve25519_dalek::Scalar::from_bytes_mod_order(Keccak256::digest(spend32).into());
        assert_eq!(hex::encode(want.to_bytes()), *a.view_key_hex());
        let b = MoneroAccount::from_spend_key(Network::Stagenet, spend32).unwrap();
        assert_eq!(
            a.primary_address().to_string(),
            b.primary_address().to_string()
        );
    }
}
