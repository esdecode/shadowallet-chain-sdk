//! ZIP-32 account keys and addresses. The spending key is derived on demand from the wallet seed inside the
//! signing boundary and is never stored; the wallet database holds only the unified FULL viewing key.

use zcash_keys::address::UnifiedAddress;
use zcash_keys::encoding::AddressCodec as _;
use zcash_keys::keys::{
    ReceiverRequirement, UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey,
};
use zip32::{AccountId, DiversifierIndex};

use crate::{ZcashError, ZcashNet};

/// Unified addresses contain Orchard, Sapling and transparent receivers.
/// Both shielded pools use the official ecosystem provers.
pub const ADDRESS_REQUEST: UnifiedAddressRequest = UnifiedAddressRequest::unsafe_custom(
    ReceiverRequirement::Require,
    ReceiverRequirement::Require,
    ReceiverRequirement::Require,
);

pub fn account_id(index: u32) -> Result<AccountId, ZcashError> {
    AccountId::try_from(index).map_err(|_| ZcashError::Derivation)
}

/// Derive the unified spending key (ZIP-32). Only the signing boundary may call this.
pub fn spending_key(
    net: ZcashNet,
    seed: &[u8],
    index: u32,
) -> Result<UnifiedSpendingKey, ZcashError> {
    if !(32..=252).contains(&seed.len()) {
        return Err(ZcashError::Derivation);
    }
    UnifiedSpendingKey::from_seed(&net.params(), seed, account_id(index)?)
        .map_err(|_| ZcashError::Derivation)
}

pub fn full_viewing_key(
    net: ZcashNet,
    seed: &[u8],
    index: u32,
) -> Result<UnifiedFullViewingKey, ZcashError> {
    Ok(spending_key(net, seed, index)?.to_unified_full_viewing_key())
}

/// The default unified address (Orchard + transparent) and the diversifier index it was found at.
pub fn unified_address(
    net: ZcashNet,
    ufvk: &UnifiedFullViewingKey,
    j: DiversifierIndex,
) -> Result<(String, DiversifierIndex), ZcashError> {
    let (ua, found): (UnifiedAddress, DiversifierIndex) = ufvk
        .find_address(j, ADDRESS_REQUEST)
        .map_err(|_| ZcashError::Derivation)?;
    Ok((ua.encode(&net.params()), found))
}

/// The account's default transparent (t-) address (ZIP-32 / BIP-44 `m/44'/coin'/account'/0/0`).
pub fn transparent_address(
    net: ZcashNet,
    ufvk: &UnifiedFullViewingKey,
) -> Result<String, ZcashError> {
    let (ua, _) = ufvk
        .find_address(
            DiversifierIndex::new(),
            UnifiedAddressRequest::TRANSPARENT_ONLY,
        )
        .map_err(|_| ZcashError::Derivation)?;
    let t = ua.transparent().ok_or(ZcashError::Derivation)?;
    Ok(t.encode(&net.params()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAINNET, TESTNET};

    fn seed() -> Vec<u8> {
        bip39::Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            .unwrap()
            .to_seed("")
            .to_vec()
    }

    /// The transparent leg is checked against an independent BIP-32/BIP-44 + Base58Check implementation (python,
    /// secp256k1 + hash160). The shielded leg comes from the reference librustzcash implementation.
    #[test]
    fn transparent_addresses_match_the_independent_derivation() {
        for line in include_str!("transparent_vectors.txt").lines() {
            let f: Vec<&str> = line.split(' ').collect();
            let net = if f[0] == "main" { MAINNET } else { TESTNET };
            let ufvk = full_viewing_key(net, &seed(), f[1].parse().unwrap()).unwrap();
            assert_eq!(transparent_address(net, &ufvk).unwrap(), f[2], "{line}");
        }
    }

    #[test]
    fn unified_addresses_restore_all_three_receivers_on_the_correct_network() {
        let main = full_viewing_key(MAINNET, &seed(), 0).unwrap();
        let test = full_viewing_key(TESTNET, &seed(), 0).unwrap();
        let (a, ja) = unified_address(MAINNET, &main, DiversifierIndex::new()).unwrap();
        let (a2, _) = unified_address(MAINNET, &main, DiversifierIndex::new()).unwrap();
        let (t, _) = unified_address(TESTNET, &test, DiversifierIndex::new()).unwrap();
        assert_eq!(a, a2);
        let decoded = zcash_keys::address::Address::decode(&MAINNET.params(), &a).unwrap();
        let zcash_keys::address::Address::Unified(ua) = decoded else {
            panic!("unified address")
        };
        assert!(ua.orchard().is_some());
        assert!(ua.sapling().is_some());
        assert!(ua.transparent().is_some());
        assert!(a.starts_with("u1"), "{a}");
        assert!(t.starts_with("utest1"), "{t}");
        assert_ne!(a, t);
        // the next diversifier index gives a different address of the same account
        let mut next = ja;
        next.increment().unwrap();
        let (b, _) = unified_address(MAINNET, &main, next).unwrap();
        assert_ne!(a, b);
        // accounts differ
        let other = full_viewing_key(MAINNET, &seed(), 1).unwrap();
        assert_ne!(
            a,
            unified_address(MAINNET, &other, DiversifierIndex::new())
                .unwrap()
                .0
        );
        // a seed shorter than 32 bytes is refused (ZIP-32 requires at least 32)
        assert!(spending_key(MAINNET, &[1u8; 16], 0).is_err());
    }
}
