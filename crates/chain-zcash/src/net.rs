use zcash_protocol::consensus::Network;

/// A Zcash network. Mainnet is read-only unless the crate is built with `mainnet-send` (the wallet's internal-testing build).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZcashNet {
    pub name: &'static str,
    pub is_mainnet: bool,
    /// Value lightwalletd reports in `chainName`.
    pub chain_name: &'static str,
    pub sapling_activation_height: u32,
    /// Sapling activation block hash, from zcash/zcash src/chainparams.cpp.
    pub sapling_activation_hash: &'static str,
}

pub const MAINNET: ZcashNet = ZcashNet {
    name: "zcash-mainnet",
    is_mainnet: true,
    chain_name: "main",
    sapling_activation_height: 419_200,
    sapling_activation_hash: "00000000025a57200d898ac7f21e26bf29028bbe96ec46e05b2c17cc9db9e4f3",
};

pub const TESTNET: ZcashNet = ZcashNet {
    name: "zcash-testnet",
    is_mainnet: false,
    chain_name: "test",
    sapling_activation_height: 280_000,
    sapling_activation_hash: "000420e7fcc3a49d729479fb0b560dd7b8617b178a08e9e389620a9d1dd6361a",
};

impl ZcashNet {
    pub fn signing_enabled(self) -> bool {
        self == TESTNET || (cfg!(feature = "mainnet-send") && self == MAINNET)
    }

    pub fn validate(self) -> Result<(), crate::ZcashError> {
        if self == MAINNET || self == TESTNET {
            Ok(())
        } else {
            Err(crate::ZcashError::Network(
                "unknown or modified network profile".to_owned(),
            ))
        }
    }
    pub fn by_name(name: &str) -> Option<ZcashNet> {
        [MAINNET, TESTNET].into_iter().find(|n| n.name == name)
    }

    pub fn params(&self) -> Network {
        if self.is_mainnet {
            Network::MainNetwork
        } else {
            Network::TestNetwork
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modified_profiles_and_mainnet_cannot_sign() {
        assert!(TESTNET.signing_enabled());
        assert_eq!(MAINNET.signing_enabled(), cfg!(feature = "mainnet-send"));
        let mut forged = MAINNET;
        forged.is_mainnet = false;
        assert!(!forged.signing_enabled());
        assert!(forged.validate().is_err());
        forged = TESTNET;
        forged.sapling_activation_hash = MAINNET.sapling_activation_hash;
        assert!(!forged.signing_enabled());
        assert!(forged.validate().is_err());
    }
}
