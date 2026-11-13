use crate::error::SolanaError;

/// Solana cluster identity. The genesis hash binds a signing request to a
/// cluster so a devnet transaction can never be prepared against mainnet RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SolanaNetwork {
    Localnet,
    Devnet,
    Testnet,
    MainnetBeta,
}

impl SolanaNetwork {
    pub const ALL: [SolanaNetwork; 4] = [
        Self::Localnet,
        Self::Devnet,
        Self::Testnet,
        Self::MainnetBeta,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::Localnet => "solana-localnet",
            Self::Devnet => "solana-devnet",
            Self::Testnet => "solana-testnet",
            Self::MainnetBeta => "solana-mainnet-beta",
        }
    }

    pub fn parse(value: &str) -> Result<Self, SolanaError> {
        Self::ALL
            .into_iter()
            .find(|n| n.id() == value)
            .ok_or_else(|| SolanaError::WrongNetwork(format!("unknown network {value}")))
    }

    /// Well-known genesis hashes. `Localnet` has none: every disposable
    /// validator generates its own genesis.
    pub fn genesis_hash(self) -> Option<&'static str> {
        match self {
            Self::Localnet => None,
            Self::Devnet => Some("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
            Self::Testnet => Some("4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"),
            Self::MainnetBeta => Some("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"),
        }
    }

    pub fn is_mainnet(self) -> bool {
        self == Self::MainnetBeta
    }

    /// Signing policy: the disposable local validator and the public Devnet (worthless test SOL)
    /// may sign. Testnet and mainnet-beta never do. The cluster identity is verified by genesis
    /// hash before any transaction is prepared (see `SolanaRpc::verify_network`).
    pub fn signing_enabled(self) -> bool {
        matches!(self, Self::Localnet | Self::Devnet)
    }
}

#[cfg(test)]
mod policy_tests {
    use super::SolanaNetwork;

    #[test]
    fn only_localnet_and_devnet_sign() {
        let signing: Vec<_> = SolanaNetwork::ALL
            .iter()
            .filter(|n| n.signing_enabled())
            .collect();
        assert_eq!(
            signing,
            vec![&SolanaNetwork::Localnet, &SolanaNetwork::Devnet]
        );
        assert!(!SolanaNetwork::MainnetBeta.signing_enabled());
        assert!(!SolanaNetwork::Testnet.signing_enabled());
    }
}
