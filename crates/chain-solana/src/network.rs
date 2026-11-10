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

    /// Phase 6 policy: only the disposable local validator may sign.
    pub fn signing_enabled(self) -> bool {
        self == Self::Localnet
    }
}
