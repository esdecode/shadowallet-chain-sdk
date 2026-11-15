use crate::NanoError;

/// `network_identifier` (genesis block hash) of the live Nano network, published in the Nano protocol documentation
/// and reproduced by the genesis vector in `tests/vectors.rs`.
pub const LIVE_NETWORK_ID: &str =
    "991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948";

/// Genesis block hash of the official Nano **test** network: Blake2b-256(source || representative || account) of the
/// legacy open block built from `test_public_key_data` (`B0311EA5…B6D0`) in nano-node's `nano/secure/common.cpp`.
/// The public test network infrastructure (test.nano.org, its peers and faucet) was retired; the identity is kept so a
/// self-hosted node of the same network can be recognised, and it is confirmed against a running test-network node.
pub const TEST_NETWORK_ID: &str =
    "04270D7F11C4B2B472F2854C5A59F2A7E84226CE9ED799DE75744BD7D85FC9D9";

/// Network identifier reported by an official Nano V29 beta node synchronised with the public beta network.
pub const BETA_NETWORK_ID: &str =
    "E1227CF974C1455A8B630433D94F3DDBF495EEAC9ADD2481A4A1D90A0D00F488";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkKind {
    /// The real Nano network: read-only here, signing and broadcasting are permanently refused.
    Live,
    /// The official test network (same work parameters as live, worthless coins).
    Test,
    /// The public beta network (kept; separate identity from test and live).
    Beta,
}

impl NetworkKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Test => "test",
            Self::Beta => "beta",
        }
    }
}

/// A network recognised from the identity a node reports (its name and genesis hash must both match a pinned pair).
/// Nano blocks are not bound to a network, so a block signed for a test network would be valid on the live network if
/// the same account chain existed there: signing is therefore only possible for a recognised non-live network, and a
/// node that claims a test name but reports the live genesis is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NanoNet {
    pub kind: NetworkKind,
    pub name: String,
    pub network_identifier: String,
}

const PINNED: [(NetworkKind, &str); 3] = [
    (NetworkKind::Live, LIVE_NETWORK_ID),
    (NetworkKind::Test, TEST_NETWORK_ID),
    (NetworkKind::Beta, BETA_NETWORK_ID),
];

impl NanoNet {
    /// Recognise any pinned network, including the live one (for read-only use).
    pub fn identify(name: &str, network_identifier: &str) -> Result<Self, NanoError> {
        let id = network_identifier.to_ascii_uppercase();
        let kind = PINNED
            .iter()
            .find(|(k, i)| k.name() == name && *i == id)
            .map(|(k, _)| *k)
            .ok_or_else(|| {
                NanoError::Network(format!(
                    "network {name:?} ({id}) does not match a pinned Nano network"
                ))
            })?;
        Ok(Self {
            kind,
            name: name.to_string(),
            network_identifier: id,
        })
    }

    /// Only a recognised non-live network may sign or broadcast.
    pub fn can_sign(&self) -> bool {
        self.kind != NetworkKind::Live
    }

    /// Recognise a network for signing: the live network is refused.
    pub fn verify(name: &str, network_identifier: &str) -> Result<Self, NanoError> {
        let id = network_identifier.to_ascii_uppercase();
        if name == "live" || id == LIVE_NETWORK_ID {
            return Err(NanoError::Network(
                "Nano mainnet signing and broadcasting are disabled".into(),
            ));
        }
        Self::identify(name, &id)
    }
}
