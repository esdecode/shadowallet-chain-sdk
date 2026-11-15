use crate::NanoError;

/// `network_identifier` (genesis block hash) of the live Nano network, published in the Nano protocol documentation.
/// A node reporting this identity is the real network, so signing is refused whatever else it claims.
pub const LIVE_NETWORK_ID: &str =
    "991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948";

/// Networks this wallet may sign for. Only a verified non-live identity can produce a `NanoNet`, so the signing path
/// (which requires one) cannot be reached for the live network. Nano blocks are not bound to a network, so a block
/// signed for a test network would be valid on the live network if the account chain existed there: that is exactly
/// why the node identity is checked before every signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NanoNet {
    pub name: String,
    pub network_identifier: String,
}

/// Pinned (name, network_identifier) pairs of non-live networks that were observed from a running node.
pub const PINNED_TEST_NETWORKS: &[(&str, &str)] = &[
    // Observed 2026-11-15 from an official Nano V29.0DB107 beta node (`version` RPC) synchronised with the public beta network.
    (
        "beta",
        "E1227CF974C1455A8B630433D94F3DDBF495EEAC9ADD2481A4A1D90A0D00F488",
    ),
];

impl NanoNet {
    pub fn verify(name: &str, network_identifier: &str) -> Result<Self, NanoError> {
        let id = network_identifier.to_ascii_uppercase();
        if name == "live" || id == LIVE_NETWORK_ID {
            return Err(NanoError::Network(
                "Nano mainnet signing and broadcasting are disabled".into(),
            ));
        }
        if !PINNED_TEST_NETWORKS
            .iter()
            .any(|(n, i)| *n == name && i.eq_ignore_ascii_case(&id))
        {
            return Err(NanoError::Network(format!(
                "network {name:?} ({id}) is not a pinned Nano test network"
            )));
        }
        Ok(Self {
            name: name.to_string(),
            network_identifier: id,
        })
    }
}
