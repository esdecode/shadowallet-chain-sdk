use dcr_rs::network::Network;

use crate::DecredError;

/// A Decred network as reported by a dcrd node (`getblockchaininfo.chain`) plus the genesis block hash it must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecredNet {
    pub name: &'static str,
    pub network: Network,
    /// `getblockchaininfo.chain` value.
    pub chain: &'static str,
    /// `getblockhash 0`, display order.
    pub genesis_hash: &'static str,
    /// Blocks before a coinbase output can be spent.
    pub coinbase_maturity: u64,
    /// Mainnet is read-only: the Rust authorization boundary never signs for it.
    pub is_mainnet: bool,
}

pub const MAINNET: DecredNet = DecredNet {
    name: "decred-mainnet",
    network: Network::Mainnet,
    chain: "mainnet",
    genesis_hash: "298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980",
    coinbase_maturity: 256,
    is_mainnet: true,
};
pub const TESTNET: DecredNet = DecredNet {
    name: "decred-testnet",
    network: Network::Testnet,
    chain: "testnet3",
    genesis_hash: "a649dce53918caf422e9c711c858837e08d626ecfcd198969b24f7b634a49bac",
    coinbase_maturity: 16,
    is_mainnet: false,
};
/// Private simulation network: a locally run dcrd, never a public network.
pub const SIMNET: DecredNet = DecredNet {
    name: "decred-simnet",
    network: Network::Simnet,
    chain: "simnet",
    genesis_hash: "6bef82c645999585f7255cb02672921ac2f5492820090cd635fe3a59d16b4f87",
    coinbase_maturity: 16,
    is_mainnet: false,
};
pub const NETS: [DecredNet; 3] = [MAINNET, TESTNET, SIMNET];

impl DecredNet {
    pub fn by_name(name: &str) -> Option<DecredNet> {
        NETS.iter().copied().find(|n| n.name == name)
    }
}

/// A network a node proved to be (chain name and genesis hash) and that is not mainnet. Only this type can reach the
/// signing and broadcast path, so a mainnet node can never be used to sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedNet(pub DecredNet);

impl VerifiedNet {
    pub fn verify(net: DecredNet, chain: &str, genesis: &str) -> Result<Self, DecredError> {
        if net.is_mainnet {
            return Err(DecredError::Network(
                "Decred mainnet signing and broadcasting are disabled".into(),
            ));
        }
        if chain != net.chain {
            return Err(DecredError::Network(format!(
                "node reports chain {chain:?}, expected {:?}",
                net.chain
            )));
        }
        if !genesis.eq_ignore_ascii_case(net.genesis_hash) {
            return Err(DecredError::Network(format!(
                "genesis {genesis} does not match {}",
                net.name
            )));
        }
        Ok(Self(net))
    }
}
