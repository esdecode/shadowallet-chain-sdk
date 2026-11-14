//! TRON network profiles. A node is trusted only if its block 0 id equals the profile's genesis id,
//! so a node of another network (or a hostile one) is refused before anything is read or signed.

/// A TRON network the wallet knows about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TronNetwork {
    pub name: &'static str,
    /// Hex block id of block 0 (the genesis block), recorded from the public network and checked
    /// on every connection.
    pub genesis_block_id: &'static str,
    /// Mainnet is read-only: the Rust authorization boundary never signs for it.
    pub is_mainnet: bool,
    pub native_symbol: &'static str,
    pub native_decimals: u8,
}

pub const MAINNET: TronNetwork = TronNetwork {
    name: "tron-mainnet",
    genesis_block_id: "00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc",
    is_mainnet: true,
    native_symbol: "TRX",
    native_decimals: 6,
};

/// Nile public testnet (developers.tron.network, nileex.io).
pub const NILE: TronNetwork = TronNetwork {
    name: "tron-nile",
    genesis_block_id: "0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc",
    is_mainnet: false,
    native_symbol: "TRX",
    native_decimals: 6,
};

/// Shasta public testnet.
pub const SHASTA: TronNetwork = TronNetwork {
    name: "tron-shasta",
    genesis_block_id: "0000000000000000de1aa88295e1fcf982742f773e0419c5a9c134c994a9059e",
    is_mainnet: false,
    native_symbol: "TRX",
    native_decimals: 6,
};

pub const NETWORKS: [TronNetwork; 3] = [MAINNET, NILE, SHASTA];

impl TronNetwork {
    pub fn by_name(name: &str) -> Option<&'static TronNetwork> {
        NETWORKS.iter().find(|n| n.name == name)
    }
}
