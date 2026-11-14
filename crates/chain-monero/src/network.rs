use monero_wallet::address::Network;

/// A Monero network and the genesis block hash a node must report to be trusted for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoneroNet {
    pub name: &'static str,
    pub network: Network,
    pub genesis_hash: [u8; 32],
    /// Mainnet is read-only: the Rust authorization boundary never signs for it.
    pub is_mainnet: bool,
}

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

// Genesis hashes were read from public nodes of each network (2026-11-14) and match the published values.
pub const MAINNET: MoneroNet = MoneroNet {
    name: "monero-mainnet",
    network: Network::Mainnet,
    genesis_hash: hex32("418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3"),
    is_mainnet: true,
};
pub const STAGENET: MoneroNet = MoneroNet {
    name: "monero-stagenet",
    network: Network::Stagenet,
    genesis_hash: hex32("76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb"),
    is_mainnet: false,
};
pub const TESTNET: MoneroNet = MoneroNet {
    name: "monero-testnet",
    network: Network::Testnet,
    genesis_hash: hex32("48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b"),
    is_mainnet: false,
};
pub const NETS: [MoneroNet; 3] = [MAINNET, STAGENET, TESTNET];

impl MoneroNet {
    pub fn by_name(name: &str) -> Option<MoneroNet> {
        NETS.iter().copied().find(|n| n.name == name)
    }
}
