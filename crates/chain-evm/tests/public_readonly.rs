#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_evm::Address;
use shadowallet_chain_evm::{
    ARBITRUM, BASE, BSC, EvmChain, EvmProvider, OPTIMISM, POLYGON, SEPOLIA,
};

#[tokio::test]
#[ignore = "requires public RPC network access; read-only"]
async fn public_networks_are_read_only_usable() {
    let cases: &[(EvmChain, &str)] = &[
        (SEPOLIA, "https://ethereum-sepolia-rpc.publicnode.com"),
        (POLYGON, "https://polygon-bor-rpc.publicnode.com"),
        (BSC, "https://bsc-rpc.publicnode.com"),
        (ARBITRUM, "https://arbitrum-one-rpc.publicnode.com"),
        (OPTIMISM, "https://optimism-rpc.publicnode.com"),
        (BASE, "https://base-rpc.publicnode.com"),
    ];
    for (chain, url) in cases {
        let provider = EvmProvider::connect(*chain, url).await.expect(chain.name);
        let block = provider.block_number().await.expect(chain.name);
        let base = provider.latest_base_fee().await.expect(chain.name);
        let _balance = provider
            .native_balance(Address::zero())
            .await
            .expect(chain.name);
        assert!(block > 0, "{} block", chain.name);
        assert!(base > 0 || chain.name == "bsc", "{} base fee", chain.name);
    }
}
