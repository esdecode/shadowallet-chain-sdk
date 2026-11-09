#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_evm::{Address, U256};
use shadowallet_chain_evm::{BSC, EvmAccount, EvmProvider, EvmTxType, prepare_native_transfer};

const ANVIL_KEY: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];

#[tokio::test]
#[ignore = "requires Anvil with chain id 56 on ANVIL_BSC_RPC_URL"]
async fn anvil_legacy_eip155_transfer_end_to_end() {
    let url =
        std::env::var("ANVIL_BSC_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8546".to_owned());
    let provider = EvmProvider::connect(BSC, &url).await.expect("connect");
    let account = EvmAccount::from_private_key(BSC, &ANVIL_KEY, 0).expect("account");
    let recipient = Address::from([0x44u8; 20]);
    let amount = U256::from(1_000_000_000_000_000u64);

    let unsigned = prepare_native_transfer(&provider, account.address, recipient, amount)
        .await
        .expect("prepare legacy");
    assert_eq!(unsigned.tx_type, EvmTxType::Legacy);
    assert!(unsigned.gas_price.is_some());

    let digest = unsigned.signature_hash();
    let signature = account.sign_digest(digest.0).expect("sign");
    let raw = unsigned.finalize(&signature).expect("finalize");
    assert_ne!(raw[0], 0x02, "legacy envelope must not be typed 0x02");
    let hash = provider.broadcast(&raw).await.expect("broadcast");
    let mut receipt = None;
    for _ in 0..30 {
        receipt = provider.receipt(hash).await.expect("receipt");
        if receipt.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(receipt.expect("mined").status);
}
