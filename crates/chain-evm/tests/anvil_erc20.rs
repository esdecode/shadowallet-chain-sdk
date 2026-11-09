#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_evm::{
    ANVIL, Address, Erc20Token, EvmAccount, EvmProvider, EvmStore, TransactionDraft, U256,
    checksum_address, erc20_transfers, prepare_deployment, prepare_erc20_transfer_with_nonce,
};

const ANVIL_KEY: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];

#[tokio::test]
#[ignore = "requires Anvil on ANVIL_RPC_URL"]
async fn anvil_erc20_transfer_end_to_end() {
    let url = std::env::var("ANVIL_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_owned());
    let provider = EvmProvider::connect(ANVIL, &url).await.expect("connect");
    let account = EvmAccount::from_private_key(ANVIL, &ANVIL_KEY, 0).expect("account");
    let bytecode = hex::decode(
        include_str!("token_bytecode.txt")
            .trim()
            .trim_start_matches("0x"),
    )
    .expect("hex");
    let deployment = prepare_deployment(&provider, account.address, bytecode)
        .await
        .expect("deployment proposal");
    let digest = deployment.signature_hash();
    let signature = account.sign_digest(digest.0).expect("sign deploy");
    let raw = deployment.finalize(&signature).expect("finalize deploy");
    let hash = provider.broadcast(&raw).await.expect("broadcast deploy");
    let mut receipt = None;
    for _ in 0..30 {
        receipt = provider.receipt(hash).await.expect("deploy receipt");
        if receipt.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let token_address = receipt
        .expect("deployment mined")
        .contract_address
        .expect("contract address");
    let token = Erc20Token {
        chain_id: ANVIL.chain_id,
        contract: token_address,
    };
    assert_eq!(token.decimals(&provider).await.expect("decimals"), 18);
    assert_eq!(token.symbol(&provider).await.expect("symbol"), "TST");
    assert_eq!(token.name(&provider).await.expect("name"), "Test Token");

    let dir = tempfile::tempdir().expect("tempdir");
    let store = EvmStore::open(dir.path().join("evm.sqlite")).expect("store");
    let sender = checksum_address(account.address);
    store
        .register_account(ANVIL.chain_id, &sender)
        .expect("register");
    let metadata = token
        .cache_metadata(&provider, &store)
        .await
        .expect("cache");
    assert_eq!(metadata.symbol.as_deref(), Some("TST"));
    assert_eq!(metadata.decimals, Some(18));

    let recipient = Address::from([0x43u8; 20]);
    let amount = U256::from(100_000_000_000_000_000_000u128); // 100 TST
    let before = token
        .balance_of(&provider, recipient)
        .await
        .expect("balance");
    let network_nonce = provider
        .pending_nonce(account.address)
        .await
        .expect("nonce");
    let reserved = store
        .reserve_nonce(
            ANVIL.chain_id,
            &sender,
            network_nonce,
            &TransactionDraft::native(&checksum_address(recipient), "0"),
        )
        .expect("reserve");
    let unsigned = prepare_erc20_transfer_with_nonce(
        &provider,
        account.address,
        token,
        recipient,
        amount,
        reserved.nonce,
    )
    .await
    .expect("prepare");
    let digest = unsigned.signature_hash();
    let signature = account.sign_digest(digest.0).expect("sign");
    let raw = unsigned.finalize(&signature).expect("finalize");
    let hash = provider.broadcast(&raw).await.expect("broadcast");
    let mut receipt = None;
    for _ in 0..30 {
        receipt = provider.receipt(hash).await.expect("receipt");
        if receipt.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let receipt = receipt.expect("mined");
    assert!(
        token.validate_transfer_receipt(&receipt, account.address, recipient, amount),
        "receipt does not bind the expected Transfer event"
    );
    let after = token
        .balance_of(&provider, recipient)
        .await
        .expect("balance");
    assert_eq!(after, before + amount);

    let latest = provider.block_number().await.expect("block");
    let transfers = erc20_transfers(&provider, token_address, 0, latest)
        .await
        .expect("logs");
    assert!(transfers.iter().any(|t| {
        t.from == account.address
            && t.to == recipient
            && t.amount == amount
            && t.tx_hash == receipt.transaction_hash
    }));
}
