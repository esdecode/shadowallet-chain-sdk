#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_evm::{
    ANVIL, Address, EvmAccount, EvmProvider, EvmStore, HistorySource, LocalHistory,
    TransactionDraft, U256, checksum_address, prepare_native_transfer_with_nonce,
    reconcile_receipt,
};

const ANVIL_KEY: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];

#[tokio::test]
#[ignore = "requires Anvil on ANVIL_RPC_URL"]
async fn anvil_native_transfer_end_to_end() {
    let url = std::env::var("ANVIL_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_owned());
    let provider = EvmProvider::connect(ANVIL, &url).await.expect("connect");
    let account = EvmAccount::from_private_key(ANVIL, &ANVIL_KEY, 0).expect("account");
    assert_eq!(
        checksum_address(account.address).to_lowercase(),
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    );
    let recipient = Address::from([0x42u8; 20]);
    let amount = U256::from(1_000_000_000_000_000u64);

    let dir = tempfile::tempdir().expect("tempdir");
    let store_path = dir.path().join("evm.sqlite");
    let store = EvmStore::open(&store_path).expect("store");
    store
        .register_account(ANVIL.chain_id, &checksum_address(account.address))
        .expect("register");
    let network_nonce = provider
        .pending_nonce(account.address)
        .await
        .expect("nonce");
    let reserved = store
        .reserve_nonce(
            ANVIL.chain_id,
            &checksum_address(account.address),
            network_nonce,
            &TransactionDraft::native(&checksum_address(recipient), "1000000000000000"),
        )
        .expect("reserve");
    assert_eq!(reserved.nonce, network_nonce);

    let before = provider.native_balance(recipient).await.expect("balance");
    let unsigned = prepare_native_transfer_with_nonce(
        &provider,
        account.address,
        recipient,
        amount,
        reserved.nonce,
    )
    .await
    .expect("prepare");
    let digest = unsigned.signature_hash();
    let signature = account.sign_digest(digest.0).expect("sign");
    let raw = unsigned.finalize(&signature).expect("finalize");
    let raw_hex = format!(
        "0x{}",
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let hash = provider.broadcast(&raw).await.expect("broadcast");
    store
        .mark_broadcast(reserved.id, &format!("{hash:?}"), &raw_hex)
        .expect("mark broadcast");

    let mut receipt = None;
    for _ in 0..30 {
        receipt = provider.receipt(hash).await.expect("receipt");
        if receipt.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let receipt = receipt.expect("receipt not mined");
    assert!(receipt.status, "transaction failed");
    assert_eq!(
        reconcile_receipt(&store, &provider, reserved.id, hash)
            .await
            .expect("reconcile"),
        Some(true)
    );
    let history = LocalHistory::new(&store)
        .page(ANVIL.chain_id, &checksum_address(account.address), 10, None)
        .expect("history");
    assert_eq!(history.items.len(), 1);
    assert_eq!(history.items[0].status, "confirmed");
    drop(store);
    let reopened = EvmStore::open(&store_path).expect("reopen");
    assert_eq!(
        reopened
            .history(ANVIL.chain_id, &checksum_address(account.address), 10, None)
            .expect("history after reopen")[0]
            .status,
        "confirmed"
    );
    let after = provider.native_balance(recipient).await.expect("balance");
    assert_eq!(after, before + amount);
}
