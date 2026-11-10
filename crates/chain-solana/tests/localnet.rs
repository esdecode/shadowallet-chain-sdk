#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Real-protocol tests against a disposable local validator.
//!
//! Run with:
//!   SOLANA_RPC_URL=http://127.0.0.1:8899 cargo test -p shadowallet-chain-solana \
//!       --test localnet -- --ignored --nocapture
//!
//! Start a validator with e.g.
//!   docker run -d --name uw-sol-validator -p 8899:8899 solanalabs/solana:v1.18.26 \
//!       solana-test-validator --reset --bind-address 0.0.0.0

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use shadowallet_chain_solana::message::Transaction;
use shadowallet_chain_solana::{
    ASSOCIATED_TOKEN_PROGRAM, AccountMeta, Instruction, Message, Pubkey, SYSTEM_PROGRAM,
    SolanaAccount, SolanaError, SolanaNetwork, SolanaRpc, TOKEN_PROGRAM, associated_token_address,
    prepare_native_transfer, prepare_spl_transfer,
};

fn rpc() -> SolanaRpc {
    let url = std::env::var("SOLANA_RPC_URL").expect("SOLANA_RPC_URL");
    SolanaRpc::http(&url, SolanaNetwork::Localnet).unwrap()
}

fn fresh_seed(tag: u8) -> [u8; 64] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut seed = [tag; 64];
    seed[..16].copy_from_slice(&nanos.to_le_bytes());
    seed
}

async fn confirm(rpc: &SolanaRpc, signature: &str) {
    for _ in 0..60 {
        if let Some(status) = rpc
            .get_signature_statuses(&[signature.to_owned()])
            .await
            .unwrap()[0]
            .clone()
        {
            assert!(!status.failed, "transaction failed: {:?}", status.error);
            if matches!(
                status.confirmation_status.as_deref(),
                Some("confirmed" | "finalized")
            ) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("transaction {signature} not confirmed");
}

async fn fund(rpc: &SolanaRpc, to: &Pubkey, lamports: u64) {
    let sig = rpc.request_airdrop(to, lamports).await.unwrap();
    confirm(rpc, &sig).await;
}

/// Test-only helper that signs setup transactions with a raw key. This is NOT
/// part of the SDK: production signing is `SolanaAccount::sign_transfer`.
async fn send_setup(
    rpc: &SolanaRpc,
    payer: &SigningKey,
    extra: &[&SigningKey],
    ixs: Vec<Instruction>,
) {
    let payer_key = Pubkey(payer.verifying_key().to_bytes());
    let (blockhash, _) = rpc.get_latest_blockhash().await.unwrap();
    let message = Message::new(&payer_key, &ixs, blockhash).unwrap();
    let bytes = message.serialize();
    let mut signatures = vec![payer.sign(&bytes).to_bytes()];
    for signer in extra {
        let key = Pubkey(signer.verifying_key().to_bytes());
        let index = message.account_keys.iter().position(|k| *k == key).unwrap();
        assert!(index < message.num_required_signatures as usize);
        while signatures.len() <= index {
            signatures.push([0; 64]);
        }
        signatures[index] = signer.sign(&bytes).to_bytes();
    }
    let tx = Transaction {
        signatures,
        message,
    };
    tx.verify_signatures().unwrap();
    let sig = rpc.send_transaction(&tx.serialize()).await.unwrap();
    confirm(rpc, &sig).await;
}

fn signing_key(tag: u8) -> SigningKey {
    let mut secret = fresh_seed(tag)[..32].to_vec();
    secret[31] ^= tag;
    SigningKey::from_bytes(&secret.try_into().unwrap())
}

#[tokio::test]
#[ignore = "requires a local Solana validator (SOLANA_RPC_URL)"]
async fn native_and_spl_transfers_end_to_end() {
    let rpc = rpc();
    rpc.verify_network().await.unwrap();

    let wallet = SolanaAccount::from_seed(&fresh_seed(1), 0).unwrap();
    let recipient = SolanaAccount::from_seed(&fresh_seed(2), 0).unwrap();
    fund(&rpc, &wallet.public(), 3_000_000_000).await;
    assert_eq!(
        rpc.get_balance(&wallet.public()).await.unwrap(),
        3_000_000_000
    );

    // ---- Native SOL --------------------------------------------------------
    let lamports = 500_000_000u64;
    let prepared = prepare_native_transfer(&rpc, wallet.public(), recipient.public(), lamports)
        .await
        .unwrap();
    assert_eq!(prepared.fee_lamports, 5_000);
    let signed = wallet.sign_transfer(&prepared).unwrap();
    let before = rpc.get_balance(&wallet.public()).await.unwrap();
    let sig = rpc.send_transaction(&signed.raw).await.unwrap();
    assert_eq!(sig, signed.signature);
    confirm(&rpc, &sig).await;
    assert_eq!(
        rpc.get_balance(&recipient.public()).await.unwrap(),
        lamports
    );
    assert_eq!(
        rpc.get_balance(&wallet.public()).await.unwrap(),
        before - lamports - prepared.fee_lamports
    );
    let effect = rpc
        .get_transaction_effect(&sig, &wallet.public())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(effect.native_delta, -(i128::from(lamports) + 5_000));
    assert!(!effect.failed);
    let history = rpc
        .get_signatures_for_address(&wallet.public(), 10, None)
        .await
        .unwrap();
    assert!(history.iter().any(|h| h.signature == sig));

    // Insufficient funds and zero amount fail closed, with nothing signed.
    assert!(matches!(
        prepare_native_transfer(&rpc, wallet.public(), recipient.public(), 9_000_000_000).await,
        Err(SolanaError::InsufficientFunds(_))
    ));
    assert!(
        prepare_native_transfer(&rpc, wallet.public(), recipient.public(), 0)
            .await
            .is_err()
    );
    // A dust transfer to a brand-new empty account would fail rent checks.
    let empty = SolanaAccount::from_seed(&fresh_seed(9), 0).unwrap();
    assert!(
        prepare_native_transfer(&rpc, wallet.public(), empty.public(), 1)
            .await
            .is_err()
    );

    // A prepared transfer cannot be signed by a different account.
    let intruder = SolanaAccount::from_seed(&fresh_seed(3), 0).unwrap();
    assert!(intruder.sign_transfer(&prepared).is_err());

    // ---- SPL token ---------------------------------------------------------
    let payer = signing_key(10);
    let payer_key = Pubkey(payer.verifying_key().to_bytes());
    fund(&rpc, &payer_key, 2_000_000_000).await;
    let mint_kp = signing_key(11);
    let mint = Pubkey(mint_kp.verifying_key().to_bytes());
    let rent_mint = rpc
        .get_minimum_balance_for_rent_exemption(82)
        .await
        .unwrap();

    let mut create_account = Vec::new();
    create_account.extend_from_slice(&0u32.to_le_bytes());
    create_account.extend_from_slice(&rent_mint.to_le_bytes());
    create_account.extend_from_slice(&82u64.to_le_bytes());
    create_account.extend_from_slice(&TOKEN_PROGRAM.0);
    let mut init_mint = vec![20u8, 6]; // InitializeMint2, 6 decimals
    init_mint.extend_from_slice(&payer_key.0); // mint authority
    init_mint.push(0); // no freeze authority
    send_setup(
        &rpc,
        &payer,
        &[&mint_kp],
        vec![
            Instruction {
                program_id: SYSTEM_PROGRAM,
                accounts: vec![
                    AccountMeta::new(payer_key, true),
                    AccountMeta::new(mint, true),
                ],
                data: create_account,
            },
            Instruction {
                program_id: *TOKEN_PROGRAM,
                accounts: vec![AccountMeta::new(mint, false)],
                data: init_mint,
            },
        ],
    )
    .await;

    let wallet_ata = associated_token_address(&wallet.public(), &mint, &TOKEN_PROGRAM).unwrap();
    let mut mint_to = vec![7u8];
    mint_to.extend_from_slice(&1_000_000_000u64.to_le_bytes());
    send_setup(
        &rpc,
        &payer,
        &[],
        vec![
            Instruction {
                program_id: *ASSOCIATED_TOKEN_PROGRAM,
                accounts: vec![
                    AccountMeta::new(payer_key, true),
                    AccountMeta::new(wallet_ata, false),
                    AccountMeta::readonly(wallet.public(), false),
                    AccountMeta::readonly(mint, false),
                    AccountMeta::readonly(SYSTEM_PROGRAM, false),
                    AccountMeta::readonly(*TOKEN_PROGRAM, false),
                ],
                data: vec![1],
            },
            Instruction {
                program_id: *TOKEN_PROGRAM,
                accounts: vec![
                    AccountMeta::new(mint, false),
                    AccountMeta::new(wallet_ata, false),
                    AccountMeta::readonly(payer_key, true),
                ],
                data: mint_to,
            },
        ],
    )
    .await;

    // Discovery: the wallet sees exactly one token account with 1000 tokens.
    let accounts = rpc
        .get_token_accounts_by_owner(&wallet.public())
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].address, wallet_ata);
    assert_eq!(accounts[0].mint, mint);
    assert_eq!(accounts[0].amount, 1_000_000_000);
    assert_eq!(accounts[0].decimals, 6);
    assert_eq!(
        rpc.get_token_account_balance(&wallet_ata).await.unwrap(),
        (1_000_000_000, 6)
    );

    // First transfer creates the recipient's associated account.
    let prepared =
        prepare_spl_transfer(&rpc, wallet.public(), recipient.public(), mint, 250_000_000)
            .await
            .unwrap();
    let signed = wallet.sign_transfer(&prepared).unwrap();
    let sig = rpc.send_transaction(&signed.raw).await.unwrap();
    confirm(&rpc, &sig).await;
    let recipient_ata =
        associated_token_address(&recipient.public(), &mint, &TOKEN_PROGRAM).unwrap();
    assert_eq!(
        rpc.get_token_account_balance(&recipient_ata)
            .await
            .unwrap()
            .0,
        250_000_000
    );
    assert_eq!(
        rpc.get_token_account_balance(&wallet_ata).await.unwrap().0,
        750_000_000
    );
    let effect = rpc
        .get_transaction_effect(&sig, &wallet.public())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(effect.token_deltas, vec![(mint, -250_000_000)]);

    // Second transfer reuses it (no create instruction).
    let prepared =
        prepare_spl_transfer(&rpc, wallet.public(), recipient.public(), mint, 100_000_000)
            .await
            .unwrap();
    assert_eq!(prepared.message.instructions.len(), 1);
    let signed = wallet.sign_transfer(&prepared).unwrap();
    confirm(&rpc, &rpc.send_transaction(&signed.raw).await.unwrap()).await;
    assert_eq!(
        rpc.get_token_account_balance(&recipient_ata)
            .await
            .unwrap()
            .0,
        350_000_000
    );

    // Negative cases: nothing is signed or broadcast.
    assert!(matches!(
        prepare_spl_transfer(
            &rpc,
            wallet.public(),
            recipient.public(),
            mint,
            9_000_000_000
        )
        .await,
        Err(SolanaError::InsufficientFunds(_))
    ));
    let bogus_mint = Pubkey(signing_key(12).verifying_key().to_bytes());
    assert!(matches!(
        prepare_spl_transfer(&rpc, wallet.public(), recipient.public(), bogus_mint, 1).await,
        Err(SolanaError::UnsupportedToken(_))
    ));
    // The wallet's own address is not a mint.
    assert!(
        prepare_spl_transfer(
            &rpc,
            wallet.public(),
            recipient.public(),
            wallet.public(),
            1
        )
        .await
        .is_err()
    );

    // A signed transaction whose blockhash is replaced no longer verifies.
    let prepared = prepare_native_transfer(&rpc, wallet.public(), recipient.public(), 1_000_000)
        .await
        .unwrap();
    let signed = wallet.sign_transfer(&prepared).unwrap();
    let mut tampered = Transaction::parse(&signed.raw).unwrap();
    tampered.message.recent_blockhash[0] ^= 1;
    assert!(tampered.verify_signatures().is_err());
    assert!(rpc.send_transaction(&tampered.serialize()).await.is_err());
    assert!(!prepared.is_expired(&rpc).await.unwrap());
}
