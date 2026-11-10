#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Test-network provisioning helper (never for mainnet).
//!
//! Funds an owner with SOL, creates a disposable 6-decimals SPL mint, creates
//! the owner's associated token account and mints tokens to it. Prints
//! `MINT=<address>`.
//!
//!   SOLANA_RPC_URL=http://127.0.0.1:8899 OWNER=<address> \
//!     cargo run -p shadowallet-chain-solana --example provision_spl

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use shadowallet_chain_solana::message::Transaction;
use shadowallet_chain_solana::{
    ASSOCIATED_TOKEN_PROGRAM, AccountMeta, Instruction, Message, Pubkey, SYSTEM_PROGRAM,
    SolanaNetwork, SolanaRpc, TOKEN_PROGRAM, associated_token_address,
};

async fn confirm(rpc: &SolanaRpc, signature: &str) {
    for _ in 0..80 {
        if let Some(s) = rpc
            .get_signature_statuses(&[signature.to_owned()])
            .await
            .unwrap()[0]
            .clone()
        {
            assert!(!s.failed, "failed: {:?}", s.error);
            if matches!(
                s.confirmation_status.as_deref(),
                Some("confirmed" | "finalized")
            ) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    panic!("not confirmed: {signature}");
}

async fn send(rpc: &SolanaRpc, payer: &SigningKey, extra: &[&SigningKey], ixs: Vec<Instruction>) {
    let payer_key = Pubkey(payer.verifying_key().to_bytes());
    let (blockhash, _) = rpc.get_latest_blockhash().await.unwrap();
    let message = Message::new(&payer_key, &ixs, blockhash).unwrap();
    let bytes = message.serialize();
    let mut signatures = vec![payer.sign(&bytes).to_bytes()];
    for signer in extra {
        let key = Pubkey(signer.verifying_key().to_bytes());
        let index = message.account_keys.iter().position(|k| *k == key).unwrap();
        while signatures.len() <= index {
            signatures.push([0; 64]);
        }
        signatures[index] = signer.sign(&bytes).to_bytes();
    }
    let tx = Transaction {
        signatures,
        message,
    };
    let sig = rpc.send_transaction(&tx.serialize()).await.unwrap();
    confirm(rpc, &sig).await;
}

fn random_key(tag: u8) -> SigningKey {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut secret = [tag; 32];
    secret[..16].copy_from_slice(&nanos.to_le_bytes());
    SigningKey::from_bytes(&secret)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let url = std::env::var("SOLANA_RPC_URL").expect("SOLANA_RPC_URL");
    let owner = Pubkey::from_base58(&std::env::var("OWNER").expect("OWNER")).unwrap();
    let rpc = SolanaRpc::http(&url, SolanaNetwork::Localnet).unwrap();
    rpc.verify_network().await.unwrap();

    let sig = rpc.request_airdrop(&owner, 5_000_000_000).await.unwrap();
    confirm(&rpc, &sig).await;

    let payer = random_key(0xA1);
    let payer_key = Pubkey(payer.verifying_key().to_bytes());
    let sig = rpc
        .request_airdrop(&payer_key, 2_000_000_000)
        .await
        .unwrap();
    confirm(&rpc, &sig).await;

    let mint_kp = random_key(0xB2);
    let mint = Pubkey(mint_kp.verifying_key().to_bytes());
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(82)
        .await
        .unwrap();
    let mut create = 0u32.to_le_bytes().to_vec();
    create.extend_from_slice(&rent.to_le_bytes());
    create.extend_from_slice(&82u64.to_le_bytes());
    create.extend_from_slice(&TOKEN_PROGRAM.0);
    let mut init = vec![20u8, 6];
    init.extend_from_slice(&payer_key.0);
    init.push(0);
    send(
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
                data: create,
            },
            Instruction {
                program_id: *TOKEN_PROGRAM,
                accounts: vec![AccountMeta::new(mint, false)],
                data: init,
            },
        ],
    )
    .await;

    let ata = associated_token_address(&owner, &mint, &TOKEN_PROGRAM).unwrap();
    let mut mint_to = vec![7u8];
    mint_to.extend_from_slice(&1_000_000_000u64.to_le_bytes());
    send(
        &rpc,
        &payer,
        &[],
        vec![
            Instruction {
                program_id: *ASSOCIATED_TOKEN_PROGRAM,
                accounts: vec![
                    AccountMeta::new(payer_key, true),
                    AccountMeta::new(ata, false),
                    AccountMeta::readonly(owner, false),
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
                    AccountMeta::new(ata, false),
                    AccountMeta::readonly(payer_key, true),
                ],
                data: mint_to,
            },
        ],
    )
    .await;
    println!("MINT={mint}");
}
