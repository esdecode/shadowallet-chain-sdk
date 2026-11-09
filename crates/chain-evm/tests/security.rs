#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shadowallet_chain_evm::{ANVIL, EvmError, FeeQuote, UnsignedEvmTransaction};
use shadowallet_chain_evm::{Address, Bytes, TxKind, U256};

fn base() -> UnsignedEvmTransaction {
    UnsignedEvmTransaction {
        chain_id: ANVIL.chain_id,
        nonce: 7,
        to: TxKind::Call(Address::from([0x11; 20])),
        value: U256::from(1_000u64),
        input: Bytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 1_000_000,
        gas_price: None,
        tx_type: shadowallet_chain_evm::EvmTxType::Eip1559,
    }
}

#[test]
fn every_committed_field_changes_the_signing_digest() {
    let reference = base().signature_hash();
    let mut variants = Vec::new();

    let mut tx = base();
    tx.chain_id = 1;
    variants.push(tx);
    let mut tx = base();
    tx.nonce += 1;
    variants.push(tx);
    let mut tx = base();
    tx.to = TxKind::Call(Address::from([0x12; 20]));
    variants.push(tx);
    let mut tx = base();
    tx.value += U256::from(1u64);
    variants.push(tx);
    let mut tx = base();
    tx.input = Bytes::from_static(&[0x01]);
    variants.push(tx);
    let mut tx = base();
    tx.gas_limit += 1;
    variants.push(tx);
    let mut tx = base();
    tx.max_fee_per_gas += 1;
    variants.push(tx);
    let mut tx = base();
    tx.max_priority_fee_per_gas += 1;
    variants.push(tx);

    for variant in variants {
        assert_ne!(reference, variant.signature_hash());
    }
}

#[test]
fn malformed_signature_is_rejected() {
    let tx = base();
    assert!(matches!(
        tx.finalize(&[0u8; 64]),
        Err(EvmError::Transaction(_))
    ));
    assert!(matches!(
        tx.finalize(&[0u8; 66]),
        Err(EvmError::Transaction(_))
    ));
}

#[test]
fn fee_total_overflow_is_rejected() {
    let quote = FeeQuote {
        base_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 1,
        gas_limit: 21_000,
        max_gas_cost_wei: U256::max_value(),
        l1_data_fee_wei: None,
        total_confident: true,
    };
    assert_eq!(
        quote.max_total_cost(U256::from(1u64)),
        Err(EvmError::FeeRejected)
    );
}

#[test]
fn receipt_binding_rejects_wrong_contract_recipient_amount_or_status() {
    use shadowallet_chain_evm::B256;
    use shadowallet_chain_evm::{Erc20Token, RpcLog, TransactionReceipt};

    let token = Address::from([0xaa; 20]);
    let from = Address::from([0x11; 20]);
    let to = Address::from([0x22; 20]);
    let amount = U256::from(1_000u64);
    let mut from_topic = [0u8; 32];
    from_topic[12..].copy_from_slice(from.as_bytes());
    let mut to_topic = [0u8; 32];
    to_topic[12..].copy_from_slice(to.as_bytes());
    let log = RpcLog {
        address: token,
        topics: vec![
            shadowallet_chain_evm::transfer_topic(),
            B256::from(from_topic),
            B256::from(to_topic),
        ],
        data: Bytes::from(amount.to_big_endian().to_vec()),
        block_number: Some(1),
        transaction_hash: Some(B256::zero()),
        log_index: Some(0),
    };
    let token = Erc20Token {
        chain_id: ANVIL.chain_id,
        contract: token,
    };
    let receipt = TransactionReceipt {
        transaction_hash: B256::zero(),
        status: true,
        block_number: Some(1),
        contract_address: None,
        logs: vec![log.clone()],
    };
    assert!(token.validate_transfer_receipt(&receipt, from, to, amount));
    assert!(!token.validate_transfer_receipt(&receipt, from, to, amount + U256::from(1u64)));
    assert!(!token.validate_transfer_receipt(&receipt, to, from, amount));
    let mut bad_contract = receipt.clone();
    bad_contract.logs[0].address = Address::from([0xbb; 20]);
    assert!(!token.validate_transfer_receipt(&bad_contract, from, to, amount));
    let mut reverted = receipt;
    reverted.status = false;
    assert!(!token.validate_transfer_receipt(&reverted, from, to, amount));
}

#[test]
fn matches_independent_legacy_eip155_vector() {
    use shadowallet_chain_evm::{ETHEREUM, EvmAccount, EvmTxType, UnsignedEvmTransaction};

    let key = [0x46u8; 32];
    let account = EvmAccount::from_private_key(ETHEREUM, &key, 0).unwrap();
    let tx = UnsignedEvmTransaction {
        chain_id: 1,
        nonce: 9,
        to: TxKind::Call(Address::from([0x35; 20])),
        value: U256::from(1_000_000_000_000_000_000u64),
        input: Bytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 20_000_000_000,
        max_priority_fee_per_gas: 0,
        gas_price: Some(20_000_000_000),
        tx_type: EvmTxType::Legacy,
    };
    let signature = account
        .sign_digest(tx.signature_hash().as_bytes().try_into().unwrap())
        .unwrap();
    let raw = hex::encode(tx.finalize(&signature).unwrap());
    assert_eq!(
        raw,
        "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
    );
}

#[test]
fn matches_independent_eip1559_vector() {
    use shadowallet_chain_evm::{ETHEREUM, EvmAccount, EvmTxType, UnsignedEvmTransaction};

    let key = [0x46u8; 32];
    let account = EvmAccount::from_private_key(ETHEREUM, &key, 0).unwrap();
    let tx = UnsignedEvmTransaction {
        chain_id: 1,
        nonce: 1,
        to: TxKind::Call(Address::from([0x35; 20])),
        value: U256::from(1_000_000_000_000_000_000u64),
        input: Bytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 30_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        gas_price: None,
        tx_type: EvmTxType::Eip1559,
    };
    let signature = account
        .sign_digest(tx.signature_hash().as_bytes().try_into().unwrap())
        .unwrap();
    let raw = hex::encode(tx.finalize(&signature).unwrap());
    assert_eq!(
        raw,
        "02f8730101843b9aca008506fc23ac00825208943535353535353535353535353535353535353535880de0b6b3a764000080c001a0e9ffdcdc2bf72eee637c2777242f6f09f8bb0be7b46e6790930b3ce5894f2642a00436c9d9e009733e8a13056a8087b7d7117e7d3aa8d80222cb9267b2f594abb9"
    );
}

#[test]
fn bip39_bip44_known_account_vector() {
    use shadowallet_chain_evm::{ANVIL, EvmAccount, checksum_address};

    let mnemonic =
        bip39::Mnemonic::parse("test test test test test test test test test test test junk")
            .unwrap();
    let seed = mnemonic.to_seed("");
    let account = EvmAccount::from_seed(ANVIL, &seed, 0).unwrap();
    assert_eq!(
        checksum_address(account.address).to_lowercase(),
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    );
}

#[test]
fn signatures_are_low_s_and_recover_the_expected_signer() {
    use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::RecoverableSignature};
    use sha3::{Digest, Keccak256};
    use shadowallet_chain_evm::{Address, EvmAccount, checksum_address};

    let key = [0x46u8; 32];
    let account = EvmAccount::from_private_key(ANVIL, &key, 0).unwrap();
    let digest = [0x11u8; 32];
    let signature = account.sign_digest(digest).unwrap();
    assert!(signature[64] <= 1);
    let half_n: [u8; 32] =
        hex::decode("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")
            .unwrap()
            .try_into()
            .unwrap();
    assert!(
        signature[32..64] <= half_n[..],
        "signature must be low-S normalized"
    );

    let recoverable = RecoverableSignature::from_compact(
        &signature[..64],
        i32::from(signature[64]).try_into().unwrap(),
    )
    .unwrap();
    let recovered = Secp256k1::verification_only()
        .recover_ecdsa(Message::from_digest(digest), &recoverable)
        .unwrap();
    let hash = Keccak256::digest(&PublicKey::serialize_uncompressed(&recovered)[1..]);
    let recovered_address = Address::from_slice(&hash[12..]);
    assert_eq!(recovered_address, account.address);
    assert_eq!(checksum_address(recovered_address).len(), 42);
}

#[test]
fn erc20_calldata_and_checksum_match_eth_abi() {
    use shadowallet_chain_evm::{
        Address, U256, checksum_address, decode_erc20_string, erc20_balance_of_calldata,
        erc20_transfer_calldata,
    };

    let to = Address::from([0x35; 20]);
    assert_eq!(
        hex::encode(erc20_transfer_calldata(to, U256::from(123_456_789u64))),
        "a9059cbb000000000000000000000000353535353535353535353535353535353535353500000000000000000000000000000000000000000000000000000000075bcd15"
    );
    assert_eq!(
        hex::encode(erc20_balance_of_calldata(to)),
        "70a082310000000000000000000000003535353535353535353535353535353535353535"
    );
    assert_eq!(
        checksum_address(Address::from([
            0xf3, 0x9f, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xf6, 0xf4, 0xce, 0x6a, 0xb8, 0x82, 0x72,
            0x79, 0xcf, 0xff, 0xb9, 0x22, 0x66,
        ])),
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );
    let encoded = hex::decode(
        "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a5465737420546f6b656e00000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert_eq!(decode_erc20_string(&encoded).unwrap(), "Test Token");
}
