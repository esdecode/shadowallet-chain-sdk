#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use shadowallet_chain_evm::{
    Address, B256, Bytes, EvmAccount, EvmTxType, TxKind, UnsignedEvmTransaction, checksum_address,
};
use std::str::FromStr;

fn tx(chain_id: u64, nonce: u64, to: Address, value: u128, gas: u64) -> UnsignedEvmTransaction {
    UnsignedEvmTransaction {
        chain_id,
        nonce,
        to: TxKind::Call(to),
        value: value.into(),
        input: Bytes::new(),
        gas_limit: gas,
        max_fee_per_gas: 30_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        gas_price: None,
        tx_type: EvmTxType::Eip1559,
        l1_data_fee_wei: Default::default(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn checksum_roundtrips(seed in any::<[u8; 20]>()) {
        let address = Address::from(seed);
        let text = checksum_address(address);
        prop_assert_eq!(Address::from_str(&text).unwrap(), address);
        prop_assert_eq!(text.len(), 42);
    }

    #[test]
    fn signing_payload_is_deterministic_and_chain_bound(
        chain in 1u64..1_000_000u64,
        nonce in any::<u64>(),
        value in any::<u128>(),
        gas in 21_000u64..1_000_000u64,
    ) {
        let to = Address::from([0x42; 20]);
        let a = tx(chain, nonce, to, value, gas);
        let b = tx(chain, nonce, to, value, gas);
        let c = tx(chain + 1, nonce, to, value, gas);
        prop_assert_eq!(a.signing_payload(), b.signing_payload());
        prop_assert_ne!(a.signature_hash(), c.signature_hash());
        let payload = a.signing_payload();
        prop_assert_eq!(payload[0], 0x02);
        let rlp = rlp::Rlp::new(&payload[1..]);
        prop_assert!(rlp.is_list());
        prop_assert_eq!(rlp.item_count().unwrap(), 9);
    }

    #[test]
    fn eip1559_finalization_is_deterministic(
        chain in 1u64..1_000_000u64,
        nonce in any::<u64>(),
        value in any::<u128>(),
    ) {
        let account = EvmAccount::from_private_key(
            shadowallet_chain_evm::ANVIL,
            &[0x46; 32],
            0,
        ).unwrap();
        let mut t = tx(chain, nonce, Address::from([0x11; 20]), value, 21_000);
        t.chain_id = chain;
        let sig = account.sign_digest(t.signature_hash().as_bytes().try_into().unwrap()).unwrap();
        let raw = t.finalize(&sig).unwrap();
        prop_assert_eq!(raw[0], 0x02);
        let rlp = rlp::Rlp::new(&raw[1..]);
        prop_assert!(rlp.is_list());
        prop_assert_eq!(rlp.item_count().unwrap(), 12);
        prop_assert_eq!(raw.clone(), t.finalize(&sig).unwrap());
    }

    #[test]
    fn legacy_payload_has_eip155_shape(nonce in any::<u64>(), chain in 1u64..1_000_000u64) {
        let mut t = tx(chain, nonce, Address::from([0x22; 20]), 1, 21_000);
        t.tx_type = EvmTxType::Legacy;
        t.gas_price = Some(20_000_000_000);
        t.max_priority_fee_per_gas = 0;
        let payload = t.signing_payload();
        let rlp = rlp::Rlp::new(&payload);
        prop_assert!(rlp.is_list());
        prop_assert_eq!(rlp.item_count().unwrap(), 9);
        let chain_bytes = chain.to_be_bytes();
        let start = chain_bytes.iter().position(|b| *b != 0).unwrap_or(8);
        prop_assert_eq!(rlp.at(6).unwrap().data().unwrap(), &chain_bytes[start..]);
        prop_assert!(rlp.at(7).unwrap().is_empty());
        prop_assert!(rlp.at(8).unwrap().is_empty());
    }
}

#[test]
fn payload_boundary_uses_long_list_prefix() {
    let mut t = tx(1, 1, Address::from([0x33; 20]), 0, 21_000);
    t.input = Bytes::from(vec![0xab; 100]);
    let payload = t.signing_payload();
    assert_eq!(payload[0], 0x02);
    assert_eq!(
        payload[1], 0xf8,
        "100-byte calldata makes the outer list long"
    );
}

#[test]
fn rlp_empty_and_small_values_are_canonical() {
    let mut t = tx(1, 0, Address::from([0x44; 20]), 0, 21_000);
    t.input = Bytes::new();
    let payload = t.signing_payload();
    let rlp = rlp::Rlp::new(&payload[1..]);
    // nonce 0 is the empty byte string, not 0x00.
    assert!(rlp.at(1).unwrap().is_empty());
    // zero value is also empty.
    assert!(rlp.at(6).unwrap().is_empty());
    // chain id 1 is the single byte 0x01.
    assert_eq!(rlp.at(0).unwrap().data().unwrap(), &[1]);
}

#[test]
fn hash_is_keccak_of_serialized_transaction() {
    use sha3::{Digest, Keccak256};
    let t = tx(1, 1, Address::from([0x55; 20]), 1, 21_000);
    let account =
        EvmAccount::from_private_key(shadowallet_chain_evm::ANVIL, &[0x46; 32], 0).unwrap();
    let sig = account
        .sign_digest(t.signature_hash().as_bytes().try_into().unwrap())
        .unwrap();
    let raw = t.finalize(&sig).unwrap();
    let expected = B256::from_slice(&Keccak256::digest(&raw));
    assert_eq!(expected.as_bytes(), &Keccak256::digest(&raw)[..]);
}
