#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowallet_chain_evm::{Address, Bytes, EvmTxType, TxKind, UnsignedEvmTransaction};

fuzz_target!(|data: &[u8]| {
    let mut sig = [0u8; 65];
    for (i, b) in data.iter().take(65).enumerate() { sig[i] = *b; }
    let input = Bytes::copy_from_slice(&data[data.len().min(65)..]);
    for tx_type in [EvmTxType::Eip1559, EvmTxType::Legacy] {
        let tx = UnsignedEvmTransaction {
            chain_id: 1,
            nonce: u64::from_le_bytes([data.first().copied().unwrap_or(0); 8]),
            to: if data.len() % 2 == 0 { TxKind::Create } else { TxKind::Call(Address::from([0x11; 20])) },
            value: data.len().into(),
            input: input.clone(),
            gas_limit: 21_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            gas_price: Some(20_000_000_000),
            tx_type,
        };
        let _ = tx.signing_payload();
        let _ = tx.signature_hash();
        let _ = tx.finalize(&sig);
    }
});
