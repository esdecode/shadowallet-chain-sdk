#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;
use shadowallet_chain_evm::{Address, checksum_address};

fuzz_target!(|data: &[u8]| {
    if data.len() >= 20 {
        let address = Address::from_slice(&data[..20]);
        let text = checksum_address(address);
        let _ = Address::from_str(&text);
    }
});
