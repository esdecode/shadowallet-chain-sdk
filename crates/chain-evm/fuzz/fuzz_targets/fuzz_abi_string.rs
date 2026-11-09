#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowallet_chain_evm::decode_erc20_string;

fuzz_target!(|data: &[u8]| {
    let _ = decode_erc20_string(data);
});
