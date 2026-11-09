# EVM Fuzzing and Property Tests

## Property tests

`tests/properties.rs` uses proptest 1.x with 64 cases per property.

```bash
PROPTEST_SEED=0000000000000000 cargo test -p shadowallet-chain-evm --test properties
```

Saved regressions live in `tests/properties.proptest-regressions`.

## Fuzzing

Requires nightly and cargo-fuzz:

```bash
cargo install cargo-fuzz --locked
cd crates/chain-evm
cargo +nightly fuzz run fuzz_finalize -- -runs=20000 -max_total_time=60
cargo +nightly fuzz run fuzz_abi_string -- -runs=20000 -max_total_time=60
cargo +nightly fuzz run fuzz_checksum -- -runs=20000 -max_total_time=60
```

Targets assert no panic on arbitrary signatures, calldata, ABI strings or
addresses. They do not claim exhaustive coverage.
