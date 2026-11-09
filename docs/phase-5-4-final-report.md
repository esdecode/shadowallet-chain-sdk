# Phase 5.4 Final Report

## Protocol verification

- Independent `eth_account` EIP-155 and EIP-1559 raw bytes: exact match.
- BIP39 mnemonic → BIP44 address vector: match.
- Low-S enforcement and signer recovery: pass.
- EIP-55 checksum and ERC-20 calldata/string vs `eth_abi`: match.
- RLP shape: empty bytes, zero integers, chain-id minimal encoding, 100-byte
  calldata long-list prefix, 9/12-item lists.
- High-S signatures rejected.

## Property and fuzz

- proptest: 7 properties × 64 cases, saved regression seed.
- cargo-fuzz/libFuzzer:
  - finalize: 20,000 runs, no crash.
  - ABI string: 20,000 runs, no crash.
  - checksum: 20,000 runs, no crash.

## Dependency / audit

- Alloy absent; 313–326 package lock depending on phase.
- `cargo audit`: clean.
- `cargo deny check`: advisories/bans/licenses/sources pass.
- `crypto-bigint 0.7.11` only.

## Platform

- Flutter 3.47.9 analyze/tests pass.
- Android SDK/NDK/JDK installed; debug APK builds.
- Android Rust `.so` build: blocked by OpenSSL cross-compilation
  (`clang-18: no input files` from the NDK/OpenSSL build). APK does not contain
  `libwallet_ffi.so`; Android runtime NOT VERIFIED.
- iOS/macOS: not run; no macOS host/CI execution.

## UTXO

BTC, BCH, DOGE, LTC and shared-vault FFI regtest: pass.

## Decision

Decision: **NOT READY FOR EXPERIMENTAL SDK RELEASE**.

Protocol, dependency-audit, vector, property, fuzz and package gates pass. The
blocking release criteria are cross-platform verification (iOS/macOS cannot be
compiled without Apple SDK/Xcode; Android app FFI is incomplete), plus no
independent audit and no L2 data-fee model. No publication.
