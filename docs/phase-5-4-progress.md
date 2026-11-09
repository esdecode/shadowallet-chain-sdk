# Phase 5.4 Progress

## Protocol / tests
- Independent EIP-155 and EIP-1559 vectors: pass.
- BIP39/BIP44 known address: pass.
- Low-S and recovery verification: pass.
- ERC-20 calldata/checksum/string vectors from eth_abi: pass.
- proptest suite: 7 properties, 64 cases each.
- cargo-fuzz targets: finalize, ABI string, checksum.
  - finalize: 20,000 runs, no crash.
  - ABI string: 20,000 runs, no crash.
  - checksum: 20,000 runs, no crash.
- RLP shape tests: empty, zero, chain id, 100-byte calldata boundary.
- High-S signatures rejected.

## Dependency / security
- Alloy absent; raw cargo audit clean (326 packages).
- cargo deny advisories pass.
- crypto-bigint 0.7.11 only.

## Platform
- Android SDK/NDK/JDK installed in isolated locations.
- Flutter debug APK builds (`app-debug.apk`), but Rust `.so` was initially absent.
- Host Rust Android build initially blocked by a Windows Application Control
  policy; owner disabled it. Linux NDK cross-build then reached OpenSSL, which
  failed (`clang-18: no input files`). Android `.so` not produced.
- iOS/macOS: NOT RUN (no macOS host/CI execution). GitHub Actions macOS runner
  is the recommended path.

## Commits
Recorded at the end of the phase.
