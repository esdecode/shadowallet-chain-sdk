# Publication Checklist

Executed for the 0.1.0-alpha.3 release set (2026-11-10). GitHub Actions stayed disabled; publication and verification used the local Windows toolchain.

## Repository

- [x] Standalone workspace
- [x] MIT + Apache-2.0 files
- [x] README, SECURITY, CONTRIBUTING, CHANGELOG
- [x] CI workflow draft
- [ ] Independent Git remote (not created by instruction)
- [ ] Repository topics/description finalized

## Crates.io

- [x] Verify crate-name availability (`shadowallet-chain-*`)
- [x] `cargo package` / `cargo publish --dry-run` for each crate
- [x] Verify crates.io metadata (repository, docs, keywords, categories)
- [x] Ensure path dependencies are published/versioned
- [x] MSRV validated on the declared toolchain
- [ ] Windows/macOS/Linux build matrix green
- [x] `cargo audit` + `cargo deny` clean or documented

## Security

- [ ] Independent review of signing/finalization boundary
- [ ] Verify no secret material in repo or history
- [ ] Confirm no mainnet examples
- [ ] Confirm no placeholder chain crate

## Blocking functional gaps

- [x] Watch-only RPC sync + persistence extracted
- [x] Network E2E for SDK crates
- [x] Shadowallet application migrated to SDK
- [x] Bitcoin compatibility bridge decided
