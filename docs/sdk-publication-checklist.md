# Publication Checklist

Local-only preparation. Nothing has been pushed or published.

## Repository

- [x] Standalone workspace
- [x] MIT + Apache-2.0 files
- [x] README, SECURITY, CONTRIBUTING, CHANGELOG
- [x] CI workflow draft
- [ ] Independent Git remote (not created by instruction)
- [ ] Repository topics/description finalized

## Crates.io

- [ ] Verify crate-name availability (`shadowallet-chain-*`)
- [ ] `cargo package` / `cargo publish --dry-run` for each crate
- [ ] Verify crates.io metadata (repository, docs, keywords, categories)
- [ ] Ensure path dependencies are published/versioned
- [ ] MSRV validated on the declared toolchain
- [ ] Windows/macOS/Linux build matrix green
- [ ] `cargo audit` + `cargo deny` clean or documented

## Security

- [ ] Independent review of signing/finalization boundary
- [ ] Verify no secret material in repo or history
- [ ] Confirm no mainnet examples
- [ ] Confirm no placeholder chain crate

## Blocking functional gaps

- [ ] Watch-only RPC sync + persistence extracted
- [ ] Network E2E for SDK crates
- [ ] Shadowallet application migrated to SDK
- [ ] Bitcoin compatibility bridge decided
