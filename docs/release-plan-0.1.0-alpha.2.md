# Release Plan — shadowallet-chain-evm 0.1.0-alpha.2

NOT EXECUTED. Requires separate owner authorization.

## Candidate

- Commit: `fb1e387` (or later docs commit on `master`)
- Tag: `v0.1.0-alpha.2-evm` (do not move `v0.1.0-alpha.1`)
- Crate: `shadowallet-chain-evm = 0.1.0-alpha.2`
- Existing crates remain at `0.1.0-alpha.1`; EVM is publishing alone.

## Preconditions

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. `cargo doc --workspace --no-deps`
5. `cargo audit` (raw, no ignores)
6. `cargo deny check`
7. Anvil native/ERC-20/BSC legacy E2E
8. `cargo package -p shadowallet-chain-evm`
9. `cargo publish -p shadowallet-chain-evm --dry-run`
10. Owner approval

## Publication order

Only one new crate: `shadowallet-chain-evm 0.1.0-alpha.2`.
It depends on no Shadowallet crates. No ordering dependency on the existing six.

1. Confirm `cargo search shadowallet-chain-evm` has no `0.1.0-alpha.2`.
2. Publish `shadowallet-chain-evm`.
3. Poll `https://crates.io/api/v1/crates/shadowallet-chain-evm/0.1.0-alpha.2` for HTTP 200.
4. Verify docs.rs build.
5. Create GitHub prerelease from the tag.

## Propagation / rollback

Crates.io versions are immutable. If publication is defective, yank the version
and publish `0.1.0-alpha.3`; never overwrite. Consumers must pin exact versions.

## Consumer migration

After publication, Shadowallet changes:

```toml
shadowallet-chain-evm = "=0.1.0-alpha.2"
```

and removes the local `path` dependency. Until then the path dependency stays.
