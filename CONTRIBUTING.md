# Contributing

- Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
  and `cargo test --workspace` before opening a change.
- Keep cryptographic primitives in reviewed upstream crates. Do not implement
  curve arithmetic or sighash algorithms from scratch.
- Any new chain crate must include network-scoped address tests, unsigned
  construction tests, and finalization tests proving that modified transactions
  fail signature verification.
- Do not add seed/private-key storage to the SDK. External signing only.
- Preserve dependency licenses; update `docs/sdk-dependency-audit.md`.
- Do not add unsupported placeholder crates.

## Commit style

Imperative, scoped commits, e.g. `feat(litecoin): verify external signatures`.
