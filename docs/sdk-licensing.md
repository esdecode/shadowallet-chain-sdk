# Licensing and Provenance

- Original Shadowallet code is offered under **MIT OR Apache-2.0**.
- Extracted code was written for Shadowallet; no third-party source was copied
  into the SDK crates in this alpha.
- Direct dependencies:

| Crate | License | Use |
|---|---|---|
| `litecoin 0.32.8-rc.1` | CC0-1.0 | Litecoin primitives |
| `bitcoin-dogecoin 0.32.7-doge.0` | Apache-2.0 OR CC0-1.0 | Dogecoin primitives |
| `serde` | MIT OR Apache-2.0 | serialization |
| `thiserror` | MIT OR Apache-2.0 | errors |
| `sha2` | MIT OR Apache-2.0 | (reserved; digest use) |
| `hex` | MIT OR Apache-2.0 | hex encoding |
| `getrandom` | MIT OR Apache-2.0 | proposal IDs (future) |

- Transitive licenses should be generated with `cargo metadata`/`cargo-deny`
  before publication. This has **not** been executed in this alpha.
- Unresolved restriction: `litecoin` is a pre-release rust-bitcoin fork
  (CC0-1.0); its maintenance status must be tracked before a stable release.
- No upstream NOTICE files were identified for direct dependencies at this
  stage; re-verify before publishing.
