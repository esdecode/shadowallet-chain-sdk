# Dependency Audit

Status: **not yet executed**. `cargo-audit` and `cargo-deny` were not available
in the build container during extraction, and no audit claim is made.

## Direct dependencies

| Crate | Version | License |
|---|---|---|
| litecoin | =0.32.8-rc.1 | CC0-1.0 |
| bitcoin-dogecoin (lib `bitcoin`) | =0.32.7-doge.0 | Apache-2.0 OR CC0-1.0 |
| serde | 1.x | MIT OR Apache-2.0 |
| thiserror | 2.x | MIT OR Apache-2.0 |
| sha2 | 0.10 | MIT OR Apache-2.0 |
| hex | 0.4 | MIT OR Apache-2.0 |
| getrandom | 0.2 | MIT OR Apache-2.0 |

## Required before publication

```bash
cargo audit
cargo deny check licenses advisories bans sources
cargo tree --duplicates
```

- Pin exact versions for cryptographic crates (done for LTC/DOGE).
- Review advisories; never silently ignore.
- Record accepted risks here with owner and date.
- `litecoin 0.32.8-rc.1` is a pre-release: track upstream for a stable release
  and re-run all signing/network tests on upgrade.
