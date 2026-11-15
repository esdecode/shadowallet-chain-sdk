# Monero and Zcash integration checkpoint

Status: incomplete wallet parity. Mainnet signing and broadcast remain disabled.

Monero now persists the issued subaddress high-water mark and watches all issued
addresses plus 200 recovery addresses. Legacy stores start allocation after index
20 to avoid repeating any address the old UI may have displayed. This supports
account 0 subaddresses through index 10000; native Monero major accounts are still
outstanding. Per-block state is atomic, genesis restore starts at block zero,
ambiguous transactions retain input reservations, account/node identity is checked
at signing, and seed-only outgoing history subtracts change and the on-chain fee.

Zcash uses the official librustzcash crates, ZIP-32, Orchard/Sapling/transparent
unified addresses, SQLite wallet state, compact-block scanning and raw transaction
enhancement, ZIP-317 proposals, reference Orchard proving and the official
hash-verified bundled Sapling prover. There are no placeholder proofs. A restore
without a birthday scans from Sapling activation; new-wallet tip birthdays must be
explicit. Connection checks metadata AND the canonical Sapling activation block
hash from https://github.com/zcash/zcash/blob/master/src/chainparams.cpp.
Only the exact canonical TESTNET profile can sign or broadcast.

The Zcash rusqlite 0.37 compatibility patch is documented in
vendor/rusqlite/SHADOWALLET-PATCH.md. It is temporary and requires independent
review, alongside the existing monero-ed25519 crypto-bigint compatibility port.

Validation evidence is preserved in the wallet repository's docs/evidence files:
- SDK workspace unit/integration/doc tests.
- Monero public read-only stagenet tests: 4 passed, including scan/reopen and proxy.
- Zcash public read-only testnet tests: 2 passed, including sync/reopen and identity.
- Affected clippy with warnings denied, cargo audit without ignores, cargo deny.

No funded shielded Zcash or Monero public transaction is claimed here. Wallet FFI,
Android UI, funded receive/spend, reinstall recovery and Android restart tests must
be tracked separately. The reference sync implementation has no progress/cancel
callbacks; long restores still require a mobile job/cancellation design. Remote
servers can correlate IP, timing, full transaction requests and transparent address
queries; this implementation does not claim server-query unlinkability.
