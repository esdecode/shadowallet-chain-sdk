# EVM Nonce Management

- `EvmStore` reserves nonces in an `IMMEDIATE` SQLite transaction.
- Effective nonce is `max(local_next, network_nonce)`, keyed by `(chain_id, address)`.
- `reserve_replacement` reuses an active nonce without advancing the cursor.
- `release_nonce` reclaims only the highest `reserved` row; never a signed,
  pending, confirmed or `broadcast_unknown` row.
- `mark_broadcast_unknown` records timeout/reset ambiguity. The nonce remains
  reserved; it is never automatically released or expired.
- `expire_stale` only expires `reserved` rows that were never submitted.
- `reconcile_nonce` raises the cursor from network/pending state and never
  lowers it below an active reservation.
- Sync checkpoints support explicit rewind (`set_sync_checkpoint`) and
  forward-only advance (`advance_sync_checkpoint`).
