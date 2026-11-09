# EVM State, Nonces and History

## Database

`EvmStore` uses SQLite with WAL, a 5-second busy timeout and
`PRAGMA user_version = 1`.

Tables: `evm_account`, `evm_nonce`, `evm_tx`, `evm_token`, `evm_sync`.

Stored: public addresses, balances cache, token metadata, nonce reservations,
public transaction fields, hashes, raw signed transactions (public chain data),
receipts/status and sync checkpoints.

Never stored: seed phrases, private keys, vault master keys or signing handles.

## Nonce lifecycle

`reserve_nonce(chain, address, network_nonce, draft)` runs an
`IMMEDIATE` transaction:

1. rejects unregistered accounts;
2. uses `max(local_next, network_nonce)`;
3. inserts a `reserved` transaction row;
4. increments `next_nonce` atomically.

`mark_signed` / `mark_broadcast` / `mark_receipt` / `mark_failed` advance the
record. `release_nonce` reclaims a nonce only if it is the highest active row
and was never broadcast. `reconcile_nonce` never lowers the local next nonce
below an active reservation.

Restart recovery is tested by reopening the SQLite file with a pending
transaction and reconciling against network nonce 0.

## History

`HistorySource` is the abstraction. `LocalHistory` is paginated by descending
row id and labels itself `OutgoingOnly`. Standard Ethereum JSON-RPC has no
arbitrary-address full history; incoming native transfers require an external
indexer. `erc20_transfers` decodes `Transfer` logs only over an explicit block
range; pruned/reorged logs make results partial.

## Fees

`quote_fees` fetches the latest base fee and provider priority fee, enforces
caps (500 gwei max fee, 10 gwei priority, 1M gas normal / 5M deployment) and
computes the maximum gas cost with checked arithmetic.

`FeeModel::Legacy` (BSC) and `Eip1559WithL1DataFee` (Arbitrum/OP/Base) are
marked unsupported: preparation fails closed rather than under-reporting cost.
