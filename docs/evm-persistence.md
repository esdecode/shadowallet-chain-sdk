# EVM Persistence

SQLite WAL, 5-second busy timeout, `PRAGMA user_version = 1`, integrity check.
Tables: accounts, nonces, transactions, tokens, sync checkpoints.

Only public data is stored. Seeds, private keys, vault keys and signing handles
never enter the database.

Transactions transition through `reserved -> signed -> pending -> confirmed`
or `reverted/failed/broadcast_unknown`. Raw signed bytes are public chain data.
`assert_scope` rejects a database bound to a different account on the same
chain; callers must reject a different chain before opening.
