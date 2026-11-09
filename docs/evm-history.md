# EVM History

`HistorySource` is provider-neutral. `LocalHistory` returns outgoing wallet
transactions only and labels them `OutgoingOnly`.

Standard JSON-RPC has no complete arbitrary-address history. Incoming native
transfers are absent unless an external indexer is configured. ERC-20 transfers
are decoded from `Transfer` logs over an explicit block range; pruned/reorged
logs make results partial.

Reorg handling: checkpoints can be rewound explicitly; event scans must be
re-run from the rewind point. Replaced transactions retain separate rows with
the same nonce.
