# ERC-20

Canonical identity: `(chain_id, contract_address)`. Symbols are display data,
never identity.

Supported: `balanceOf`, `decimals`, `symbol`, `name`, `transfer`; metadata
cache; bytes32 symbol/name fallback; receipt validation that the expected
`Transfer` log exists with matching contract, sender, recipient and amount.

Not supported: approvals, allowances, arbitrary calls, blind signing, batch
transfers. Malformed ABI responses and reverted transfers fail closed.
