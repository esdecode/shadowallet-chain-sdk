# EVM Fees

- EIP-1559: base fee from latest block, priority from
  `eth_maxPriorityFeePerGas` (fallback 1 gwei), `maxFee = 2*base + priority`.
- Caps: 500 gwei max fee, 10 gwei priority, 1M normal gas, 5M deployment.
- Legacy (BSC): `eth_gasPrice`, capped at 500 gwei; EIP-155 chain-id signing.
- Max debit = value + maxFee*gasLimit with checked arithmetic.
- Insufficient native balance fails before signing.
- BSC legacy is implemented and Anvil-validated (chain id 56).
- Arbitrum/OP/Base L1 data fees are not modelled: preparation fails closed and
  those networks remain read-only.
