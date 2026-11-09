# EVM Network Profiles

| Profile | Chain ID | Native | EIP-1559 | Confirmations |
|---|---:|---|---|---:|
| Ethereum | 1 | ETH/18 | yes | 12 |
| Sepolia | 11155111 | ETH/18 | yes | 6 |
| Polygon | 137 | POL/18 | yes | 64 |
| BNB Smart Chain | 56 | BNB/18 | no (legacy path not yet implemented) | 15 |
| Arbitrum One | 42161 | ETH/18 | yes (L1 data fee not modelled) | 1 |
| OP Mainnet | 10 | ETH/18 | yes (L1 data fee not modelled) | 1 |
| Base | 8453 | ETH/18 | yes (L1 data fee not modelled) | 1 |
| Anvil | 31337 | ETH/18 | yes | 1 |

No RPC URL is embedded or fabricated. Callers provide an endpoint; the SDK
validates `eth_chainId` before use. BSC legacy transaction support is not yet
implemented, so BSC is not advertised as supported for signing.

## Phase 5.2 read-only validation (2026-11-09)

Validated against public RPC endpoints without sending transactions:

| Network | chain_id | block height | base fee | status |
|---|---:|---|---|---|
| Sepolia | 11155111 | >0 | >0 | read-only |
| Polygon | 137 | >0 | >0 | read-only |
| BNB Smart Chain | 56 | >0 | legacy gasPrice | read-only |
| Arbitrum One | 42161 | >0 | >0 | read-only, L1 fee not modelled |
| OP Mainnet | 10 | >0 | >0 | read-only, L1 fee not modelled |
| Base | 8453 | >0 | >0 | read-only, L1 fee not modelled |

No Sepolia transfer was attempted: no disposable funded account or authorized
RPC credential is configured. Mainnet/public signing remains disabled.
