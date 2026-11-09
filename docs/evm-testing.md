# EVM Testing

## Anvil

```bash
docker run -d --name uw-anvil -p 8545:8545 --entrypoint anvil \
  ghcr.io/foundry-rs/foundry:stable --host 0.0.0.0 --port 8545

ANVIL_RPC_URL=http://127.0.0.1:8545 \
  cargo test -p shadowallet-chain-evm -- --ignored --nocapture
```

Executed:

- Native transfer: derive account, read balance, prepare unsigned EIP-1559 tx,
  sign digest externally, finalize, broadcast, wait for receipt, verify balance.
- ERC-20: compile/deploy a disposable test token, read decimals/symbol/balance,
  build canonical `transfer` calldata, sign/finalize/broadcast, verify balance.

Additional Phase 5.2 tests:

- BSC legacy EIP-155 transfer on Anvil chain id 56.
- Public read-only RPC validation for Sepolia, Polygon, BSC, Arbitrum, OP, Base.
- Nonce ambiguity, replacement, expiry, corruption, scope and concurrency.
- ERC-20 receipt binding and fee overflow.

No mainnet/testnet funds were used.
