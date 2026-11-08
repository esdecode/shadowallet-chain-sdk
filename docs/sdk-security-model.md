# Security Model

## Enforced by the SDK

- No seed/private-key input, storage, logging or export.
- `prepare_transfer` produces transactions with empty witnesses/scriptSig and
  rejects premature signatures.
- `signing_request` exposes only transaction-specific SIGHASH_ALL digests and
  the corresponding public keys.
- `finalize_transfer` recomputes the sighash, verifies each DER signature
  against the SDK-derived public key, then assembles the witness/scriptSig.
- Any modification of outputs, amounts or inputs invalidates the signature.
- Network/xpub mismatches, insufficient funds and fee-envelope violations fail
  closed.
- The fee envelope is a safety guard, not a network policy oracle.

## Enforced by the calling wallet

- User authentication, explicit transaction review/approval and one-time
  authorization bound to the exact proposal.
- Vault locking/session expiry, replay protection, account/network binding.
- Provider trust, confirmation depth and broadcast policy.
- Mainnet enablement. The SDK does not distinguish production readiness.
- Key storage and signing implementation. The signer must only sign approved
  `SignRequest`s.

## Not provided

- Reorg handling, SPV proofs, provider authentication.
- Anti-fee-sniping policy, dust policy beyond the caller's fee envelope.
- Hardware-wallet integration.

## Known limitations

- The SDK cannot prove that a caller's signer enforced authorization; that is
  the application's trust boundary.
- Alpha code, no audit.
