# Security Policy

## Status

Pre-release alpha. No independent security audit. Do not use with mainnet
funds.

## Reporting a vulnerability

Do not open a public issue. Send a private report to the maintainers with:

- affected crate/version,
- impact and attack scenario,
- minimal reproduction,
- whether funds or keys can be affected.

You will receive an acknowledgement and a remediation timeline. Please allow
90 days before public disclosure unless an active exploit requires earlier
notice.

## Scope

In scope: address derivation, unsigned transaction construction, fee envelope,
signature request generation, signature verification/finalization, serialization.

Out of scope: the calling wallet's vault, session policy, user authorization,
RPC provider, node software and broadcast policy. Those are explicitly the
application's responsibility.

## Key handling

The SDK never accepts or stores seeds/private keys. Reports that require
exporting keys through the SDK are not applicable to this codebase.
