# Maintenance Policy

- Pre-1.0: APIs may change; breaking changes require a changelog entry and a
  version bump.
- Cryptographic dependencies: no automatic upgrades. Any upgrade requires full
  unit, signing-vector and regtest E2E regression.
- Security fixes: patch release plus advisory; coordinated disclosure per
  `SECURITY.md`.
- Deprecations: at least one minor release with warnings before removal after
  1.0.
- Chain engines are maintained independently; a stale engine must be marked
  unsupported rather than silently left claiming support.
- No production-readiness claim without external audit and public-network
  evidence.
