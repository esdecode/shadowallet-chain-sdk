# Release Process

1. All workspace tests, clippy, fmt, docs, audit and deny checks pass.
2. Chain E2E suites pass against disposable regtest nodes.
3. Changelog updated; API diff reviewed.
4. Version bumped per SemVer (pre-1.0: breaking changes allowed with minor bump).
5. `cargo package` and `cargo publish --dry-run` succeed for every crate in
   dependency order.
6. Security review for signing-boundary changes.
7. Tag `vX.Y.Z`, publish in dependency order, and create the GitHub prerelease
   only after explicit maintainer approval. GitHub Actions are not used for
   publication or release verification.

Releases are executed from a reviewed local checkout. Record the published
checksums in the release notes.
