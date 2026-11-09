# EVM WASM Feasibility

Alloy 1.8 supports WASM-oriented primitives, but this crate currently uses the
HTTP provider (`reqwest`) and native TLS, which are not the intended browser
transport.

For a browser wallet:

- use Alloy's WASM-compatible transport or a JS RPC bridge;
- keep key custody in the browser's secure enclave/WebCrypto plus explicit user
  approval; do not reuse the native vault assumption;
- re-evaluate `aws-lc`/TLS and async runtime size;
- prohibit signing from untrusted web content.

Not implemented in Phase 5. The native security model must not be weakened for
future WASM support.
