# Compatibility patch: SQLCipher in place of plain SQLite

Source: crates.io `libsqlite3-sys 0.39.1` (MIT). Version number kept at 0.39.1 so `rusqlite 0.41` and the
patched `rusqlite 0.37` (see `../rusqlite/SHADOWALLET-PATCH.md`) accept it.

Changes, all in the build configuration (no SQLite or SQLCipher source is modified):

* `bundled` now builds **SQLCipher 4.20.0 on SQLite 3.54.1** from `sqlcipher-src =420.0.0` (upstream 0.39.1 pins
  `=419.0.6`, which bundles SQLite 3.53.4 and is affected by RUSTSEC-2026-0459; 3.54.x contains the fix).
  The bundled plain `sqlite3/` amalgamation was removed from this copy; it is not used.
* The crypto provider is SQLCipher's own **LibTomCrypt** provider (`-DSQLCIPHER_CRYPTO_LIBTOMCRYPT=1`), compiled from
  the sources shipped in `sqlcipher-src`, instead of an external OpenSSL. This is what makes one identical build work
  for Windows, Linux and Android (arm64-v8a, x86_64) without cross-compiling OpenSSL.
  `shadowallet_ltc.h` is the single LibTomCrypt configuration (AES-256-CBC, SHA-1/256/512, HMAC, PBKDF2, OS random
  bytes via `/dev/urandom` or `CryptGenRandom`). `shadowallet_ltc_shim.c` makes LibTomCrypt's clock-jitter random
  fallback abort, so a failed OS entropy source can never silently produce weak keys or IVs.
* No cryptography is implemented here: the cipher, KDF, MAC and page format are SQLCipher's.

Not independently audited. The packaging of `sqlcipher-src` is third party; its sources are pinned by version and the
`Cargo.lock` checksum. Remove this patch when upstream `libsqlite3-sys` bundles SQLCipher on a fixed SQLite without
OpenSSL. Never suppress RUSTSEC-2026-0459.
