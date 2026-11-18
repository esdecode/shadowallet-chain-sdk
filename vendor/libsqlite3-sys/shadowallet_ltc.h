/* SHADOWALLET-PATCH: the single LibTomCrypt configuration shared by SQLCipher and every LibTomCrypt unit.
 * Only what SQLCipher's LibTomCrypt provider needs: AES-256-CBC, SHA-1/256/512, HMAC, PBKDF2, OS random bytes.
 * Derived from the configuration of sqlite-wasm-rs, with the OS entropy sources enabled. */
#ifndef SHADOWALLET_LTC_H
#define SHADOWALLET_LTC_H

#define LTC_NOTHING
#define LTC_RIJNDAEL
#define LTC_CBC_MODE
#define LTC_SHA1
#define LTC_SHA256
#define LTC_SHA512
#define LTC_HASH_HELPERS
#define LTC_HMAC
#define LTC_FORTUNA
#define LTC_PKCS_5
#define LTC_RNG_GET_BYTES
#define LTC_PRNG_ENABLE_LTC_RNG
#define LTC_DEVRANDOM
#define LTC_TRY_URANDOM_FIRST
#define LTC_NO_TEST
#define LTC_NO_ASM
#define LTC_NO_MATH
#define LTC_CLEAN_STACK
#define ARGTYPE 4
/* rng_get_bytes falls back to a clock-jitter generator when the OS source fails: fail closed instead. */
#define XCLOCK shadowallet_ltc_no_clock
#define XCLOCKS_PER_SEC 1
long shadowallet_ltc_no_clock(void);

#endif
