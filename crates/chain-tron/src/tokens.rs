//! TRC-20 asset identity. An asset is `(network, contract address)`, never a symbol. The registry
//! is data, not a single hard-coded token: it can be extended, and anything outside it is a
//! *custom* token that carries a warning and is never presented as verified.

use crate::{TronAddress, TronError};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifiedToken {
    pub network: &'static str,
    pub contract: &'static str,
    pub symbol: &'static str,
    pub name: &'static str,
    pub decimals: u8,
    /// Where the address comes from. Every entry was also checked read-only on chain
    /// (`symbol()`, `name()`, `decimals()` equal the values here).
    pub source: &'static str,
}

pub const REGISTRY: &[VerifiedToken] = &[
    VerifiedToken {
        network: "tron-mainnet",
        contract: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        symbol: "USDT",
        name: "Tether USD",
        decimals: 6,
        source: "Tether supported-protocols (tether.to), TRON deployment",
    },
    VerifiedToken {
        network: "tron-mainnet",
        contract: "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8",
        symbol: "USDC",
        name: "USD Coin",
        decimals: 6,
        source: "Circle USDC on TRON (circle.com multichain USDC)",
    },
    VerifiedToken {
        network: "tron-nile",
        contract: "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
        symbol: "USDT",
        name: "Tether USD",
        decimals: 6,
        source: "Nile testnet USDT test token (TRON developer docs); no monetary value",
    },
];

pub fn verified(network: &str, contract: &TronAddress) -> Option<&'static VerifiedToken> {
    let text = contract.to_base58();
    REGISTRY
        .iter()
        .find(|t| t.network == network && t.contract == text)
}

/// Symbols of verified tokens: a custom token that uses one of them is a look-alike.
pub fn is_verified_symbol(network: &str, symbol: &str) -> bool {
    REGISTRY
        .iter()
        .any(|t| t.network == network && t.symbol.eq_ignore_ascii_case(symbol))
}

/// How a token the user is about to see or send is classified.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TokenTrust {
    Verified,
    /// Not in the registry. `lookalike` is true if its symbol collides with a verified token.
    Custom {
        lookalike: bool,
    },
}

/// Metadata read from the chain for a TRC-20 contract (untrusted until validated).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TokenMeta {
    pub contract: TronAddress,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub trust: TokenTrust,
}

/// Contract-supplied text is attacker-controlled: keep printable ASCII only, bounded, no control or
/// bidirectional characters, never empty.
pub fn sanitize_label(raw: &str, max: usize) -> Result<String, TronError> {
    let trimmed = raw.trim_matches('\0').trim();
    if trimmed.is_empty() || trimmed.len() > max {
        return Err(TronError::Token(
            "token label is empty or too long".to_owned(),
        ));
    }
    if !trimmed.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(TronError::Token(
            "token label contains non-printable or non-ASCII characters".to_owned(),
        ));
    }
    Ok(trimmed.to_owned())
}

/// Decode an ABI `string` return (offset, length, bytes) or the legacy `bytes32` form.
pub fn decode_abi_string(data: &[u8]) -> Result<String, TronError> {
    if data.len() == 32 {
        let end = data.iter().position(|b| *b == 0).unwrap_or(32);
        return String::from_utf8(data[..end].to_vec())
            .map_err(|_| TronError::Token("token string is not UTF-8".to_owned()));
    }
    if data.len() < 64 {
        return Err(TronError::Token(
            "token string answer is too short".to_owned(),
        ));
    }
    let offset = word_usize(&data[..32])?;
    let len_at = offset;
    if len_at.checked_add(32).is_none_or(|e| e > data.len()) {
        return Err(TronError::Token("bad string offset".to_owned()));
    }
    let len = word_usize(&data[len_at..len_at + 32])?;
    let start = len_at + 32;
    if start.checked_add(len).is_none_or(|e| e > data.len()) || len > 256 {
        return Err(TronError::Token("bad string length".to_owned()));
    }
    String::from_utf8(data[start..start + len].to_vec())
        .map_err(|_| TronError::Token("token string is not UTF-8".to_owned()))
}

fn word_usize(word: &[u8]) -> Result<usize, TronError> {
    if word[..24].iter().any(|b| *b != 0) {
        return Err(TronError::Token("word too large".to_owned()));
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&word[24..32]);
    usize::try_from(u64::from_be_bytes(v))
        .map_err(|_| TronError::Token("word too large".to_owned()))
}

/// `decimals()` must be a single word that fits in 0..=36.
pub fn decode_decimals(data: &[u8]) -> Result<u8, TronError> {
    if data.len() != 32 || data[..31].iter().any(|b| *b != 0) || data[31] > 36 {
        return Err(TronError::Token("implausible decimals()".to_owned()));
    }
    Ok(data[31])
}

/// Render a raw integer amount with `decimals` places, exactly (no floating point).
pub fn format_units(raw: &str, decimals: u8) -> String {
    let d = usize::from(decimals);
    if d == 0 {
        return raw.to_owned();
    }
    let padded = format!("{raw:0>width$}", width = d + 1);
    let (int, frac) = padded.split_at(padded.len() - d);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        int.to_owned()
    } else {
        format!("{int}.{frac}")
    }
}

/// Parse a human decimal amount into raw units without rounding; more places than `decimals` is an error.
pub fn parse_units(text: &str, decimals: u8) -> Result<String, TronError> {
    let text = text.trim();
    let (int, frac) = text.split_once('.').unwrap_or((text, ""));
    if int.is_empty() && frac.is_empty()
        || !int.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
        || frac.len() > usize::from(decimals)
    {
        return Err(TronError::Amount);
    }
    let mut raw = format!(
        "{int}{frac}{}",
        "0".repeat(usize::from(decimals) - frac.len())
    );
    let trimmed = raw.trim_start_matches('0');
    raw = if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    };
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_addresses_are_valid_and_unique() {
        for t in REGISTRY {
            assert!(TronAddress::parse(t.contract).is_ok(), "{}", t.contract);
            assert_eq!(
                REGISTRY
                    .iter()
                    .filter(|o| o.network == t.network && o.contract == t.contract)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn lookalike_symbols_are_detected() {
        assert!(is_verified_symbol("tron-mainnet", "usdt"));
        assert!(!is_verified_symbol("tron-mainnet", "DAI"));
    }

    #[test]
    fn labels_reject_hostile_text() {
        assert!(sanitize_label("USDT", 12).is_ok());
        assert!(sanitize_label("U\u{202e}SDT", 12).is_err());
        assert!(sanitize_label("", 12).is_err());
        assert!(sanitize_label("A\nB", 12).is_err());
        assert!(sanitize_label("Ünicode", 12).is_err());
        assert!(sanitize_label("ABCDEFGHIJKLMN", 12).is_err());
    }

    #[test]
    fn abi_strings_and_decimals() {
        let mut w = vec![0u8; 32];
        w[31] = 0x20;
        let mut data = w.clone();
        let mut len = vec![0u8; 32];
        len[31] = 4;
        data.extend(len);
        data.extend(b"USDT");
        data.extend(vec![0u8; 28]);
        assert_eq!(decode_abi_string(&data).unwrap(), "USDT");
        let mut b32 = b"MKR".to_vec();
        b32.resize(32, 0);
        assert_eq!(decode_abi_string(&b32).unwrap(), "MKR");
        let mut hostile = data.clone();
        hostile[63] = 0xff; // length 255 but only 32 data bytes follow
        assert!(decode_abi_string(&hostile).is_err());
        let mut d = vec![0u8; 32];
        d[31] = 6;
        assert_eq!(decode_decimals(&d).unwrap(), 6);
        d[31] = 37;
        assert!(decode_decimals(&d).is_err());
        d[31] = 6;
        d[0] = 1;
        assert!(decode_decimals(&d).is_err());
    }

    #[test]
    fn exact_unit_conversion_for_6_8_9_and_18_decimals() {
        for (raw, dec, shown) in [
            ("1500000", 6u8, "1.5"),
            ("1", 8, "0.00000001"),
            ("1000000000", 9, "1"),
            ("1234567890123456789", 18, "1.234567890123456789"),
            ("0", 6, "0"),
        ] {
            assert_eq!(format_units(raw, dec), shown);
            assert_eq!(parse_units(shown, dec).unwrap(), raw);
        }
        assert!(parse_units("1.0000001", 6).is_err());
        assert!(parse_units("-1", 6).is_err());
        assert!(parse_units("", 6).is_err());
        assert!(parse_units("1e3", 6).is_err());
    }
}
