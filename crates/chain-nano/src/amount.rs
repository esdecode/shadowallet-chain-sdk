use crate::NanoError;

/// 1 XNO = 10^30 raw. The maximum supply (133,248,297 XNO) fits in a u128.
pub const RAW_PER_XNO: u128 = 1_000_000_000_000_000_000_000_000_000_000;

/// Parse a decimal XNO string ("1", "0.000001", up to 30 decimals) into raw without any floating point.
pub fn parse_xno(text: &str) -> Result<u128, NanoError> {
    let bad = || NanoError::Amount(format!("{text:?} is not a valid XNO amount"));
    let (whole, frac) = match text.split_once('.') {
        Some((w, f)) => (w, f),
        None => (text, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(bad());
    }
    if !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
        || frac.len() > 30
    {
        return Err(bad());
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| bad())?
    };
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 30 {
        frac_padded.push('0');
    }
    let frac: u128 = frac_padded.parse().map_err(|_| bad())?;
    whole
        .checked_mul(RAW_PER_XNO)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(bad)
}

/// Exact decimal formatting of a raw amount (trailing zeros trimmed).
pub fn format_xno(raw: u128) -> String {
    let whole = raw / RAW_PER_XNO;
    let frac = raw % RAW_PER_XNO;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:030}");
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_exactly() {
        assert_eq!(parse_xno("1").unwrap(), RAW_PER_XNO);
        assert_eq!(parse_xno("0.000001").unwrap(), RAW_PER_XNO / 1_000_000);
        assert_eq!(format_xno(parse_xno("12.3400").unwrap()), "12.34");
        assert_eq!(format_xno(1), "0.000000000000000000000000000001");
        assert_eq!(
            parse_xno("340282366.920938463463374607431768211455").unwrap(),
            u128::MAX
        );
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            ".",
            "-1",
            "1e3",
            "1.2.3",
            "0.0000000000000000000000000000001",
            "340282367",
        ] {
            assert!(parse_xno(bad).is_err(), "{bad}");
        }
    }
}
