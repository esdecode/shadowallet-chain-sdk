use blake2::digest::consts::U5;
use blake2::{Blake2b, Digest};

use crate::NanoError;

const ALPHABET: &[u8; 32] = b"13456789abcdefghijkmnopqrstuwxyz";

fn checksum(public: &[u8; 32]) -> [u8; 5] {
    let mut h = Blake2b::<U5>::new();
    h.update(public);
    let mut out: [u8; 5] = h.finalize().into();
    out.reverse();
    out
}

fn bits_to_chars(bits: &[u8]) -> String {
    bits.chunks(5)
        .map(|c| {
            let mut v = 0usize;
            for b in c {
                v = (v << 1) | usize::from(*b);
            }
            char::from(ALPHABET[v])
        })
        .collect()
}

fn byte_bits(bytes: &[u8], out: &mut Vec<u8>) {
    for b in bytes {
        for i in (0..8).rev() {
            out.push((b >> i) & 1);
        }
    }
}

/// `nano_` + 52 key characters (260 bits: 4 zero bits then the key) + 8 checksum characters.
pub fn encode_address(public: &[u8; 32]) -> String {
    let mut bits = vec![0u8; 4];
    byte_bits(public, &mut bits);
    let mut cs = Vec::new();
    byte_bits(&checksum(public), &mut cs);
    format!("nano_{}{}", bits_to_chars(&bits), bits_to_chars(&cs))
}

/// Accepts `nano_` and the legacy `xrb_` prefix and verifies the checksum.
pub fn decode_address(text: &str) -> Result<[u8; 32], NanoError> {
    let bad = |why: &str| NanoError::Address(why.to_string());
    let body = text
        .strip_prefix("nano_")
        .or_else(|| text.strip_prefix("xrb_"))
        .ok_or_else(|| bad("missing nano_ prefix"))?;
    if body.len() != 60 || !body.is_ascii() {
        return Err(bad("wrong length"));
    }
    let mut bits = Vec::with_capacity(300);
    for ch in body.bytes() {
        let v = ALPHABET
            .iter()
            .position(|a| *a == ch)
            .ok_or_else(|| bad("invalid character"))?;
        for i in (0..5).rev() {
            bits.push(u8::try_from((v >> i) & 1).unwrap_or(0));
        }
    }
    if bits[..4].iter().any(|b| *b != 0) {
        return Err(bad("non-canonical padding"));
    }
    let mut bytes = [0u8; 37];
    for (i, chunk) in bits[4..].chunks(8).enumerate() {
        let mut v = 0u8;
        for b in chunk {
            v = (v << 1) | b;
        }
        bytes[i] = v;
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&bytes[..32]);
    if bytes[32..37] != checksum(&public) {
        return Err(bad("checksum mismatch"));
    }
    Ok(public)
}
