//! TRON addresses: `0x41 || keccak256(uncompressed pubkey)[12..]`, shown as Base58Check.

use sha2::{Digest, Sha256};

use crate::TronError;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The one-byte TRON mainnet/testnet address prefix (all public networks share it).
pub const ADDRESS_PREFIX: u8 = 0x41;

/// A 21-byte TRON address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TronAddress(pub [u8; 21]);

fn checksum(payload: &[u8]) -> [u8; 4] {
    let d = Sha256::digest(Sha256::digest(payload));
    [d[0], d[1], d[2], d[3]]
}

impl TronAddress {
    pub fn from_evm_bytes(raw20: &[u8; 20]) -> Self {
        let mut out = [0u8; 21];
        out[0] = ADDRESS_PREFIX;
        out[1..].copy_from_slice(raw20);
        Self(out)
    }

    /// The 20-byte EVM-style body (used in ABI calldata).
    pub fn body(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        out.copy_from_slice(&self.0[1..]);
        out
    }

    /// Base58Check text.
    pub fn to_base58(&self) -> String {
        let mut data = self.0.to_vec();
        data.extend_from_slice(&checksum(&self.0));
        let zeros = data.iter().take_while(|b| **b == 0).count();
        let mut digits: Vec<u8> = Vec::new();
        for byte in &data {
            let mut carry = u32::from(*byte);
            for d in digits.iter_mut() {
                carry += u32::from(*d) << 8;
                *d = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        let mut s = String::new();
        s.extend(std::iter::repeat_n('1', zeros));
        for d in digits.iter().rev() {
            s.push(ALPHABET[usize::from(*d)] as char);
        }
        s
    }

    /// Strict parse: Base58Check, 25 bytes, prefix 0x41, valid checksum. Hex (41...) is also accepted
    /// because node APIs return it, but only with the exact 42-digit shape.
    pub fn parse(text: &str) -> Result<Self, TronError> {
        let text = text.trim();
        if text.len() == 42 && text.starts_with("41") {
            let raw = hex::decode(text).map_err(|_| TronError::Address)?;
            let mut out = [0u8; 21];
            out.copy_from_slice(&raw);
            return Ok(Self(out));
        }
        if text.len() < 26 || text.len() > 36 {
            return Err(TronError::Address);
        }
        let mut bytes: Vec<u8> = Vec::new();
        for ch in text.bytes() {
            let Some(value) = ALPHABET.iter().position(|a| *a == ch) else {
                return Err(TronError::Address);
            };
            let mut carry = value as u32;
            for b in bytes.iter_mut() {
                carry += u32::from(*b) * 58;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let zeros = text.bytes().take_while(|b| *b == b'1').count();
        bytes.extend(std::iter::repeat_n(0u8, zeros));
        bytes.reverse();
        if bytes.len() != 25 || bytes[0] != ADDRESS_PREFIX {
            return Err(TronError::Address);
        }
        let (payload, check) = bytes.split_at(21);
        if checksum(payload) != check {
            return Err(TronError::Address);
        }
        let mut out = [0u8; 21];
        out.copy_from_slice(payload);
        Ok(Self(out))
    }
}

impl std::fmt::Display for TronAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors_roundtrip() {
        // USDT contract: hex form from the TRON docs example <-> Base58Check shown by TronScan.
        let a = TronAddress::parse("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").unwrap();
        assert_eq!(a.to_base58(), "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        assert_eq!(
            TronAddress::parse("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap(),
            a
        );
    }

    #[test]
    fn rejects_bad_checksum_prefix_and_garbage() {
        assert!(TronAddress::parse("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u").is_err());
        assert!(TronAddress::parse("").is_err());
        assert!(TronAddress::parse("0x1234").is_err());
        // an Ethereum-style 0x address is not a TRON address
        assert!(TronAddress::parse("0xa614f803b6fd780986a42c78ec9c7f77e6ded13c").is_err());
        // bitcoin address has the wrong version byte
        assert!(TronAddress::parse("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_err());
    }
}
