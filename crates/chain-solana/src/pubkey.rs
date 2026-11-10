use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::LazyLock;

use crate::error::SolanaError;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    /// Strict base58 parse: 32..=44 characters decoding to exactly 32 bytes.
    pub fn from_base58(value: &str) -> Result<Self, SolanaError> {
        if !(32..=44).contains(&value.len()) {
            return Err(SolanaError::InvalidAddress);
        }
        let bytes = bs58::decode(value)
            .into_vec()
            .map_err(|_| SolanaError::InvalidAddress)?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| SolanaError::InvalidAddress)?;
        Ok(Self(array))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// True when the key is a valid Ed25519 curve point (i.e. not a PDA).
    pub fn is_on_curve(&self) -> bool {
        CompressedEdwardsY(self.0).decompress().is_some()
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey({})", self.to_base58())
    }
}

pub const TOKEN_PROGRAM_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_STR: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ASSOCIATED_TOKEN_PROGRAM_STR: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// `1111…1111` is 32 zero bytes.
pub const SYSTEM_PROGRAM: Pubkey = Pubkey([0; 32]);

/// Decode a compile-time literal. A failure here is a programming error that
/// the unit tests below would catch, never a runtime input path.
#[allow(clippy::expect_used)]
fn known(literal: &str) -> Pubkey {
    Pubkey::from_base58(literal).expect("well-known program id literal")
}

pub static TOKEN_PROGRAM: LazyLock<Pubkey> = LazyLock::new(|| known(TOKEN_PROGRAM_STR));
pub static TOKEN_2022_PROGRAM: LazyLock<Pubkey> = LazyLock::new(|| known(TOKEN_2022_PROGRAM_STR));
pub static ASSOCIATED_TOKEN_PROGRAM: LazyLock<Pubkey> =
    LazyLock::new(|| known(ASSOCIATED_TOKEN_PROGRAM_STR));

/// Program-derived address search (bump from 255 downwards).
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
    for bump in (0..=255u8).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id.0);
        hasher.update(b"ProgramDerivedAddress");
        let hash: [u8; 32] = hasher.finalize().into();
        let candidate = Pubkey(hash);
        if !candidate.is_on_curve() {
            return Some((candidate, bump));
        }
    }
    None
}

/// Associated token account address for `(owner, token_program, mint)`.
pub fn associated_token_address(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Result<Pubkey, SolanaError> {
    find_program_address(
        &[owner.as_bytes(), token_program.as_bytes(), mint.as_bytes()],
        &ASSOCIATED_TOKEN_PROGRAM,
    )
    .map(|(key, _)| key)
    .ok_or(SolanaError::InvalidAddress)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn well_known_ids_round_trip() {
        for s in [
            "11111111111111111111111111111111",
            TOKEN_PROGRAM_STR,
            TOKEN_2022_PROGRAM_STR,
            ASSOCIATED_TOKEN_PROGRAM_STR,
        ] {
            assert_eq!(Pubkey::from_base58(s).unwrap().to_base58(), s);
        }
        assert_eq!(
            Pubkey::from_base58("11111111111111111111111111111111").unwrap(),
            SYSTEM_PROGRAM
        );
    }

    #[test]
    fn rejects_invalid_addresses() {
        assert!(Pubkey::from_base58("").is_err());
        assert!(Pubkey::from_base58("short").is_err());
        // '0', 'O', 'I', 'l' are not base58 characters.
        assert!(Pubkey::from_base58("0OIl111111111111111111111111111111111111111").is_err());
        // 33 decoded bytes.
        assert!(Pubkey::from_base58(&bs58::encode([7u8; 33]).into_string()).is_err());
    }

    #[test]
    fn pda_is_off_curve_and_program_sensitive() {
        let owner = Pubkey([9; 32]);
        let mint = Pubkey([8; 32]);
        let ata = associated_token_address(&owner, &mint, &TOKEN_PROGRAM).unwrap();
        assert!(!ata.is_on_curve());
        assert_eq!(
            ata,
            associated_token_address(&owner, &mint, &TOKEN_PROGRAM).unwrap()
        );
        assert_ne!(
            ata,
            associated_token_address(&owner, &mint, &TOKEN_2022_PROGRAM).unwrap()
        );
    }
}
