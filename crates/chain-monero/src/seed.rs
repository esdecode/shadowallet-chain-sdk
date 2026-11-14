//! Monero legacy 25-word ("electrum style") seed: 32 bytes -> 24 words (3 words per 4 bytes, base 1626) + 1
//! checksum word (CRC-32 of the first three letters of each word, modulo 24). Compatible with the official Monero
//! wallets and independently cross-checked against python-monero (`tests/monero_seed_vectors.txt`).
//!
//! The word list is the Monero project's English list (BSD-3-Clause, see `english.LICENSE.txt`).

use std::sync::LazyLock;

use zeroize::Zeroizing;

use crate::MoneroError;

const WORDS_TEXT: &str = include_str!("english.txt");
const N: u64 = 1626;
const PREFIX_LEN: usize = 3;

static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| WORDS_TEXT.lines().collect());

fn word_index(word: &str) -> Option<u64> {
    let w = word.to_ascii_lowercase();
    // a full word, or its unique three-letter prefix (as Monero wallets accept)
    let hit = WORDS.iter().position(|c| *c == w).or_else(|| {
        if w.len() == PREFIX_LEN {
            WORDS.iter().position(|c| c.starts_with(&w))
        } else {
            None
        }
    })?;
    Some(hit as u64)
}

fn checksum_index(words: &[&str]) -> usize {
    let mut prefixes = String::new();
    for w in words {
        prefixes.push_str(&w[..PREFIX_LEN.min(w.len())]);
    }
    (crc32fast::hash(prefixes.as_bytes()) as usize) % words.len()
}

/// The 25 words for a 32-byte seed (the spend key before reduction).
pub fn seed_to_words(seed: &[u8; 32]) -> Zeroizing<String> {
    let mut out: Vec<&str> = Vec::with_capacity(25);
    for chunk in seed.chunks(4) {
        let w = u64::from(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        let w1 = w % N;
        let w2 = ((w / N) + w1) % N;
        let w3 = (((w / N) / N) + w2) % N;
        out.push(WORDS[w1 as usize]);
        out.push(WORDS[w2 as usize]);
        out.push(WORDS[w3 as usize]);
    }
    let idx = checksum_index(&out);
    let check = out[idx];
    out.push(check);
    Zeroizing::new(out.join(" "))
}

/// A fresh random Monero seed: 32 OS-random bytes reduced modulo the group order (so the words encode exactly
/// the spend key, as official wallets generate them), returned as 25 words.
pub fn generate_seed_words() -> Result<Zeroizing<String>, MoneroError> {
    let mut raw = Zeroizing::new([0u8; 64]);
    getrandom_fill(raw.as_mut())?;
    let reduced =
        Zeroizing::new(curve25519_dalek::Scalar::from_bytes_mod_order_wide(&raw).to_bytes());
    Ok(seed_to_words(&reduced))
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), MoneroError> {
    use rand_core::RngCore as _;
    rand_core::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| MoneroError::Derivation)
}

/// Decode and verify a 25-word seed. Errors never echo the words.
pub fn words_to_seed(phrase: &str) -> Result<Zeroizing<[u8; 32]>, MoneroError> {
    let raw: Vec<&str> = phrase.split_whitespace().collect();
    if raw.len() != 25 {
        return Err(MoneroError::Address(format!(
            "a Monero seed has 25 words, got {}",
            raw.len()
        )));
    }
    let mut indexes = Vec::with_capacity(25);
    for w in &raw {
        indexes.push(word_index(w).ok_or_else(|| {
            MoneroError::Address("a word is not in the Monero word list".to_owned())
        })?);
    }
    // canonical (full-word) form for the checksum
    let canon: Vec<&str> = indexes.iter().map(|i| WORDS[*i as usize]).collect();
    let (body, check) = canon.split_at(24);
    if body[checksum_index(body)] != check[0] {
        return Err(MoneroError::Address(
            "the Monero seed checksum is wrong: check the words".to_owned(),
        ));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    for (i, group) in indexes[..24].chunks(3).enumerate() {
        let (w1, w2, w3) = (group[0], group[1], group[2]);
        let w = w1 + N * ((N - w1 + w2) % N) + N * N * ((N - w2 + w3) % N);
        let w = u32::try_from(w)
            .map_err(|_| MoneroError::Address("the words do not form a valid seed".to_owned()))?;
        seed[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_list_is_complete_and_prefix_unique() {
        assert_eq!(WORDS.len(), 1626);
        let mut prefixes: Vec<&str> = WORDS.iter().map(|w| &w[..PREFIX_LEN]).collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 1626);
    }

    #[test]
    fn roundtrips_random_seeds_and_rejects_bad_input() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..200 {
            let mut seed = [0u8; 32];
            for b in seed.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (state >> 56) as u8;
            }
            let words = seed_to_words(&seed);
            assert_eq!(words.split_whitespace().count(), 25);
            assert_eq!(*words_to_seed(&words).unwrap(), seed);
        }
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let good = seed_to_words(&seed);
        // replacing any single word by another valid word is detected by the checksum (all but a 1-in-24 collision)
        let parts: Vec<&str> = good.split(' ').collect();
        let mut caught = 0;
        for i in 0..24 {
            let mut p = parts.clone();
            p[i] = if p[i] == "abbey" { "abducts" } else { "abbey" };
            if words_to_seed(&p.join(" ")).is_err() {
                caught += 1;
            }
        }
        assert!(
            caught >= 21,
            "checksum caught only {caught} of 24 single-word changes"
        );
        assert!(words_to_seed("abbey abbey").is_err());
        assert!(words_to_seed(&format!("{} abbey", good.as_str())).is_err());
        assert!(words_to_seed(&good.replace(good.split(' ').next().unwrap(), "zzzzzz")).is_err());
        // three-letter prefixes and capitals are accepted
        let short: Vec<String> = good
            .split(' ')
            .map(|w| w[..3].to_ascii_uppercase())
            .collect();
        assert_eq!(*words_to_seed(&short.join(" ")).unwrap(), seed);
    }

    #[test]
    fn generated_seeds_are_valid_unique_and_canonical() {
        let a = generate_seed_words().unwrap();
        let b = generate_seed_words().unwrap();
        assert_ne!(a.as_str(), b.as_str());
        let seed = words_to_seed(&a).unwrap();
        // canonical: already reduced, so restoring and exporting returns the very same words
        let acct = crate::MoneroAccount::from_monero_seed(crate::Network::Stagenet, &a).unwrap();
        assert_eq!(acct.monero_seed_words().as_str(), a.as_str());
        assert_eq!(hex::encode(*seed), *acct.spend_key_hex());
    }

    #[test]
    fn matches_the_independent_python_monero_vectors() {
        let vectors = include_str!("../tests/monero_seed_vectors.txt");
        let mut n = 0;
        for line in vectors.lines() {
            let f: Vec<&str> = line.split(" | ").collect();
            let seed_hex = hex::decode(f[0]).unwrap();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_hex);
            assert_eq!(seed_to_words(&seed).as_str(), f[1], "words for {}", f[0]);
            assert_eq!(hex::encode(*words_to_seed(f[1]).unwrap()), f[0]);
            n += 1;
        }
        assert_eq!(n, 15);
    }
}
