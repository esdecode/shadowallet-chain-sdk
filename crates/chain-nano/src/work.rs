use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use blake2::digest::consts::U8;
use blake2::{Blake2b, Digest};

use crate::NanoError;

/// Proof-of-work value: Blake2b-64(work as little-endian u64 || root), read as a little-endian u64.
pub fn work_value(work: u64, root: &[u8; 32]) -> u64 {
    let mut h = Blake2b::<U8>::new();
    h.update(work.to_le_bytes());
    h.update(root);
    let out: [u8; 8] = h.finalize().into();
    u64::from_le_bytes(out)
}

/// A work threshold as published by the node (`active_difficulty`) or fixed by the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Difficulty(pub u64);

impl Difficulty {
    pub fn from_hex(text: &str) -> Result<Self, NanoError> {
        u64::from_str_radix(text.trim(), 16)
            .map(Self)
            .map_err(|_| NanoError::Rpc(format!("bad difficulty {text:?}")))
    }

    pub fn is_met(self, work: u64, root: &[u8; 32]) -> bool {
        work_value(work, root) >= self.0
    }
}

/// CPU proof of work on `threads` threads. `root` is the previous block hash, or the account key for an open block.
/// Fails closed after `max_attempts` per thread so a wrong threshold cannot spin forever.
pub fn generate_work(
    root: &[u8; 32],
    difficulty: Difficulty,
    threads: usize,
    max_attempts: u64,
) -> Result<u64, NanoError> {
    let threads = threads.clamp(1, 32);
    let found = AtomicBool::new(false);
    let result = AtomicU64::new(0);
    let mut seed = [0u8; 8];
    getrandom::getrandom(&mut seed).map_err(|e| NanoError::Block(format!("no randomness: {e}")))?;
    let base = u64::from_le_bytes(seed);
    std::thread::scope(|scope| {
        for t in 0..threads {
            let (found, result) = (&found, &result);
            scope.spawn(move || {
                let mut nonce = base.wrapping_add((t as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                for _ in 0..max_attempts {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }
                    if work_value(nonce, root) >= difficulty.0 {
                        result.store(nonce, Ordering::SeqCst);
                        found.store(true, Ordering::SeqCst);
                        return;
                    }
                    nonce = nonce.wrapping_add(1);
                }
            });
        }
    });
    if found.load(Ordering::SeqCst) {
        Ok(result.load(Ordering::SeqCst))
    } else {
        Err(NanoError::Block(
            "proof of work not found within the attempt limit".into(),
        ))
    }
}
