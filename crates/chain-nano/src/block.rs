use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde_json::{Value, json};

use crate::NanoError;
use crate::address::encode_address;
use crate::keys::{public_key, sign_hash, verify_hash};

/// What a state block does. Nano encodes the same five-field structure for all of them; the kind is a node-side hint
/// (`subtype`) derived from the balance change and the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    Open,
    Receive,
    Send,
    Change,
}

impl BlockKind {
    pub fn subtype(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Receive => "receive",
            Self::Send => "send",
            Self::Change => "change",
        }
    }
}

/// Nano state block (block type 6): account, previous, representative, balance and link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateBlock {
    pub account: [u8; 32],
    pub previous: [u8; 32],
    pub representative: [u8; 32],
    pub balance: u128,
    /// Destination account key for a send, source block hash for a receive/open, zero for a change.
    pub link: [u8; 32],
}

impl StateBlock {
    /// Blake2b-256 of the 32-byte state preamble (ends in 06), account, previous, representative, balance (BE) and link.
    pub fn hash(&self) -> [u8; 32] {
        let mut preamble = [0u8; 32];
        preamble[31] = 6;
        let mut h = Blake2b::<U32>::new();
        h.update(preamble);
        h.update(self.account);
        h.update(self.previous);
        h.update(self.representative);
        h.update(self.balance.to_be_bytes());
        h.update(self.link);
        h.finalize().into()
    }

    /// The value proof of work is computed over: the previous hash, or the account key for the first block.
    pub fn work_root(&self) -> [u8; 32] {
        if self.previous == [0u8; 32] {
            self.account
        } else {
            self.previous
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignedBlock {
    pub block: StateBlock,
    pub signature: [u8; 64],
    pub work: Option<u64>,
}

impl SignedBlock {
    /// Sign with the account's own private key; a key that does not belong to `block.account` is refused.
    pub fn sign(block: StateBlock, private: &[u8; 32]) -> Result<Self, NanoError> {
        if public_key(private) != block.account {
            return Err(NanoError::Block(
                "signing key does not belong to the block account".into(),
            ));
        }
        let signature = sign_hash(private, &block.hash());
        let signed = Self {
            block,
            signature,
            work: None,
        };
        signed.verify()?;
        Ok(signed)
    }

    pub fn verify(&self) -> Result<(), NanoError> {
        verify_hash(&self.block.account, &self.block.hash(), &self.signature)
    }

    /// JSON as accepted by the node `process` RPC (`json_block: true`).
    pub fn to_json(&self) -> Value {
        let b = &self.block;
        json!({
            "type": "state",
            "account": encode_address(&b.account),
            "previous": hex::encode_upper(b.previous),
            "representative": encode_address(&b.representative),
            "balance": b.balance.to_string(),
            "link": hex::encode_upper(b.link),
            "link_as_account": encode_address(&b.link),
            "signature": hex::encode_upper(self.signature),
            "work": self.work.map(|w| format!("{w:016x}")).unwrap_or_default(),
        })
    }
}
