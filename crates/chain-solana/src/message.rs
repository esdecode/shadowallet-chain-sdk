//! Legacy Solana transaction message encoding.
//!
//! Only the legacy (v0-less) message format is produced or accepted. Parsing is
//! strict: versioned messages, non-canonical lengths and trailing bytes are
//! rejected so the bytes that get signed are exactly the bytes that were
//! inspected.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::SolanaError;
use crate::pubkey::Pubkey;

const MAX_ACCOUNTS: usize = 64;
const MAX_INSTRUCTIONS: usize = 16;
const MAX_DATA: usize = 1_232;
/// Maximum serialized transaction size accepted by the network.
pub const PACKET_LIMIT: usize = 1_232;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn new(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }

    pub fn readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

pub(crate) fn write_compact_u16(out: &mut Vec<u8>, value: u16) {
    let mut rem = value;
    loop {
        let mut byte = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem == 0 {
            out.push(byte);
            break;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

fn read_compact_u16(input: &[u8], pos: &mut usize) -> Result<u16, SolanaError> {
    let mut value: u32 = 0;
    for i in 0..3 {
        let byte = *input
            .get(*pos)
            .ok_or_else(|| SolanaError::InvalidTransaction("truncated length".into()))?;
        *pos += 1;
        value |= u32::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            // Canonical form: no trailing zero continuation groups.
            if i > 0 && byte == 0 {
                return Err(SolanaError::InvalidTransaction(
                    "non-canonical length".into(),
                ));
            }
            return u16::try_from(value)
                .map_err(|_| SolanaError::InvalidTransaction("length overflow".into()));
        }
    }
    Err(SolanaError::InvalidTransaction("length overflow".into()))
}

fn take<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], SolanaError> {
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| SolanaError::InvalidTransaction("truncated message".into()))?;
    let slice = &input[*pos..end];
    *pos = end;
    Ok(slice)
}

impl Message {
    /// Compile instructions into a legacy message with `payer` as fee payer.
    /// Account ordering is deterministic: signer-writable, signer-readonly,
    /// writable, readonly, each in order of first appearance, payer first.
    pub fn new(
        payer: &Pubkey,
        instructions: &[Instruction],
        recent_blockhash: [u8; 32],
    ) -> Result<Self, SolanaError> {
        let mut metas: Vec<AccountMeta> = vec![AccountMeta::new(*payer, true)];
        let upsert = |metas: &mut Vec<AccountMeta>, key: &Pubkey, signer: bool, writable: bool| {
            if let Some(existing) = metas.iter_mut().find(|m| &m.pubkey == key) {
                existing.is_signer |= signer;
                existing.is_writable |= writable;
            } else {
                metas.push(AccountMeta {
                    pubkey: *key,
                    is_signer: signer,
                    is_writable: writable,
                });
            }
        };
        for ix in instructions {
            for meta in &ix.accounts {
                upsert(&mut metas, &meta.pubkey, meta.is_signer, meta.is_writable);
            }
        }
        for ix in instructions {
            upsert(&mut metas, &ix.program_id, false, false);
        }
        let rank = |m: &AccountMeta| match (m.is_signer, m.is_writable) {
            (true, true) => 0u8,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        };
        let mut indexed: Vec<(usize, AccountMeta)> = metas.into_iter().enumerate().collect();
        indexed.sort_by_key(|(i, m)| (rank(m), *i));
        let metas: Vec<AccountMeta> = indexed.into_iter().map(|(_, m)| m).collect();
        if metas.len() > MAX_ACCOUNTS || instructions.len() > MAX_INSTRUCTIONS {
            return Err(SolanaError::InvalidTransaction("message too large".into()));
        }
        if metas[0].pubkey != *payer {
            return Err(SolanaError::InvalidTransaction(
                "fee payer must be the first signer".into(),
            ));
        }
        let signers = metas.iter().filter(|m| m.is_signer).count();
        let readonly_signed = metas
            .iter()
            .filter(|m| m.is_signer && !m.is_writable)
            .count();
        let readonly_unsigned = metas
            .iter()
            .filter(|m| !m.is_signer && !m.is_writable)
            .count();
        let index_of = |key: &Pubkey| -> Result<u8, SolanaError> {
            metas
                .iter()
                .position(|m| &m.pubkey == key)
                .and_then(|i| u8::try_from(i).ok())
                .ok_or_else(|| SolanaError::InvalidTransaction("unknown account".into()))
        };
        let mut compiled = Vec::with_capacity(instructions.len());
        for ix in instructions {
            if ix.data.len() > MAX_DATA {
                return Err(SolanaError::InvalidTransaction(
                    "instruction too large".into(),
                ));
            }
            compiled.push(CompiledInstruction {
                program_id_index: index_of(&ix.program_id)?,
                accounts: ix
                    .accounts
                    .iter()
                    .map(|a| index_of(&a.pubkey))
                    .collect::<Result<_, _>>()?,
                data: ix.data.clone(),
            });
        }
        let message = Self {
            num_required_signatures: u8::try_from(signers)
                .map_err(|_| SolanaError::InvalidTransaction("too many signers".into()))?,
            num_readonly_signed: u8::try_from(readonly_signed)
                .map_err(|_| SolanaError::InvalidTransaction("too many signers".into()))?,
            num_readonly_unsigned: u8::try_from(readonly_unsigned)
                .map_err(|_| SolanaError::InvalidTransaction("too many accounts".into()))?,
            account_keys: metas.iter().map(|m| m.pubkey).collect(),
            recent_blockhash,
            instructions: compiled,
        };
        if message.serialize().len() + 1 + 64 * usize::from(message.num_required_signatures)
            > PACKET_LIMIT
        {
            return Err(SolanaError::InvalidTransaction(
                "transaction exceeds packet size".into(),
            ));
        }
        Ok(message)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![
            self.num_required_signatures,
            self.num_readonly_signed,
            self.num_readonly_unsigned,
        ];
        write_compact_u16(&mut out, self.account_keys.len() as u16);
        for key in &self.account_keys {
            out.extend_from_slice(&key.0);
        }
        out.extend_from_slice(&self.recent_blockhash);
        write_compact_u16(&mut out, self.instructions.len() as u16);
        for ix in &self.instructions {
            out.push(ix.program_id_index);
            write_compact_u16(&mut out, ix.accounts.len() as u16);
            out.extend_from_slice(&ix.accounts);
            write_compact_u16(&mut out, ix.data.len() as u16);
            out.extend_from_slice(&ix.data);
        }
        out
    }

    /// Strict parser for legacy messages.
    pub fn parse(bytes: &[u8]) -> Result<Self, SolanaError> {
        let mut pos = 0usize;
        let header = take(bytes, &mut pos, 3)?;
        if header[0] & 0x80 != 0 {
            return Err(SolanaError::InvalidTransaction(
                "versioned messages are not supported".into(),
            ));
        }
        let (required, ro_signed, ro_unsigned) = (header[0], header[1], header[2]);
        let key_count = usize::from(read_compact_u16(bytes, &mut pos)?);
        if key_count > MAX_ACCOUNTS {
            return Err(SolanaError::InvalidTransaction("too many accounts".into()));
        }
        let mut account_keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            let raw = take(bytes, &mut pos, 32)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(raw);
            account_keys.push(Pubkey(key));
        }
        let mut recent_blockhash = [0u8; 32];
        recent_blockhash.copy_from_slice(take(bytes, &mut pos, 32)?);
        let ix_count = usize::from(read_compact_u16(bytes, &mut pos)?);
        if ix_count > MAX_INSTRUCTIONS {
            return Err(SolanaError::InvalidTransaction(
                "too many instructions".into(),
            ));
        }
        let mut instructions = Vec::with_capacity(ix_count);
        for _ in 0..ix_count {
            let program_id_index = take(bytes, &mut pos, 1)?[0];
            let n_accounts = usize::from(read_compact_u16(bytes, &mut pos)?);
            let accounts = take(bytes, &mut pos, n_accounts)?.to_vec();
            let n_data = usize::from(read_compact_u16(bytes, &mut pos)?);
            if n_data > MAX_DATA {
                return Err(SolanaError::InvalidTransaction(
                    "instruction too large".into(),
                ));
            }
            let data = take(bytes, &mut pos, n_data)?.to_vec();
            instructions.push(CompiledInstruction {
                program_id_index,
                accounts,
                data,
            });
        }
        if pos != bytes.len() {
            return Err(SolanaError::InvalidTransaction("trailing bytes".into()));
        }
        if usize::from(required) > key_count
            || usize::from(ro_signed) > usize::from(required)
            || usize::from(required) + usize::from(ro_unsigned) > key_count
            || required == 0
        {
            return Err(SolanaError::InvalidTransaction("invalid header".into()));
        }
        for ix in &instructions {
            if usize::from(ix.program_id_index) >= key_count
                || ix.accounts.iter().any(|i| usize::from(*i) >= key_count)
            {
                return Err(SolanaError::InvalidTransaction(
                    "account index out of range".into(),
                ));
            }
            // The fee payer slot and signer slots can never be program ids.
            if ix.program_id_index < required {
                return Err(SolanaError::InvalidTransaction(
                    "program id must not be a signer".into(),
                ));
            }
        }
        Ok(Self {
            num_required_signatures: required,
            num_readonly_signed: ro_signed,
            num_readonly_unsigned: ro_unsigned,
            account_keys,
            recent_blockhash,
            instructions,
        })
    }

    pub fn is_signer(&self, index: usize) -> bool {
        index < usize::from(self.num_required_signatures)
    }

    pub fn is_writable(&self, index: usize) -> bool {
        let n = self.account_keys.len();
        let required = usize::from(self.num_required_signatures);
        if index < required {
            index < required - usize::from(self.num_readonly_signed)
        } else {
            index < n - usize::from(self.num_readonly_unsigned)
        }
    }

    pub fn fee_payer(&self) -> Option<&Pubkey> {
        self.account_keys.first()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub signatures: Vec<[u8; 64]>,
    pub message: Message,
}

impl Transaction {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_compact_u16(&mut out, self.signatures.len() as u16);
        for sig in &self.signatures {
            out.extend_from_slice(sig);
        }
        out.extend_from_slice(&self.message.serialize());
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, SolanaError> {
        let mut pos = 0usize;
        let count = usize::from(read_compact_u16(bytes, &mut pos)?);
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(take(bytes, &mut pos, 64)?);
            signatures.push(sig);
        }
        let message = Message::parse(&bytes[pos..])?;
        if signatures.len() != usize::from(message.num_required_signatures) {
            return Err(SolanaError::InvalidTransaction(
                "signature count does not match header".into(),
            ));
        }
        Ok(Self {
            signatures,
            message,
        })
    }

    /// Verify every signature against the corresponding signer key.
    pub fn verify_signatures(&self) -> Result<(), SolanaError> {
        let bytes = self.message.serialize();
        for (index, sig) in self.signatures.iter().enumerate() {
            let key = self
                .message
                .account_keys
                .get(index)
                .ok_or_else(|| SolanaError::InvalidTransaction("missing signer".into()))?;
            let verifying = VerifyingKey::from_bytes(&key.0)
                .map_err(|_| SolanaError::InvalidTransaction("invalid signer key".into()))?;
            verifying
                .verify_strict(&bytes, &Signature::from_bytes(sig))
                .map_err(|_| SolanaError::InvalidTransaction("bad signature".into()))?;
        }
        Ok(())
    }

    /// The transaction id: the first signature, base58.
    pub fn id(&self) -> Option<String> {
        self.signatures
            .first()
            .map(|s| bs58::encode(s).into_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::pubkey::SYSTEM_PROGRAM;

    #[test]
    fn compact_u16_known_vectors() {
        for (value, encoded) in [
            (0u16, vec![0x00]),
            (0x7f, vec![0x7f]),
            (0x80, vec![0x80, 0x01]),
            (0x3fff, vec![0xff, 0x7f]),
            (0x4000, vec![0x80, 0x80, 0x01]),
            (u16::MAX, vec![0xff, 0xff, 0x03]),
        ] {
            let mut out = Vec::new();
            write_compact_u16(&mut out, value);
            assert_eq!(out, encoded);
            let mut pos = 0;
            assert_eq!(read_compact_u16(&encoded, &mut pos).unwrap(), value);
            assert_eq!(pos, encoded.len());
        }
        // Non-canonical and overflowing encodings are rejected.
        let mut pos = 0;
        assert!(read_compact_u16(&[0x80, 0x00], &mut pos).is_err());
        let mut pos = 0;
        assert!(read_compact_u16(&[0xff, 0xff, 0x04], &mut pos).is_err());
    }

    fn sample() -> Message {
        let payer = Pubkey([1; 32]);
        let dest = Pubkey([2; 32]);
        let ix = Instruction {
            program_id: SYSTEM_PROGRAM,
            accounts: vec![AccountMeta::new(payer, true), AccountMeta::new(dest, false)],
            data: vec![2, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0],
        };
        Message::new(&payer, &[ix], [7; 32]).unwrap()
    }

    #[test]
    fn message_round_trip_and_layout() {
        let message = sample();
        assert_eq!(message.num_required_signatures, 1);
        assert_eq!(message.num_readonly_signed, 0);
        assert_eq!(message.num_readonly_unsigned, 1);
        assert_eq!(message.account_keys[0], Pubkey([1; 32]));
        assert_eq!(message.account_keys[2], SYSTEM_PROGRAM);
        let bytes = message.serialize();
        assert_eq!(Message::parse(&bytes).unwrap(), message);
        // 3 header + 1 + 96 keys + 32 blockhash + 1 + (1 + 1 + 2 + 1 + 12)
        assert_eq!(bytes.len(), 3 + 1 + 96 + 32 + 1 + 17);
    }

    #[test]
    fn parser_rejects_malformed_messages() {
        let bytes = sample().serialize();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Message::parse(&trailing).is_err());
        assert!(Message::parse(&bytes[..bytes.len() - 1]).is_err());
        let mut versioned = bytes.clone();
        versioned[0] |= 0x80;
        assert!(Message::parse(&versioned).is_err());
        assert!(Message::parse(&[]).is_err());
    }

    #[test]
    fn transaction_round_trip() {
        let tx = Transaction {
            signatures: vec![[9; 64]],
            message: sample(),
        };
        assert_eq!(Transaction::parse(&tx.serialize()).unwrap(), tx);
        let mut bad = tx.serialize();
        bad[0] = 2; // wrong signature count
        assert!(Transaction::parse(&bad).is_err());
    }
}
