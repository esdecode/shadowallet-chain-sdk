//! Local construction of TRON transactions. The node is never asked to build a transaction: the
//! `raw_data` protobuf is encoded here so what the user reviews is exactly what gets signed.

use sha2::{Digest, Sha256};

use crate::{TronAddress, TronError};

const TYPE_TRANSFER: u64 = 1;
const TYPE_TRIGGER_SMART: u64 = 31;
const URL_TRANSFER: &str = "type.googleapis.com/protocol.TransferContract";
const URL_TRIGGER: &str = "type.googleapis.com/protocol.TriggerSmartContract";

/// What a transaction does. Anything else is refused.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Action {
    /// Native TRX transfer, amount in sun.
    Trx { to: TronAddress, amount_sun: u64 },
    /// `transfer(address,uint256)` on a TRC-20 contract; `amount` is the raw big-endian 32-byte word.
    Trc20 {
        contract: TronAddress,
        to: TronAddress,
        amount: [u8; 32],
    },
}

/// Fields taken from a recent block so the transaction is valid only briefly and only on this chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockRef {
    pub number: u64,
    pub block_id: [u8; 32],
}

impl BlockRef {
    pub fn ref_block_bytes(&self) -> [u8; 2] {
        [self.block_id[6], self.block_id[7]]
    }
    pub fn ref_block_hash(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out.copy_from_slice(&self.block_id[8..16]);
        out
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnsignedTronTransaction {
    pub owner: TronAddress,
    pub action: Action,
    pub block: BlockRef,
    pub timestamp_ms: u64,
    pub expiration_ms: u64,
    /// Maximum TRX (sun) a contract call may burn for energy; 0 for plain transfers.
    pub fee_limit_sun: u64,
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn key(field: u64, wire: u64, out: &mut Vec<u8>) {
    varint((field << 3) | wire, out);
}

fn bytes_field(field: u64, data: &[u8], out: &mut Vec<u8>) {
    key(field, 2, out);
    varint(data.len() as u64, out);
    out.extend_from_slice(data);
}

fn int_field(field: u64, v: u64, out: &mut Vec<u8>) {
    key(field, 0, out);
    varint(v, out);
}

/// ABI calldata for `transfer(address,uint256)`.
pub fn trc20_transfer_data(to: &TronAddress, amount: &[u8; 32]) -> Vec<u8> {
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&to.body());
    data.extend_from_slice(amount);
    data
}

/// ABI word for a decimal amount.
pub fn amount_word(decimal: &str) -> Result<[u8; 32], TronError> {
    if decimal.is_empty() || !decimal.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TronError::Amount);
    }
    let mut word = [0u8; 32];
    for ch in decimal.bytes() {
        let mut carry = u32::from(ch - b'0');
        for b in word.iter_mut().rev() {
            let v = u32::from(*b) * 10 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err(TronError::Amount);
        }
    }
    Ok(word)
}

/// Decimal text of a 32-byte big-endian word.
pub fn word_to_decimal(word: &[u8; 32]) -> String {
    let mut n = word.to_vec();
    let mut digits = Vec::new();
    while n.iter().any(|b| *b != 0) {
        let mut rem = 0u32;
        for b in n.iter_mut() {
            let v = rem * 256 + u32::from(*b);
            *b = (v / 10) as u8;
            rem = v % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        return "0".to_owned();
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

impl UnsignedTronTransaction {
    /// The protobuf `Transaction.raw_data` bytes (fields in ascending number order, as the node encodes).
    pub fn raw_data(&self) -> Result<Vec<u8>, TronError> {
        if self.expiration_ms <= self.timestamp_ms {
            return Err(TronError::Transaction(
                "expiration must follow the timestamp".to_owned(),
            ));
        }
        let (ty, url, value) = match &self.action {
            Action::Trx { to, amount_sun } => {
                if *amount_sun == 0 || *amount_sun > i64::MAX as u64 {
                    return Err(TronError::Amount);
                }
                if *to == self.owner {
                    return Err(TronError::Transaction(
                        "sending to the own address is refused".to_owned(),
                    ));
                }
                let mut v = Vec::new();
                bytes_field(1, &self.owner.0, &mut v);
                bytes_field(2, &to.0, &mut v);
                int_field(3, *amount_sun, &mut v);
                (TYPE_TRANSFER, URL_TRANSFER, v)
            }
            Action::Trc20 {
                contract,
                to,
                amount,
            } => {
                if amount.iter().all(|b| *b == 0) {
                    return Err(TronError::Amount);
                }
                let mut v = Vec::new();
                bytes_field(1, &self.owner.0, &mut v);
                bytes_field(2, &contract.0, &mut v);
                bytes_field(4, &trc20_transfer_data(to, amount), &mut v);
                (TYPE_TRIGGER_SMART, URL_TRIGGER, v)
            }
        };
        let mut any = Vec::new();
        bytes_field(1, url.as_bytes(), &mut any);
        bytes_field(2, &value, &mut any);
        let mut contract = Vec::new();
        int_field(1, ty, &mut contract);
        bytes_field(2, &any, &mut contract);
        let mut raw = Vec::new();
        bytes_field(1, &self.block.ref_block_bytes(), &mut raw);
        bytes_field(4, &self.block.ref_block_hash(), &mut raw);
        int_field(8, self.expiration_ms, &mut raw);
        bytes_field(11, &contract, &mut raw);
        int_field(14, self.timestamp_ms, &mut raw);
        if self.fee_limit_sun > 0 {
            int_field(18, self.fee_limit_sun, &mut raw);
        }
        Ok(raw)
    }

    /// Transaction id and the digest that is signed: `sha256(raw_data)`.
    pub fn txid(&self) -> Result<[u8; 32], TronError> {
        Ok(Sha256::digest(self.raw_data()?).into())
    }

    /// Full serialized `Transaction{raw_data, signature}` for `/wallet/broadcasthex`.
    pub fn finalize(&self, signature: &[u8; 65]) -> Result<Vec<u8>, TronError> {
        let mut out = Vec::new();
        bytes_field(1, &self.raw_data()?, &mut out);
        bytes_field(2, signature, &mut out);
        Ok(out)
    }

    /// Bandwidth the network charges: serialized size plus the fixed 64-byte result reserve.
    pub fn bandwidth_bytes(&self) -> Result<u64, TronError> {
        Ok(self.finalize(&[0u8; 65])?.len() as u64 + 64)
    }
}

/// What a serialized `raw_data` actually says. Only the two supported contract types are understood;
/// everything else is an error, so the wallet can prove the bytes match the review.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct DecodedTransaction {
    pub contract_type: u64,
    pub owner: Vec<u8>,
    pub to: Vec<u8>,
    pub contract: Vec<u8>,
    pub amount_sun: u64,
    pub call_value: u64,
    pub data: Vec<u8>,
    pub expiration_ms: u64,
    pub timestamp_ms: u64,
    pub fee_limit_sun: u64,
    pub contract_count: u32,
}

pub fn describe_raw_data(raw: &[u8]) -> Result<DecodedTransaction, TronError> {
    let mut r = Reader { buf: raw, pos: 0 };
    let mut out = DecodedTransaction::default();
    while !r.done() {
        let (field, wire) = r.key()?;
        match (field, wire) {
            (1, 2) | (4, 2) => {
                r.bytes()?;
            }
            (8, 0) => out.expiration_ms = r.varint()?,
            (14, 0) => out.timestamp_ms = r.varint()?,
            (18, 0) => out.fee_limit_sun = r.varint()?,
            (11, 2) => {
                if out.contract_count > 0 {
                    return Err(TronError::Transaction("more than one contract".to_owned()));
                }
                out.contract_count += 1;
                parse_contract(r.bytes()?, &mut out)?;
            }
            _ => {
                return Err(TronError::Transaction(format!("unexpected field {field}")));
            }
        }
    }
    Ok(out)
}

fn parse_contract(buf: &[u8], out: &mut DecodedTransaction) -> Result<(), TronError> {
    let mut r = Reader { buf, pos: 0 };
    while !r.done() {
        let (field, wire) = r.key()?;
        match (field, wire) {
            (1, 0) => out.contract_type = r.varint()?,
            (2, 2) => {
                let any = r.bytes()?;
                let mut a = Reader { buf: any, pos: 0 };
                while !a.done() {
                    let (f, w) = a.key()?;
                    match (f, w) {
                        (1, 2) => {
                            a.bytes()?;
                        }
                        (2, 2) => parse_value(a.bytes()?, out)?,
                        _ => {
                            return Err(TronError::Transaction("unexpected Any field".to_owned()));
                        }
                    }
                }
            }
            _ => {
                return Err(TronError::Transaction(
                    "unexpected contract field".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn parse_value(buf: &[u8], out: &mut DecodedTransaction) -> Result<(), TronError> {
    let mut r = Reader { buf, pos: 0 };
    while !r.done() {
        let (field, wire) = r.key()?;
        match (out.contract_type, field, wire) {
            (_, 1, 2) => out.owner = r.bytes()?.to_vec(),
            (TYPE_TRANSFER, 2, 2) => out.to = r.bytes()?.to_vec(),
            (TYPE_TRANSFER, 3, 0) => out.amount_sun = r.varint()?,
            (TYPE_TRIGGER_SMART, 2, 2) => out.contract = r.bytes()?.to_vec(),
            (TYPE_TRIGGER_SMART, 3, 0) => out.call_value = r.varint()?,
            (TYPE_TRIGGER_SMART, 4, 2) => out.data = r.bytes()?.to_vec(),
            _ => {
                return Err(TronError::Transaction(
                    "unsupported contract field".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn varint(&mut self) -> Result<u64, TronError> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *self
                .buf
                .get(self.pos)
                .ok_or_else(|| TronError::Transaction("truncated".to_owned()))?;
            self.pos += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(TronError::Transaction("varint overflow".to_owned()))
    }
    fn key(&mut self) -> Result<(u64, u64), TronError> {
        let k = self.varint()?;
        Ok((k >> 3, k & 7))
    }
    fn bytes(&mut self) -> Result<&'a [u8], TronError> {
        let len = self.varint()? as usize;
        let end = self
            .pos
            .checked_add(len)
            .filter(|e| *e <= self.buf.len())
            .ok_or_else(|| TronError::Transaction("truncated".to_owned()))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> BlockRef {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&72_707_454u64.to_be_bytes());
        for (i, b) in id.iter_mut().enumerate().skip(8) {
            *b = i as u8;
        }
        BlockRef {
            number: 72_707_454,
            block_id: id,
        }
    }

    fn addr(n: u8) -> TronAddress {
        TronAddress::from_evm_bytes(&[n; 20])
    }

    fn trx() -> UnsignedTronTransaction {
        UnsignedTronTransaction {
            owner: addr(1),
            action: Action::Trx {
                to: addr(2),
                amount_sun: 1_000_000,
            },
            block: block(),
            timestamp_ms: 1_700_000_000_000,
            expiration_ms: 1_700_000_060_000,
            fee_limit_sun: 0,
        }
    }

    #[test]
    fn amount_words_roundtrip_exactly() {
        for s in [
            "1",
            "255",
            "256",
            "1000000",
            "18446744073709551616",
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        ] {
            assert_eq!(word_to_decimal(&amount_word(s).unwrap()), s);
        }
        assert!(
            amount_word(
                "115792089237316195423570985008687907853269984665640564039457584007913129639936"
            )
            .is_err()
        );
        assert!(amount_word("1.5").is_err());
        assert!(amount_word("-1").is_err());
        assert!(amount_word("").is_err());
    }

    #[test]
    fn trx_transfer_decodes_back_to_what_was_reviewed() {
        let raw = trx().raw_data().unwrap();
        let d = describe_raw_data(&raw).unwrap();
        assert_eq!(d.contract_type, 1);
        assert_eq!(d.owner, addr(1).0);
        assert_eq!(d.to, addr(2).0);
        assert_eq!(d.amount_sun, 1_000_000);
        assert_eq!(d.expiration_ms, 1_700_000_060_000);
        assert_eq!(d.fee_limit_sun, 0);
    }

    #[test]
    fn trc20_transfer_has_exact_selector_recipient_and_amount() {
        let tx = UnsignedTronTransaction {
            action: Action::Trc20 {
                contract: addr(9),
                to: addr(2),
                amount: amount_word("1500000").unwrap(),
            },
            fee_limit_sun: 30_000_000,
            ..trx()
        };
        let d = describe_raw_data(&tx.raw_data().unwrap()).unwrap();
        assert_eq!(d.contract_type, 31);
        assert_eq!(d.contract, addr(9).0);
        assert_eq!(&d.data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(&d.data[4..16], &[0u8; 12]);
        assert_eq!(&d.data[16..36], &[2u8; 20]);
        let mut w = [0u8; 32];
        w.copy_from_slice(&d.data[36..68]);
        assert_eq!(word_to_decimal(&w), "1500000");
        assert_eq!(d.fee_limit_sun, 30_000_000);
        assert_eq!(d.call_value, 0);
    }

    #[test]
    fn any_change_changes_the_txid() {
        let base = trx().txid().unwrap();
        let mut other = trx();
        other.action = Action::Trx {
            to: addr(3),
            amount_sun: 1_000_000,
        };
        assert_ne!(base, other.txid().unwrap());
        let mut other = trx();
        other.action = Action::Trx {
            to: addr(2),
            amount_sun: 1_000_001,
        };
        assert_ne!(base, other.txid().unwrap());
        let mut other = trx();
        other.expiration_ms += 1;
        assert_ne!(base, other.txid().unwrap());
    }

    #[test]
    fn refuses_zero_self_and_bad_expiry() {
        let mut t = trx();
        t.action = Action::Trx {
            to: addr(2),
            amount_sun: 0,
        };
        assert!(t.raw_data().is_err());
        let mut t = trx();
        t.action = Action::Trx {
            to: addr(1),
            amount_sun: 5,
        };
        assert!(t.raw_data().is_err());
        let mut t = trx();
        t.expiration_ms = t.timestamp_ms;
        assert!(t.raw_data().is_err());
    }

    #[test]
    fn rejects_duplicated_contracts_when_decoding() {
        let mut raw = trx().raw_data().unwrap();
        raw.extend_from_slice(&[0x5a, 0x00]); // a second (empty) contract entry, field 11
        assert!(describe_raw_data(&raw).is_err());
    }
}
