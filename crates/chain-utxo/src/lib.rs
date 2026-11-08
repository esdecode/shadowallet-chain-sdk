//! UTXO models shared by Bitcoin-like chains.
//!
//! No consensus rules live here. Address formats, sighash, serialization, dust
//! policy and fee defaults stay in each chain crate. This crate provides
//! display/aggregation semantics, the fee safety envelope and persistence and
//! coin-selection interfaces.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UtxoBalance {
    pub confirmed_sats: u64,
    pub trusted_pending_sats: u64,
    pub untrusted_pending_sats: u64,
    pub immature_sats: u64,
    pub reserved_sats: u64,
}

impl UtxoBalance {
    pub fn pending_sats(&self) -> u64 {
        self.trusted_pending_sats
            .saturating_add(self.untrusted_pending_sats)
    }

    pub fn spendable_sats(&self) -> u64 {
        self.confirmed_sats.saturating_sub(self.reserved_sats)
    }

    pub fn total_sats(&self) -> u64 {
        self.confirmed_sats
            .saturating_add(self.pending_sats())
            .saturating_add(self.immature_sats)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoHistoryEntry {
    pub txid: String,
    pub received_sats: u64,
    pub sent_sats: u64,
    pub confirmation_height: Option<u64>,
}

impl UtxoHistoryEntry {
    pub fn is_confirmed(&self) -> bool {
        self.confirmation_height.is_some()
    }

    pub fn net_sats(&self) -> i128 {
        self.received_sats as i128 - self.sent_sats as i128
    }
}

/// Public UTXO record. `keychain/index` identify the derivation slot, never a
/// private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub confirmations: u32,
    pub keychain: u32,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub economy_sat_vb: u64,
    pub normal_sat_vb: u64,
    pub priority_sat_vb: u64,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyncState {
    Idle,
    Syncing,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncStatus {
    pub state: Option<SyncState>,
    pub tip_height: u64,
    pub new_transactions: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Esplora,
    Core,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePolicy {
    pub min_sat_vb: u64,
    pub max_sat_vb: u64,
    pub max_fee_sats: u64,
    pub max_fee_percent: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FeePolicyError {
    #[error("fee rate below the chain minimum")]
    RateTooLow,
    #[error("fee rate above the accepted maximum")]
    RateTooHigh,
    #[error("absolute fee above the accepted maximum")]
    FeeTooHigh,
    #[error("fee exceeds the percentage limit for this amount")]
    FeeRatioExceeded,
    #[error("invalid fee policy configuration")]
    InvalidPolicy,
}

impl FeePolicy {
    pub fn validate(&self) -> Result<(), FeePolicyError> {
        if self.min_sat_vb == 0
            || self.max_sat_vb < self.min_sat_vb
            || self.max_sat_vb > 10_000
            || self.max_fee_sats == 0
            || self.max_fee_percent == 0
            || self.max_fee_percent > 100
        {
            return Err(FeePolicyError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn check(
        &self,
        rate_sat_vb: u64,
        fee_sats: u64,
        amount_sats: Option<u64>,
    ) -> Result<(), FeePolicyError> {
        self.validate()?;
        if rate_sat_vb < self.min_sat_vb {
            return Err(FeePolicyError::RateTooLow);
        }
        if rate_sat_vb > self.max_sat_vb {
            return Err(FeePolicyError::RateTooHigh);
        }
        if fee_sats > self.max_fee_sats {
            return Err(FeePolicyError::FeeTooHigh);
        }
        if let Some(amount) = amount_sats
            && fee_sats.saturating_mul(100) > amount.saturating_mul(self.max_fee_percent)
        {
            return Err(FeePolicyError::FeeRatioExceeded);
        }
        Ok(())
    }
}

/// Durable state contract. Implementations must never persist private keys.
pub trait UtxoStore {
    type Error;

    fn load_utxos(&self) -> Result<Vec<Utxo>, Self::Error>;
    fn save_utxos(&mut self, utxos: &[Utxo]) -> Result<(), Self::Error>;
    fn load_history(&self) -> Result<Vec<UtxoHistoryEntry>, Self::Error>;
    fn save_history(&mut self, history: &[UtxoHistoryEntry]) -> Result<(), Self::Error>;
    fn load_checkpoint(&self) -> Result<Option<u64>, Self::Error>;
    fn save_checkpoint(&mut self, height: u64) -> Result<(), Self::Error>;
}

/// Coin selection is policy supplied by the caller; the SDK only enforces
/// sufficient value and stable deterministic ordering.
pub trait CoinSelector {
    fn select(&self, utxos: &[Utxo], target_sats: u64) -> Result<Vec<Utxo>, SelectionError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("zero target")]
    ZeroTarget,
}

/// Largest-first selection; deterministic and fee-rate agnostic.
#[derive(Debug, Default, Clone, Copy)]
pub struct LargestFirst;

impl CoinSelector for LargestFirst {
    fn select(&self, utxos: &[Utxo], target_sats: u64) -> Result<Vec<Utxo>, SelectionError> {
        if target_sats == 0 {
            return Err(SelectionError::ZeroTarget);
        }
        let mut sorted: Vec<&Utxo> = utxos.iter().collect();
        sorted.sort_by_key(|u| std::cmp::Reverse(u.value_sats));
        let mut selected = Vec::new();
        let mut total = 0u64;
        for utxo in sorted {
            total = total.saturating_add(utxo.value_sats);
            selected.push(utxo.clone());
            if total >= target_sats {
                return Ok(selected);
            }
        }
        Err(SelectionError::InsufficientFunds)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn balance_never_double_counts_pending() {
        let balance = UtxoBalance {
            confirmed_sats: 1_000,
            trusted_pending_sats: 200,
            untrusted_pending_sats: 100,
            immature_sats: 50,
            reserved_sats: 300,
        };
        assert_eq!(balance.pending_sats(), 300);
        assert_eq!(balance.spendable_sats(), 700);
        assert_eq!(balance.total_sats(), 1_350);
    }

    #[test]
    fn fee_policy_fails_closed() {
        let policy = FeePolicy {
            min_sat_vb: 1,
            max_sat_vb: 1_000,
            max_fee_sats: 1_000_000,
            max_fee_percent: 10,
        };
        assert!(policy.check(1, 100, Some(1_000)).is_ok());
        assert!(policy.check(0, 100, Some(1_000)).is_err());
        assert!(policy.check(1, 200, Some(1_000)).is_err());
    }

    #[test]
    fn selection_is_deterministic_largest_first() {
        let utxos = vec![
            Utxo {
                txid: "a".into(),
                vout: 0,
                value_sats: 100,
                confirmations: 1,
                keychain: 0,
                index: 0,
            },
            Utxo {
                txid: "b".into(),
                vout: 0,
                value_sats: 500,
                confirmations: 1,
                keychain: 0,
                index: 1,
            },
        ];
        let selected = LargestFirst.select(&utxos, 400).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value_sats, 500);
        assert!(LargestFirst.select(&utxos, 700).is_err());
    }
}
