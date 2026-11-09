//! EIP-1559 fee quoting with explicit confidence status.
//!
//! L2 chains add an L1 data-fee component that this SDK cannot compute
//! reliably yet. Their quotes are returned with `total_confident = false`
//! and transaction preparation refuses to sign them.

use crate::U256;

use crate::{EvmError, EvmProvider, EvmTxType, FeeModel};

pub const MAX_FEE_PER_GAS: u128 = 500_000_000_000; // 500 gwei
pub const MAX_PRIORITY_FEE_PER_GAS: u128 = 10_000_000_000; // 10 gwei
pub const MAX_GAS_LIMIT: u64 = 1_000_000;
pub const MAX_DEPLOY_GAS_LIMIT: u64 = 5_000_000;
pub const MAX_LEGACY_GAS_PRICE: u128 = 500_000_000_000; // 500 gwei

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedFees {
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub gas_price: Option<u128>,
    pub max_gas_cost_wei: U256,
    pub tx_type: EvmTxType,
}

/// Select the chain's verified fee model. Unknown models fail closed.
pub async fn select_fees(provider: &EvmProvider, gas_limit: u64) -> Result<SelectedFees, EvmError> {
    match provider.chain.fee_model {
        FeeModel::Legacy => {
            let gas_price = provider.gas_price().await?;
            if gas_price == 0 || gas_price > MAX_LEGACY_GAS_PRICE {
                return Err(EvmError::FeeRejected);
            }
            let max_gas_cost = U256::from(gas_price)
                .checked_mul(U256::from(gas_limit))
                .ok_or(EvmError::FeeRejected)?;
            Ok(SelectedFees {
                gas_limit,
                max_fee_per_gas: gas_price,
                max_priority_fee_per_gas: 0,
                gas_price: Some(gas_price),
                max_gas_cost_wei: max_gas_cost,
                tx_type: EvmTxType::Legacy,
            })
        }
        FeeModel::Eip1559 => {
            let quote = quote_fees(provider, gas_limit).await?;
            if !quote.total_confident {
                return Err(EvmError::UnsupportedFeeModel);
            }
            Ok(SelectedFees {
                gas_limit: quote.gas_limit,
                max_fee_per_gas: quote.max_fee_per_gas,
                max_priority_fee_per_gas: quote.max_priority_fee_per_gas,
                gas_price: None,
                max_gas_cost_wei: quote.max_gas_cost_wei,
                tx_type: EvmTxType::Eip1559,
            })
        }
        FeeModel::Eip1559WithL1DataFee => Err(EvmError::UnsupportedFeeModel),
    }
}

impl SelectedFees {
    pub fn max_total_cost(&self, value: U256) -> Result<U256, EvmError> {
        value
            .checked_add(self.max_gas_cost_wei)
            .ok_or(EvmError::FeeRejected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeQuote {
    pub base_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// `max_fee_per_gas * gas_limit`; excludes value and L1 data fee.
    pub max_gas_cost_wei: U256,
    pub l1_data_fee_wei: Option<U256>,
    /// True only when every fee component is modelled and bounded.
    pub total_confident: bool,
}

impl FeeQuote {
    pub fn max_total_cost(&self, value: U256) -> Result<U256, EvmError> {
        let mut total = value;
        for part in [
            self.max_gas_cost_wei,
            self.l1_data_fee_wei.unwrap_or(U256::zero()),
        ] {
            total = total.checked_add(part).ok_or(EvmError::FeeRejected)?;
        }
        Ok(total)
    }
}

pub async fn quote_fees(provider: &EvmProvider, gas_limit: u64) -> Result<FeeQuote, EvmError> {
    if gas_limit == 0 || gas_limit > MAX_DEPLOY_GAS_LIMIT {
        return Err(EvmError::FeeRejected);
    }
    if provider.chain.fee_model == FeeModel::Legacy {
        return Err(EvmError::UnsupportedFeeModel);
    }
    let base_fee = provider.latest_base_fee().await?;
    let (max_fee, priority) = provider.eip1559_fees().await?;
    if priority > MAX_PRIORITY_FEE_PER_GAS || max_fee > MAX_FEE_PER_GAS {
        return Err(EvmError::FeeRejected);
    }
    // Never trust a provider estimate below the base fee.
    let minimum = base_fee.saturating_mul(2).saturating_add(priority);
    let max_fee = max_fee.max(minimum);
    if max_fee > MAX_FEE_PER_GAS {
        return Err(EvmError::FeeRejected);
    }
    let max_gas_cost = U256::from(max_fee)
        .checked_mul(U256::from(gas_limit))
        .ok_or(EvmError::FeeRejected)?;
    Ok(FeeQuote {
        base_fee_per_gas: base_fee,
        max_priority_fee_per_gas: priority,
        max_fee_per_gas: max_fee,
        gas_limit,
        max_gas_cost_wei: max_gas_cost,
        l1_data_fee_wei: None,
        total_confident: provider.chain.fee_model == FeeModel::Eip1559,
    })
}
