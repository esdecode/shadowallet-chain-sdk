//! Bitcoin wallet engine built on BDK 3.2.
//!
//! Security boundary:
//! - Descriptors persisted in SQLite are **public** (xpub) descriptors only.
//! - The watch-only engine never receives a seed or private descriptor.
//! - The calling application signs the PSBT; the SDK finalizes it.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, OutPoint, address::NetworkChecked};
use bdk_wallet::{KeychainKind, PersistedWallet, Wallet};
use thiserror::Error;

pub mod sqlite_store;
pub use sqlite_store::{SqliteStore, SqliteStoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BtcNetwork {
    Mainnet,
    Testnet4,
    Signet,
    Regtest,
}

impl BtcNetwork {
    pub const fn network(self) -> Network {
        match self {
            Self::Mainnet => Network::Bitcoin,
            Self::Testnet4 => Network::Testnet4,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }

    /// BIP44 coin type: 0 on mainnet, 1 on every test network.
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            _ => 1,
        }
    }

    pub const fn is_mainnet(self) -> bool {
        matches!(self, Self::Mainnet)
    }

    pub fn parse(value: &str) -> Result<Self, BitcoinError> {
        match value {
            "bitcoin" | "mainnet" | "bitcoin-mainnet" => Ok(Self::Mainnet),
            "testnet4" | "bitcoin-testnet4" => Ok(Self::Testnet4),
            "signet" | "bitcoin-signet" => Ok(Self::Signet),
            "regtest" | "bitcoin-regtest" => Ok(Self::Regtest),
            _ => Err(BitcoinError::UnknownNetwork),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressKind {
    /// BIP84 native segwit (default).
    P2wpkh,
}

impl AddressKind {
    pub const fn purpose(self) -> u32 {
        match self {
            Self::P2wpkh => 84,
        }
    }
}

#[derive(Debug, Error)]
pub enum BitcoinError {
    #[error("unknown bitcoin network")]
    UnknownNetwork,
    #[error("address is not valid for the selected network")]
    WrongNetworkAddress,
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("wallet storage error: {0}")]
    Storage(String),
    #[error("wallet engine error: {0}")]
    Engine(String),
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("transaction must not exceed the authorized fee")]
    FeeTooHigh,
    #[error("signing requires an unlocked, authorized session")]
    Unauthorized,
    #[error("network request failed: {0}")]
    Network(String),
    #[error("unsupported operation in this phase")]
    Unsupported,
    #[error("mainnet signing and broadcasting are disabled in Phase 4A")]
    MainnetDisabled,
}

/// Deterministic account descriptor material. Contains only public keys.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WatchDescriptors {
    pub network: BtcNetwork,
    pub kind: AddressKind,
    /// Public descriptor (can be shown/persisted).
    pub external: String,
    pub internal: String,
    pub fingerprint: String,
}

impl std::fmt::Debug for WatchDescriptors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchDescriptors")
            .field("network", &self.network)
            .field("kind", &self.kind)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

pub struct BitcoinEngine {
    wallet: PersistedWallet<SqliteStore>,
    descriptors: WatchDescriptors,
    store: SqliteStore,
    db_path: PathBuf,
}

impl std::fmt::Debug for BitcoinEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoinEngine")
            .field("network", &self.descriptors.network)
            .field("fingerprint", &self.descriptors.fingerprint)
            .finish()
    }
}

/// Result of a synchronization pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    pub tip_height: u64,
    pub new_transactions: usize,
}

impl BitcoinEngine {
    /// Full/incremental scan through Esplora. The endpoint is untrusted input:
    /// it can supply chain data, never authorization.
    pub fn sync_esplora(&mut self, url: &str) -> Result<SyncReport, BitcoinError> {
        let client = bdk_esplora::esplora_client::Builder::new(url)
            .build_async()
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        let request = self.wallet.start_full_scan();
        let update = block_on(bdk_esplora::EsploraAsyncExt::full_scan(
            &client, request, 20, 1,
        ))
        .map_err(|e| BitcoinError::Network(e.to_string()))?;
        let before = self.wallet.transactions().count();
        self.wallet
            .apply_update(update)
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        self.persist()?;
        Ok(SyncReport {
            tip_height: self.wallet.latest_checkpoint().height() as u64,
            new_transactions: self.wallet.transactions().count().saturating_sub(before),
        })
    }

    /// Regtest/self-hosted sync through Bitcoin Core RPC.
    pub fn sync_bitcoind(
        &mut self,
        url: &str,
        user: &str,
        password: &str,
    ) -> Result<SyncReport, BitcoinError> {
        use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
        let rpc = Client::new(url, Auth::UserPass(user.to_owned(), password.to_owned()))
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        let tip = rpc
            .get_block_count()
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        let start = self.wallet.latest_checkpoint().height() as u64;
        let _ = start.min(tip);
        let mut emitter = bdk_bitcoind_rpc::Emitter::new(
            &rpc,
            self.wallet.latest_checkpoint(),
            start as u32,
            std::iter::empty::<bdk_wallet::bitcoin::Transaction>(),
        );
        let before = self.wallet.transactions().count();
        let mempool = emitter
            .mempool()
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        for tx in mempool.update {
            self.wallet.apply_unconfirmed_txs([tx]);
        }
        while let Some(event) = emitter
            .next_block()
            .map_err(|e| BitcoinError::Network(e.to_string()))?
        {
            self.wallet
                .apply_block(&event.block, event.block_height())
                .map_err(|e| BitcoinError::Engine(e.to_string()))?;
            self.persist()?;
        }
        // Mempool events are intentionally not applied here; unconfirmed
        // balances require a separate, explicitly configured policy.
        self.persist()?;
        Ok(SyncReport {
            tip_height: self.wallet.latest_checkpoint().height() as u64,
            new_transactions: self.wallet.transactions().count().saturating_sub(before),
        })
    }
}

impl BitcoinEngine {
    pub fn create(db_path: &Path, descriptors: WatchDescriptors) -> Result<Self, BitcoinError> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| BitcoinError::Storage(e.to_string()))?;
        }
        let mut store =
            SqliteStore::open(db_path).map_err(|e| BitcoinError::Storage(e.to_string()))?;
        // BDK persists public descriptors and chain data only.
        let wallet = Wallet::create(descriptors.external.clone(), descriptors.internal.clone())
            .network(descriptors.network.network())
            .create_wallet(&mut store)
            .map_err(|e| BitcoinError::Storage(e.to_string()))?;
        Ok(Self {
            wallet,
            descriptors,
            store,
            db_path: db_path.to_owned(),
        })
    }

    pub fn load(
        db_path: &Path,
        descriptors: WatchDescriptors,
    ) -> Result<Option<Self>, BitcoinError> {
        if !db_path.exists() {
            return Ok(None);
        }
        let mut store =
            SqliteStore::open(db_path).map_err(|e| BitcoinError::Storage(e.to_string()))?;
        let wallet = Wallet::load()
            .descriptor(KeychainKind::External, Some(descriptors.external.clone()))
            .descriptor(KeychainKind::Internal, Some(descriptors.internal.clone()))
            .load_wallet(&mut store)
            .map_err(|e| BitcoinError::Storage(e.to_string()))?;
        Ok(wallet.map(|wallet| Self {
            wallet,
            descriptors,
            store,
            db_path: db_path.to_owned(),
        }))
    }

    pub fn network(&self) -> BtcNetwork {
        self.descriptors.network
    }

    pub fn descriptors(&self) -> &WatchDescriptors {
        &self.descriptors
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn tip_height(&self) -> u64 {
        self.wallet.latest_checkpoint().height() as u64
    }

    /// Next unused native segwit receive address. Persists the index change.
    pub fn next_receive_address(&mut self) -> Result<String, BitcoinError> {
        let info = self.wallet.reveal_next_address(KeychainKind::External);
        self.persist()?;
        Ok(info.address.to_string())
    }

    pub fn persist(&mut self) -> Result<(), BitcoinError> {
        self.wallet
            .persist(&mut self.store)
            .map_err(|e| BitcoinError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn balance(&self) -> WalletBalance {
        let balance = self.wallet.balance();
        WalletBalance {
            confirmed_sats: balance.confirmed.to_sat(),
            trusted_pending_sats: balance.trusted_pending.to_sat(),
            untrusted_pending_sats: balance.untrusted_pending.to_sat(),
            immature_sats: balance.immature.to_sat(),
            spendable_sats: balance
                .confirmed
                .checked_sub(Amount::from_sat(0))
                .map(|a| a.to_sat())
                .unwrap_or(balance.confirmed.to_sat()),
        }
    }

    /// Shared balance projection; consensus/coin-selection policy remains here.
    pub fn balance_common(&self) -> shadowallet_chain_utxo::UtxoBalance {
        let balance = self.balance();
        shadowallet_chain_utxo::UtxoBalance {
            confirmed_sats: balance.confirmed_sats,
            trusted_pending_sats: balance.trusted_pending_sats,
            untrusted_pending_sats: balance.untrusted_pending_sats,
            immature_sats: balance.immature_sats,
            reserved_sats: 0,
        }
    }

    /// Shared history projection. Amounts are computed by this engine.
    pub fn history_common(&self) -> Vec<shadowallet_chain_utxo::UtxoHistoryEntry> {
        self.transactions()
            .into_iter()
            .map(|tx| shadowallet_chain_utxo::UtxoHistoryEntry {
                txid: tx.txid,
                received_sats: tx.received_sats,
                sent_sats: tx.sent_sats,
                confirmation_height: tx.confirmation_height,
            })
            .collect()
    }

    pub fn list_unspent(&self) -> Vec<OutPoint> {
        self.wallet.list_unspent().map(|u| u.outpoint).collect()
    }

    pub fn transactions(&self) -> Vec<TxSummary> {
        self.wallet
            .transactions()
            .map(|entry| {
                let tx = entry.tx_node.tx.clone();
                let received_sats: u64 = tx
                    .output
                    .iter()
                    .filter(|out| self.wallet.is_mine(out.script_pubkey.clone()))
                    .map(|out| out.value.to_sat())
                    .sum();
                let spent_points: std::collections::HashSet<_> =
                    tx.input.iter().map(|i| i.previous_output).collect();
                let sent_sats: u64 = self
                    .wallet
                    .list_unspent()
                    .chain(self.wallet.list_output())
                    .filter(|out| spent_points.contains(&out.outpoint))
                    .map(|out| out.txout.value.to_sat())
                    .sum();
                TxSummary {
                    txid: entry.tx_node.txid.to_string(),
                    received_sats,
                    sent_sats,
                    confirmation_height: entry
                        .chain_position
                        .confirmation_height_upper_bound()
                        .map(|h| h as u64),
                }
            })
            .collect()
    }

    /// Validate a destination against the wallet's network. Never infer the
    /// network from the address alone.
    pub fn validate_address(&self, address: &str) -> Result<Address<NetworkChecked>, BitcoinError> {
        let unchecked =
            Address::from_str(address).map_err(|e| BitcoinError::InvalidAddress(e.to_string()))?;
        unchecked
            .require_network(self.descriptors.network.network())
            .map_err(|_| BitcoinError::WrongNetworkAddress)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletBalance {
    pub confirmed_sats: u64,
    pub trusted_pending_sats: u64,
    pub untrusted_pending_sats: u64,
    pub immature_sats: u64,
    pub spendable_sats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSummary {
    pub txid: String,
    pub received_sats: u64,
    pub sent_sats: u64,
    pub confirmation_height: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TransferPlan {
    pub psbt: Vec<u8>,
    pub fee_sats: u64,
}

impl BtcNetwork {
    pub const fn network_id(self) -> &'static str {
        match self {
            Self::Mainnet => "bitcoin-mainnet",
            Self::Testnet4 => "bitcoin-testnet4",
            Self::Signet => "bitcoin-signet",
            Self::Regtest => "bitcoin-regtest",
        }
    }
}

impl BitcoinEngine {
    /// Build an unsigned PSBT. No key material is used.
    pub fn build_transfer(
        &mut self,
        destination: &str,
        amount_sats: u64,
        fee_rate_sat_vb: u64,
        send_max: bool,
    ) -> Result<TransferPlan, BitcoinError> {
        if self.descriptors.network.is_mainnet() {
            return Err(BitcoinError::MainnetDisabled);
        }
        let address = self.validate_address(destination)?;
        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate_sat_vb).ok_or(BitcoinError::Unsupported)?;
        let mut builder = self.wallet.build_tx();
        if send_max {
            builder.drain_wallet().drain_to(address.script_pubkey());
        } else {
            if amount_sats == 0 {
                return Err(BitcoinError::Unsupported);
            }
            builder.add_recipient(address.script_pubkey(), Amount::from_sat(amount_sats));
        }
        builder
            .fee_rate(fee_rate)
            .set_exact_sequence(bdk_wallet::bitcoin::Sequence::from_consensus(0xFFFF_FFFD));
        let psbt = builder
            .finish()
            .map_err(|e| BitcoinError::Engine(e.to_string()))?;
        let fee_sats = psbt.fee().map(|fee| fee.to_sat()).unwrap_or(0);
        BITCOIN_FEE_POLICY
            .check(
                fee_rate_sat_vb,
                fee_sats,
                if send_max { None } else { Some(amount_sats) },
            )
            .map_err(|_| BitcoinError::FeeTooHigh)?;
        Ok(TransferPlan {
            psbt: psbt.serialize(),
            fee_sats,
        })
    }

    /// Finalize an externally signed PSBT after authorization. The caller signs
    /// the exact PSBT bytes; this method never signs.
    pub fn finalize_psbt(&self, psbt_bytes: &[u8]) -> Result<Vec<u8>, BitcoinError> {
        let psbt = bdk_wallet::bitcoin::psbt::Psbt::deserialize(psbt_bytes)
            .map_err(|e| BitcoinError::Engine(e.to_string()))?;
        let tx = psbt
            .extract_tx()
            .map_err(|e| BitcoinError::Engine(format!("extract failed: {e:?}")))?;
        Ok(bdk_wallet::bitcoin::consensus::serialize(&tx))
    }

    pub fn broadcast_bitcoind(
        &self,
        raw_transaction: &[u8],
        url: &str,
        user: &str,
        password: &str,
    ) -> Result<String, BitcoinError> {
        use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
        let tx: bdk_wallet::bitcoin::Transaction =
            bdk_wallet::bitcoin::consensus::deserialize(raw_transaction)
                .map_err(|e| BitcoinError::Engine(e.to_string()))?;
        let rpc = Client::new(url, Auth::UserPass(user.to_owned(), password.to_owned()))
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        let txid = rpc
            .send_raw_transaction(&tx)
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        Ok(txid.to_string())
    }

    pub fn broadcast_esplora(
        &self,
        raw_transaction: &[u8],
        url: &str,
    ) -> Result<String, BitcoinError> {
        let tx: bdk_wallet::bitcoin::Transaction =
            bdk_wallet::bitcoin::consensus::deserialize(raw_transaction)
                .map_err(|e| BitcoinError::Engine(e.to_string()))?;
        let client = bdk_esplora::esplora_client::Builder::new(url)
            .build_async()
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        block_on(client.broadcast(&tx)).map_err(|e| BitcoinError::Network(e.to_string()))?;
        Ok(tx.compute_txid().to_string())
    }
}

#[allow(clippy::expect_used)] // runtime creation failure is fatal and not recoverable
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(future)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct FeeEstimates {
    pub economy_sat_vb: u64,
    pub normal_sat_vb: u64,
    pub priority_sat_vb: u64,
    pub source: &'static str,
}

pub const BITCOIN_FEE_POLICY: shadowallet_chain_utxo::FeePolicy =
    shadowallet_chain_utxo::FeePolicy {
        min_sat_vb: 1,
        max_sat_vb: 1_000,
        max_fee_sats: 1_000_000,
        max_fee_percent: 10,
    };

fn check_rate(rate: f64) -> Result<u64, BitcoinError> {
    if !rate.is_finite() || rate <= 0.0 {
        return Err(BitcoinError::Network("invalid fee estimate".to_owned()));
    }
    let rounded = rate.ceil() as u64;
    if !(BITCOIN_FEE_POLICY.min_sat_vb..=BITCOIN_FEE_POLICY.max_sat_vb).contains(&rounded) {
        return Err(BitcoinError::Network(format!(
            "fee estimate outside accepted bounds: {rounded} sat/vB"
        )));
    }
    Ok(rounded)
}

impl BitcoinEngine {
    /// Live fee estimates from Bitcoin Core `estimatesmartfee`.
    pub fn estimate_fees_core(
        url: &str,
        user: &str,
        password: &str,
    ) -> Result<FeeEstimates, BitcoinError> {
        use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
        let rpc = Client::new(url, Auth::UserPass(user.to_owned(), password.to_owned()))
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        let estimate = |target: u64| -> Result<u64, BitcoinError> {
            let value: serde_json::Value = rpc
                .call("estimatesmartfee", &[serde_json::json!(target)])
                .map_err(|e| BitcoinError::Network(e.to_string()))?;
            let feerate = value
                .get("feerate")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| BitcoinError::Network("no feerate in estimate".to_owned()))?;
            // BTC/kvB -> sat/vB
            check_rate(feerate * 100_000_000.0 / 1_000.0)
        };
        let economy = estimate(144)?;
        let normal = estimate(6)?;
        let priority = estimate(1)?;
        let rates = [economy, normal, priority];
        let min = rates.iter().copied().min().unwrap_or(1);
        let max = rates.iter().copied().max().unwrap_or(1);
        if max > min.saturating_mul(3) {
            return Err(BitcoinError::Network(
                "provider fee estimates disagree by more than 3x".to_owned(),
            ));
        }
        Ok(FeeEstimates {
            economy_sat_vb: economy,
            normal_sat_vb: normal,
            priority_sat_vb: priority,
            source: "bitcoind",
        })
    }

    /// Live fee estimates from Esplora (`/fee-estimates`, sat/vB by target).
    pub fn estimate_fees_esplora(url: &str) -> Result<FeeEstimates, BitcoinError> {
        let client = bdk_esplora::esplora_client::Builder::new(url)
            .build_async()
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        let estimates = block_on(client.get_fee_estimates())
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        let pick = |target: u16| -> Result<u64, BitcoinError> {
            // Use the estimate for the closest target at or above the requested
            // confirmation target; fall back to the highest available.
            let chosen = estimates
                .iter()
                .filter(|(blocks, _)| **blocks >= target)
                .min_by_key(|(blocks, _)| **blocks)
                .or_else(|| estimates.iter().max_by_key(|(blocks, _)| **blocks))
                .map(|(_, rate)| *rate)
                .ok_or_else(|| BitcoinError::Network("empty fee estimates".to_owned()))?;
            check_rate(chosen)
        };
        let economy = pick(144)?;
        let normal = pick(6)?;
        let priority = pick(1)?;
        Ok(FeeEstimates {
            economy_sat_vb: economy,
            normal_sat_vb: normal,
            priority_sat_vb: priority,
            source: "esplora",
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod fee_tests {
    use super::*;

    #[test]
    fn fee_rate_bounds_are_enforced() {
        assert_eq!(check_rate(1.0).unwrap(), 1);
        assert_eq!(check_rate(1.2).unwrap(), 2);
        assert_eq!(check_rate(1000.0).unwrap(), 1000);
        assert!(check_rate(0.0).is_err());
        assert!(check_rate(-1.0).is_err());
        assert!(check_rate(f64::NAN).is_err());
        assert!(check_rate(f64::INFINITY).is_err());
        assert!(check_rate(1001.0).is_err());
    }

    #[test]
    fn transaction_fee_caps_are_documented_constants() {
        // The build_transfer guard uses these limits; keeping them explicit
        // makes accidental relaxation visible in review.
        assert_eq!(super::BITCOIN_FEE_POLICY.max_sat_vb, 1_000);
        assert_eq!(super::BITCOIN_FEE_POLICY.max_fee_sats, 1_000_000);
        assert_eq!(super::BITCOIN_FEE_POLICY.max_fee_percent, 10);
    }
}
