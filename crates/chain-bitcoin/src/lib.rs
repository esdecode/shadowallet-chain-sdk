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

impl WatchDescriptors {
    /// Watch-only native SegWit (P2WPKH) account from an account-level SLIP-0132 extended PUBLIC key
    /// (`zpub` on mainnet, `vpub` on the test networks), for example an Electrum native-SegWit wallet.
    ///
    /// The key is parsed locally and converted to the plain extended-public-key form BDK reads, without changing the
    /// key or chain code. The receive branch is `/0/*` and the change branch `/1/*`, exactly as Electrum derives them.
    /// No origin path is assumed: a valid key says nothing about whether it came from `m/84'/0'/0'`, and the addresses
    /// depend only on the key itself. Refused, without echoing the input: a bad Base58Check checksum, a private key,
    /// a version that is not the P2WPKH public version of `network`, a master key (depth 0), a wrong length.
    /// An engine built from these descriptors holds no private key and has no signing method.
    pub fn from_extended_pubkey(text: &str, network: BtcNetwork) -> Result<Self, BitcoinError> {
        use bdk_wallet::bitcoin::{base58, bip32::Xpub};
        const ZPUB: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
        const VPUB: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];
        const PRIVATE: [[u8; 4]; 6] = [
            [0x04, 0x88, 0xad, 0xe4], // xprv
            [0x04, 0x9d, 0x78, 0x78], // yprv
            [0x04, 0xb2, 0x43, 0x0c], // zprv
            [0x04, 0x35, 0x83, 0x94], // tprv
            [0x04, 0x4a, 0x4e, 0x28], // uprv
            [0x04, 0x5f, 0x18, 0xbc], // vprv
        ];
        let fail = |why: &str| BitcoinError::Engine(format!("extended public key refused: {why}"));
        let data = base58::decode_check(text.trim())
            .map_err(|_| fail("not valid Base58Check (typo or wrong checksum)"))?;
        if data.len() != 78 {
            return Err(fail("wrong length"));
        }
        let version: [u8; 4] = [data[0], data[1], data[2], data[3]];
        if PRIVATE.contains(&version) {
            return Err(fail("this is a private key; only public keys are accepted"));
        }
        let expected = if network.is_mainnet() { ZPUB } else { VPUB };
        if version != expected {
            return Err(fail(
                "version is not the native SegWit public version for this network (zpub on mainnet, vpub on test networks)",
            ));
        }
        let mut plain = data;
        let plain_version: [u8; 4] = if network.is_mainnet() {
            [0x04, 0x88, 0xb2, 0x1e]
        } else {
            [0x04, 0x35, 0x87, 0xcf]
        };
        plain[..4].copy_from_slice(&plain_version);
        let xpub = Xpub::decode(&plain).map_err(|_| fail("not a valid extended public key"))?;
        if xpub.depth == 0 {
            return Err(fail("a master (depth 0) key is not an account key"));
        }
        let fingerprint = xpub.fingerprint().to_string();
        Ok(Self {
            network,
            kind: AddressKind::P2wpkh,
            external: format!("wpkh({xpub}/0/*)"),
            internal: format!("wpkh({xpub}/1/*)"),
            fingerprint,
        })
    }
}

/// Upper bound for one Esplora request (read or submit). A stalled provider can no longer hang the wallet.
pub const HTTP_TIMEOUT_SECS: u64 = 30;

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
        // Read-only: a public server may reset a pooled connection or rate-limit, so the scan is
        // retried a bounded number of times, each time with a fresh client and a fresh request.
        let update = retry_read(|| {
            let client = bdk_esplora::esplora_client::Builder::new(url)
                .timeout(HTTP_TIMEOUT_SECS)
                .build_async()
                .map_err(|e| BitcoinError::Network(e.to_string()))?;
            let request = self.wallet.start_full_scan();
            block_on(bdk_esplora::EsploraAsyncExt::full_scan(
                &client, request, 20, 1,
            ))
            .map_err(|e| BitcoinError::Network(e.to_string()))
        })?;
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

    /// Highest derivation index known for the receive and the change branch (after a scan: the highest index that has
    /// history), `None` for a branch with no activity. Public key material only.
    pub fn revealed_indexes(&self) -> (Option<u32>, Option<u32>) {
        (
            self.wallet.derivation_index(KeychainKind::External),
            self.wallet.derivation_index(KeychainKind::Internal),
        )
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
        self.build_transfer_excluding(destination, amount_sats, fee_rate_sat_vb, send_max, &[])
    }

    /// Like [`build_transfer`](Self::build_transfer) but never selects the
    /// given outpoints (`txid`, `vout`), so a caller that holds reservations
    /// can let coin selection work from the remaining coins. An outpoint that
    /// is not a valid txid is rejected rather than ignored.
    pub fn build_transfer_excluding(
        &mut self,
        destination: &str,
        amount_sats: u64,
        fee_rate_sat_vb: u64,
        send_max: bool,
        exclude: &[(String, u32)],
    ) -> Result<TransferPlan, BitcoinError> {
        use std::str::FromStr;
        let unspendable = exclude
            .iter()
            .map(|(txid, vout)| {
                bdk_wallet::bitcoin::Txid::from_str(txid)
                    .map(|txid| bdk_wallet::bitcoin::OutPoint::new(txid, *vout))
                    .map_err(|e| BitcoinError::Engine(format!("bad excluded outpoint: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Compile-time opt-in (`mainnet-send`), never a runtime switch: the wallet's native policy decides separately.
        if !cfg!(feature = "mainnet-send") && self.descriptors.network.is_mainnet() {
            return Err(BitcoinError::MainnetDisabled);
        }
        let address = self.validate_address(destination)?;
        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate_sat_vb).ok_or(BitcoinError::Unsupported)?;
        let mut unspendable = unspendable;
        unspendable.extend(self.policy_blocked_outpoints());
        let mut builder = self.wallet.build_tx();
        builder.unspendable(unspendable);
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
        self.broadcast_esplora_with_timeout(raw_transaction, url, HTTP_TIMEOUT_SECS)
    }

    /// Submit a signed transaction through Esplora with a bounded wait. The returned id is ALWAYS the one computed from
    /// the signed bytes: an id echoed by the provider is never used, so a provider cannot redirect tracking. An error
    /// (including a timeout) means the outcome is UNKNOWN unless the provider answered with a definite rejection; the
    /// caller must keep the inputs reserved and reconcile by this id. A submission is never retried here.
    pub fn broadcast_esplora_with_timeout(
        &self,
        raw_transaction: &[u8],
        url: &str,
        timeout_secs: u64,
    ) -> Result<String, BitcoinError> {
        let tx: bdk_wallet::bitcoin::Transaction =
            bdk_wallet::bitcoin::consensus::deserialize(raw_transaction)
                .map_err(|e| BitcoinError::Engine(e.to_string()))?;
        let client = bdk_esplora::esplora_client::Builder::new(url)
            .timeout(timeout_secs)
            .build_async()
            .map_err(|e| BitcoinError::Network(e.to_string()))?;
        block_on(client.broadcast(&tx)).map_err(|e| BitcoinError::Network(e.to_string()))?;
        Ok(tx.compute_txid().to_string())
    }
}

/// Bounded retry for READ-ONLY requests to a public server (stale pooled connection, rate limit,
/// transient 5xx). Up to four attempts with 0.5 s, 1 s and 2 s pauses. Never used for a broadcast:
/// retrying a submission after an unclear outcome could duplicate it.
fn retry_read<T>(mut attempt: impl FnMut() -> Result<T, BitcoinError>) -> Result<T, BitcoinError> {
    let mut pause = std::time::Duration::from_millis(500);
    let mut last = None;
    for n in 0..4 {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(error) => {
                last = Some(error);
                if n < 3 {
                    std::thread::sleep(pause);
                    pause *= 2;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| BitcoinError::Network("no attempt was made".to_owned())))
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
        let estimates = retry_read(|| {
            let client = bdk_esplora::esplora_client::Builder::new(url)
                .timeout(HTTP_TIMEOUT_SECS)
                .build_async()
                .map_err(|e| BitcoinError::Network(e.to_string()))?;
            block_on(client.get_fee_estimates()).map_err(|e| BitcoinError::Network(e.to_string()))
        })?;
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

// ---------------------------------------------------------------------------------------------
// Coin Control: output listing, explicit input selection and an independent PSBT summary.
// ---------------------------------------------------------------------------------------------

/// One unspent output of the wallet, as a coin-selection UI needs it. Everything is derived from the
/// wallet's own synchronized view; nothing here is supplied by a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub address: Option<String>,
    /// Output of the internal (change) keychain.
    pub is_change: bool,
    pub derivation_index: u32,
    /// Block height of the confirming block; `None` while unconfirmed.
    pub confirmation_height: Option<u32>,
    /// Timestamp of the confirming block header; `None` while unconfirmed.
    pub confirmation_time: Option<u64>,
    /// `tip - height + 1` when confirmed, `0` otherwise.
    pub confirmations: u64,
    /// The funding transaction is a coinbase (first input spends the null outpoint).
    pub is_coinbase: bool,
    /// Whether automatic coin selection may use this output under the wallet's spending policy.
    pub spendable: bool,
    /// Why it is not spendable: `immature coinbase` or `unconfirmed incoming`.
    pub unspendable_reason: Option<&'static str>,
}

/// One input of a PSBT with the value it spends (taken from the PSBT's own previous-output data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtInputInfo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

/// One output of a PSBT. `is_change` is true only for the wallet's own internal keychain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtOutputInfo {
    pub script_pubkey_hex: String,
    pub address: Option<String>,
    pub value_sats: u64,
    pub is_mine: bool,
    pub is_change: bool,
}

/// What an unsigned PSBT really does, recomputed from the PSBT bytes with integer arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtSummary {
    pub inputs: Vec<PsbtInputInfo>,
    pub outputs: Vec<PsbtOutputInfo>,
    pub total_in_sats: u64,
    pub total_out_sats: u64,
    pub fee_sats: u64,
}

fn parse_outpoint(txid: &str, vout: u32) -> Result<OutPoint, BitcoinError> {
    let txid = bdk_wallet::bitcoin::Txid::from_str(txid)
        .map_err(|e| BitcoinError::Engine(format!("bad outpoint: {e}")))?;
    Ok(OutPoint::new(txid, vout))
}

/// Bitcoin consensus: a coinbase output may be spent by a block at height >= its own height + 100, i.e. it needs
/// 100 confirmations (`tip - height + 1 >= 100`) before it can enter a transaction that the next block could include.
pub const COINBASE_MATURITY: u64 = 100;

impl BitcoinEngine {
    /// True when the transaction that created `outpoint` is a coinbase transaction.
    pub fn is_coinbase(&self, outpoint: &OutPoint) -> bool {
        self.wallet
            .get_tx(outpoint.txid)
            .is_some_and(|t| t.tx_node.tx.is_coinbase())
    }

    /// Spending policy for AUTOMATIC selection (the wallet never trusts a provider flag for this):
    /// an immature coinbase is never spendable, and an unconfirmed output is spendable only when it is the wallet's own
    /// change (internal keychain); an unconfirmed payment from someone else can be replaced or dropped by its sender.
    fn policy_block_reason(&self, u: &bdk_wallet::LocalOutput, tip: u32) -> Option<&'static str> {
        use bdk_wallet::chain::ChainPosition;
        let confirmations = match &u.chain_position {
            ChainPosition::Confirmed { anchor, .. } => {
                u64::from(tip.saturating_sub(anchor.block_id.height)).saturating_add(1)
            }
            ChainPosition::Unconfirmed { .. } => 0,
        };
        if self.is_coinbase(&u.outpoint) && confirmations < COINBASE_MATURITY {
            return Some("immature coinbase");
        }
        if confirmations == 0 && u.keychain != KeychainKind::Internal {
            return Some("unconfirmed incoming");
        }
        None
    }

    /// Outputs that automatic selection must not use under the spending policy.
    fn policy_blocked_outpoints(&self) -> Vec<OutPoint> {
        let tip = self.wallet.latest_checkpoint().height();
        self.wallet
            .list_unspent()
            .filter(|u| self.policy_block_reason(u, tip).is_some())
            .map(|u| u.outpoint)
            .collect()
    }

    /// Every unspent output the wallet knows, with the data Coin Control displays.
    pub fn list_utxos(&self) -> Vec<UtxoInfo> {
        use bdk_wallet::chain::ChainPosition;
        let tip = self.wallet.latest_checkpoint().height();
        let network = self.descriptors.network.network();
        let mut out: Vec<UtxoInfo> = self
            .wallet
            .list_unspent()
            .map(|u| {
                let (height, time) = match &u.chain_position {
                    ChainPosition::Confirmed { anchor, .. } => {
                        (Some(anchor.block_id.height), Some(anchor.confirmation_time))
                    }
                    ChainPosition::Unconfirmed { .. } => (None, None),
                };
                UtxoInfo {
                    txid: u.outpoint.txid.to_string(),
                    vout: u.outpoint.vout,
                    value_sats: u.txout.value.to_sat(),
                    script_pubkey_hex: u.txout.script_pubkey.to_hex_string(),
                    address: Address::from_script(&u.txout.script_pubkey, network)
                        .ok()
                        .map(|a| a.to_string()),
                    is_change: u.keychain == KeychainKind::Internal,
                    derivation_index: u.derivation_index,
                    confirmation_height: height,
                    confirmation_time: time,
                    confirmations: height
                        .map_or(0, |h| u64::from(tip.saturating_sub(h)).saturating_add(1)),
                    is_coinbase: self.is_coinbase(&u.outpoint),
                    spendable: self.policy_block_reason(&u, tip).is_none(),
                    unspendable_reason: self.policy_block_reason(&u, tip),
                }
            })
            .collect();
        out.sort_by(|a, b| (a.txid.as_str(), a.vout).cmp(&(b.txid.as_str(), b.vout)));
        out
    }

    /// Build an unsigned PSBT that spends **exactly** the `selected` outpoints, never more.
    ///
    /// Refused, with nothing built: an empty selection, a duplicate outpoint, an outpoint that is not
    /// an unspent output of this wallet, and an outpoint also present in `blocked` (frozen or reserved
    /// by the caller). Insufficient selected funds fail with [`BitcoinError::InsufficientFunds`]; the
    /// engine never falls back to automatic selection. With `send_max` the whole selection is swept to
    /// the destination. The finished PSBT is checked to contain exactly the selected inputs.
    pub fn build_transfer_selected(
        &mut self,
        destination: &str,
        amount_sats: u64,
        fee_rate_sat_vb: u64,
        send_max: bool,
        selected: &[(String, u32)],
        blocked: &[(String, u32)],
    ) -> Result<TransferPlan, BitcoinError> {
        // Compile-time opt-in (`mainnet-send`), never a runtime switch: the wallet's native policy decides separately.
        if !cfg!(feature = "mainnet-send") && self.descriptors.network.is_mainnet() {
            return Err(BitcoinError::MainnetDisabled);
        }
        if selected.is_empty() {
            return Err(BitcoinError::Engine("no inputs selected".to_owned()));
        }
        let mut wanted = std::collections::BTreeSet::new();
        for (txid, vout) in selected {
            if !wanted.insert(parse_outpoint(txid, *vout)?) {
                return Err(BitcoinError::Engine(format!(
                    "duplicate input {txid}:{vout}"
                )));
            }
        }
        let blocked: std::collections::BTreeSet<OutPoint> = blocked
            .iter()
            .map(|(t, v)| parse_outpoint(t, *v))
            .collect::<Result<_, _>>()?;
        let unspent: std::collections::BTreeSet<OutPoint> =
            self.list_unspent().into_iter().collect();
        for outpoint in &wanted {
            if !unspent.contains(outpoint) {
                return Err(BitcoinError::Engine(format!(
                    "input {outpoint} is not an unspent output of this wallet"
                )));
            }
            if blocked.contains(outpoint) {
                return Err(BitcoinError::Engine(format!(
                    "input {outpoint} is frozen or reserved by another transaction"
                )));
            }
            // An explicit choice may use an unconfirmed output (CPFP does), but never an immature coinbase.
            let tip = self.wallet.latest_checkpoint().height();
            if let Some(u) = self.wallet.list_unspent().find(|u| u.outpoint == *outpoint)
                && self.policy_block_reason(&u, tip) == Some("immature coinbase")
            {
                return Err(BitcoinError::Engine(format!(
                    "input {outpoint} is an immature coinbase output (needs {COINBASE_MATURITY} confirmations)"
                )));
            }
        }
        let address = self.validate_address(destination)?;
        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate_sat_vb).ok_or(BitcoinError::Unsupported)?;
        let list: Vec<OutPoint> = wanted.iter().copied().collect();
        let mut builder = self.wallet.build_tx();
        builder
            .add_utxos(&list)
            .map_err(|e| BitcoinError::Engine(format!("input refused: {e}")))?;
        builder.manually_selected_only();
        if send_max {
            builder.drain_to(address.script_pubkey());
        } else {
            if amount_sats == 0 {
                return Err(BitcoinError::Unsupported);
            }
            builder.add_recipient(address.script_pubkey(), Amount::from_sat(amount_sats));
        }
        builder
            .fee_rate(fee_rate)
            .set_exact_sequence(bdk_wallet::bitcoin::Sequence::from_consensus(0xFFFF_FFFD));
        let psbt = builder.finish().map_err(|e| {
            let text = e.to_string();
            if text.to_lowercase().contains("insufficient") {
                BitcoinError::InsufficientFunds
            } else {
                BitcoinError::Engine(text)
            }
        })?;
        let used: std::collections::BTreeSet<OutPoint> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|i| i.previous_output)
            .collect();
        if used != wanted || psbt.unsigned_tx.input.len() != wanted.len() {
            return Err(BitcoinError::Engine(
                "the built transaction does not spend exactly the selected inputs".to_owned(),
            ));
        }
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

    /// Recompute, from the PSBT bytes alone, which outputs it spends, what it pays and where, and the
    /// fee. Used to check a reviewed intent against the transaction that would really be signed.
    pub fn describe_psbt(&self, psbt_bytes: &[u8]) -> Result<PsbtSummary, BitcoinError> {
        let psbt = bdk_wallet::bitcoin::psbt::Psbt::deserialize(psbt_bytes)
            .map_err(|e| BitcoinError::Engine(e.to_string()))?;
        let network = self.descriptors.network.network();
        let mut inputs = Vec::new();
        let mut total_in: u64 = 0;
        for (index, txin) in psbt.unsigned_tx.input.iter().enumerate() {
            let data = psbt
                .inputs
                .get(index)
                .ok_or_else(|| BitcoinError::Engine("psbt input data missing".to_owned()))?;
            let value = if let Some(utxo) = &data.witness_utxo {
                utxo.value.to_sat()
            } else if let Some(prev) = &data.non_witness_utxo {
                prev.output
                    .get(txin.previous_output.vout as usize)
                    .map(|o| o.value.to_sat())
                    .ok_or_else(|| {
                        BitcoinError::Engine("psbt previous output missing".to_owned())
                    })?
            } else {
                return Err(BitcoinError::Engine(
                    "psbt input without previous output data".to_owned(),
                ));
            };
            total_in = total_in
                .checked_add(value)
                .ok_or_else(|| BitcoinError::Engine("input total overflows".to_owned()))?;
            inputs.push(PsbtInputInfo {
                txid: txin.previous_output.txid.to_string(),
                vout: txin.previous_output.vout,
                value_sats: value,
            });
        }
        let mut outputs = Vec::new();
        let mut total_out: u64 = 0;
        for out in &psbt.unsigned_tx.output {
            let sats = out.value.to_sat();
            total_out = total_out
                .checked_add(sats)
                .ok_or_else(|| BitcoinError::Engine("output total overflows".to_owned()))?;
            let own = self.wallet.derivation_of_spk(out.script_pubkey.clone());
            outputs.push(PsbtOutputInfo {
                script_pubkey_hex: out.script_pubkey.to_hex_string(),
                address: Address::from_script(&out.script_pubkey, network)
                    .ok()
                    .map(|a| a.to_string()),
                value_sats: sats,
                is_mine: own.is_some(),
                is_change: matches!(own, Some((KeychainKind::Internal, _))),
            });
        }
        let fee_sats = total_in
            .checked_sub(total_out)
            .ok_or_else(|| BitcoinError::Engine("outputs exceed inputs".to_owned()))?;
        Ok(PsbtSummary {
            inputs,
            outputs,
            total_in_sats: total_in,
            total_out_sats: total_out,
            fee_sats,
        })
    }
}

/// Deterministic fixtures for tests. Compiled only with the `test-support` feature: they put synthetic,
/// unsigned-prevout transactions into the wallet's view, so offline tests can have UTXOs without a node.
#[cfg(feature = "test-support")]
impl BitcoinEngine {
    fn test_tx(
        &self,
        tag: u8,
        outputs: Vec<(bdk_wallet::bitcoin::ScriptBuf, u64)>,
        spend: Vec<OutPoint>,
    ) -> bdk_wallet::bitcoin::Transaction {
        use bdk_wallet::bitcoin::{ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        let inputs = if spend.is_empty() {
            let mut bytes = [0u8; 32];
            bytes.fill(tag);
            vec![OutPoint::new(
                bdk_wallet::bitcoin::Txid::from_raw_hash(
                    bdk_wallet::bitcoin::hashes::Hash::from_byte_array(bytes),
                ),
                u32::from(tag),
            )]
        } else {
            spend
        };
        Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: inputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .into_iter()
                .map(|(script_pubkey, sats)| TxOut {
                    value: Amount::from_sat(sats),
                    script_pubkey,
                })
                .collect(),
        }
    }

    /// Pay `amounts` (satoshis) to the wallet's external addresses `0..n` in one synthetic transaction;
    /// confirmed in a new block on top of the current tip, or unconfirmed. Returns the txid.
    pub fn fund_for_test(&mut self, tag: u8, amounts: &[u64], confirmed: bool) -> String {
        let outputs = amounts
            .iter()
            .enumerate()
            .map(|(i, sats)| {
                let spk = self
                    .wallet
                    .peek_address(KeychainKind::External, i as u32)
                    .address
                    .script_pubkey();
                (spk, *sats)
            })
            .collect();
        let tx = self.test_tx(tag, outputs, Vec::new());
        self.apply_test_tx(tx, confirmed)
    }

    /// Pay `sats` to an arbitrary script (a foreign recipient), spending `spend` (an outpoint the wallet
    /// owns): the way a wallet output becomes spent on-chain without this wallet's involvement.
    pub fn spend_for_test(&mut self, spend: &[(String, u32)], confirmed: bool) -> String {
        let spend: Vec<OutPoint> = spend
            .iter()
            .map(|(t, v)| parse_outpoint(t, *v).unwrap_or_else(|_| OutPoint::null()))
            .collect();
        let foreign = bdk_wallet::bitcoin::ScriptBuf::new_op_return([0x42u8; 4]);
        let tx = self.test_tx(0, vec![(foreign, 0)], spend);
        self.apply_test_tx(tx, confirmed)
    }

    /// Apply a signed transaction the wallet itself produced, the way a synchronisation would show it:
    /// unconfirmed, or confirmed in a new block on top of the tip. Returns the txid.
    pub fn ingest_for_test(&mut self, raw: &[u8], confirmed: bool) -> Result<String, BitcoinError> {
        let tx: bdk_wallet::bitcoin::Transaction = bdk_wallet::bitcoin::consensus::deserialize(raw)
            .map_err(|e| BitcoinError::Engine(e.to_string()))?;
        Ok(self.apply_test_tx(tx, confirmed))
    }

    /// Mine `n` empty blocks on top of the tip (raises confirmations).
    pub fn mine_for_test(&mut self, n: u32) {
        for _ in 0..n {
            self.apply_test_block(Vec::new());
        }
    }

    fn apply_test_tx(&mut self, tx: bdk_wallet::bitcoin::Transaction, confirmed: bool) -> String {
        let txid = tx.compute_txid().to_string();
        if confirmed {
            self.apply_test_block(vec![tx]);
        } else {
            self.wallet.apply_unconfirmed_txs([(tx, 1_700_000_000u64)]);
        }
        let _ = self.persist();
        txid
    }

    fn apply_test_block(&mut self, txdata: Vec<bdk_wallet::bitcoin::Transaction>) {
        use bdk_wallet::bitcoin::block::{Header, Version};
        use bdk_wallet::bitcoin::{Block, CompactTarget, TxMerkleNode};
        let tip = self.wallet.latest_checkpoint();
        let height = tip.height() + 1;
        let block = Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: tip.hash(),
                merkle_root: TxMerkleNode::from_raw_hash(
                    bdk_wallet::bitcoin::hashes::Hash::all_zeros(),
                ),
                time: 1_700_000_000 + height,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: height,
            },
            txdata,
        };
        let _ = self.wallet.apply_block(&block, height);
        let _ = self.persist();
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
