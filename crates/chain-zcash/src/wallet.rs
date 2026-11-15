//! Wallet database, lightwalletd connection (network identity verified), synchronization, balances and addresses.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use secrecy::SecretVec;
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::data_api::chain::{BlockCache, BlockSource, error};
use zcash_client_backend::data_api::scanning::ScanRange;
use zcash_client_backend::data_api::{Account as _, AccountBirthday, WalletRead, WalletWrite};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{
    BlockId, ChainSpec, Empty, compact_tx_streamer_client::CompactTxStreamerClient,
};
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{BlockHeight, Network};

use crate::{ZcashError, ZcashNet};

/// The system RNG as an infallible RNG (a failing OS RNG is fatal for key material anyway).
pub type SysRng = rand_core::UnwrapErr<rand::rngs::SysRng>;

pub type Db = WalletDb<rusqlite::Connection, Network, SystemClock, SysRng>;
pub type Client = CompactTxStreamerClient<Channel>;

fn server(e: impl std::fmt::Display) -> ZcashError {
    ZcashError::Server(e.to_string())
}

fn wallet(e: impl std::fmt::Debug) -> ZcashError {
    ZcashError::Wallet(format!("{e:?}"))
}

/// In-memory compact block cache for one synchronization run (blocks are only needed until they are scanned).
#[derive(Default, Clone)]
pub struct MemBlockCache {
    blocks: Arc<Mutex<BTreeMap<u32, CompactBlock>>>,
}

/// The in-memory cache can only fail if its lock was poisoned by a panic.
#[derive(Debug, thiserror::Error)]
#[error("block cache unavailable")]
pub struct CacheError;

impl BlockSource for MemBlockCache {
    type Error = CacheError;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), error::Error<WalletErrT, Self::Error>>,
    {
        let blocks: Vec<CompactBlock> = {
            let guard = self
                .blocks
                .lock()
                .map_err(|_| error::Error::BlockSource(CacheError))?;
            let start = from_height.map(u32::from).unwrap_or(0);
            guard
                .range(start..)
                .map(|(_, b)| b.clone())
                .take(limit.unwrap_or(usize::MAX))
                .collect()
        };
        for b in blocks {
            with_block(b)?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for MemBlockCache {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        let guard = self.blocks.lock().map_err(|_| CacheError)?;
        Ok(guard
            .keys()
            .copied()
            .filter(|h| range.is_none_or(|r| r.block_range().contains(&BlockHeight::from_u32(*h))))
            .max()
            .map(BlockHeight::from_u32))
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let guard = self.blocks.lock().map_err(|_| CacheError)?;
        Ok(guard
            .values()
            .filter(|b| {
                range
                    .block_range()
                    .contains(&BlockHeight::from_u32(b.height as u32))
            })
            .cloned()
            .collect())
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        let mut guard = self.blocks.lock().map_err(|_| CacheError)?;
        for b in compact_blocks {
            guard.insert(b.height as u32, b);
        }
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        let mut guard = self.blocks.lock().map_err(|_| CacheError)?;
        guard.retain(|h, _| !range.block_range().contains(&BlockHeight::from_u32(*h)));
        Ok(())
    }
}

/// What a lightwalletd server reported about itself.
#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub chain_name: String,
    pub block_height: u32,
    pub sapling_activation_height: u32,
    pub vendor: String,
}

/// Connect to a lightwalletd server (`https://host:port`) and verify it serves the expected network: the chain
/// name must match and the Sapling activation height must be this network's.
pub async fn connect(net: ZcashNet, url: &str) -> Result<(Client, ServerInfo), ZcashError> {
    net.validate()?;
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(ZcashError::Server(
            "the server URL must be http(s)".to_owned(),
        ));
    }
    // Several TLS backends are present in the dependency graph; select ring explicitly (ignore "already set").
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut endpoint = Channel::from_shared(url.to_owned())
        .map_err(server)?
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(60));
    if url.starts_with("https://") {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .map_err(server)?;
    }
    let channel = endpoint.connect().await.map_err(server)?;
    let mut client = CompactTxStreamerClient::new(channel);
    let info = client
        .get_lightd_info(Empty {})
        .await
        .map_err(server)?
        .into_inner();
    if info.chain_name != net.chain_name
        || info.sapling_activation_height != u64::from(net.sapling_activation_height)
    {
        return Err(ZcashError::Network(format!(
            "the server serves chain {:?} (Sapling activation {}), not {}",
            info.chain_name, info.sapling_activation_height, net.name
        )));
    }
    // Metadata alone is insufficient: also require a known block from the expected chain.
    let checkpoint = client
        .get_tree_state(BlockId {
            height: u64::from(net.sapling_activation_height),
            hash: vec![],
        })
        .await
        .map_err(server)?
        .into_inner();
    if checkpoint.height != u64::from(net.sapling_activation_height)
        || checkpoint.hash != net.sapling_activation_hash
        || checkpoint.network != net.chain_name
    {
        return Err(ZcashError::Network(
            "the server's Sapling checkpoint does not match the expected chain".to_owned(),
        ));
    }
    let info = ServerInfo {
        chain_name: info.chain_name,
        block_height: info.block_height as u32,
        sapling_activation_height: info.sapling_activation_height as u32,
        vendor: info.vendor,
    };
    Ok((client, info))
}

pub async fn latest_height(client: &mut Client) -> Result<u32, ZcashError> {
    let b = client
        .get_latest_block(ChainSpec {})
        .await
        .map_err(server)?
        .into_inner();
    Ok(b.height as u32)
}

/// One Zcash account bound to its wallet database file.
pub struct ZcashWallet {
    pub net: ZcashNet,
    pub db: Db,
    pub db_path: PathBuf,
    pub account: AccountUuid,
    pub ufvk: UnifiedFullViewingKey,
}

/// Open (or create) the wallet database and the account for `seed`. A new account needs a birthday (the height
/// scanning starts from): `birthday_height` of `None` restores from Sapling activation. New wallets must explicitly provide a recent birthday.
pub async fn open_wallet(
    net: ZcashNet,
    db_path: &Path,
    seed: &[u8],
    account_index: u32,
    client: &mut Client,
    birthday_height: Option<u32>,
) -> Result<ZcashWallet, ZcashError> {
    net.validate()?;
    let params = net.params();
    let mut db: Db = WalletDb::for_path(
        db_path,
        params,
        SystemClock,
        rand_core::UnwrapErr(rand::rngs::SysRng),
    )
    .map_err(wallet)?;
    init_wallet_db(&mut db, Some(SecretVec::new(seed.to_vec()))).map_err(wallet)?;
    let ufvk = crate::account::full_viewing_key(net, seed, account_index)?;
    let account = match db.get_account_for_ufvk(&ufvk).map_err(wallet)? {
        Some(a) => a.id(),
        None => {
            if !db.get_account_ids().map_err(wallet)?.is_empty() {
                return Err(ZcashError::Wallet(
                    "this database belongs to a different seed, account or network".to_owned(),
                ));
            }
            let tip = latest_height(client).await?;
            let height = birthday_height
                .unwrap_or(net.sapling_activation_height)
                .max(net.sapling_activation_height);
            if height > tip {
                return Err(ZcashError::Wallet(
                    "restore height is above the server tip".to_owned(),
                ));
            }
            // the birthday needs the commitment tree state just before it
            let state = client
                .get_tree_state(BlockId {
                    height: u64::from(height.saturating_sub(1)),
                    hash: vec![],
                })
                .await
                .map_err(server)?
                .into_inner();
            let birthday = AccountBirthday::from_treestate(state, None)
                .map_err(|e| ZcashError::Wallet(format!("birthday: {e:?}")))?;
            // create_account chooses the next index, which is 0 in a fresh database.
            // Import the requested ZIP-32 index explicitly or account 1 would watch account 0.
            let (account, _usk) = db
                .import_account_hd(
                    &format!("account-{account_index}"),
                    &SecretVec::new(seed.to_vec()),
                    crate::account::account_id(account_index)?,
                    &birthday,
                    None,
                )
                .map_err(wallet)?;
            account.id()
        }
    };
    Ok(ZcashWallet {
        net,
        db,
        db_path: db_path.to_path_buf(),
        account,
        ufvk,
    })
}
