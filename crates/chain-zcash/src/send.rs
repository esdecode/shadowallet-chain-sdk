//! Proposals (ZIP-317 fees), signing with the unified spending key, proving (Orchard: Halo 2, no trusted-setup
//! parameters) and broadcast. Sapling uses the official hash-verified bundled proving parameters.

use std::sync::LazyLock;
use zcash_client_backend::data_api::wallet::{
    ConfirmationsPolicy, SpendingKeys, create_proposed_transactions,
    propose_standard_transfer_to_address,
};
use zcash_client_backend::data_api::{InputSource, WalletRead};
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::proto::service::RawTransaction;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_keys::address::Address;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use crate::wallet::{Client, Db};
use crate::{ZcashError, ZcashWallet};

// Parse and verify the official parameters once, on the first signing operation.
// No custom prover or placeholder proof is used for either shielded pool.
static SAPLING_PROVER: LazyLock<LocalTxProver> = LazyLock::new(LocalTxProver::bundled);

/// A built (unsigned) proposal and what the user reviews.
pub struct PreparedSend {
    proposal: Proposal<StandardFeeRule, <Db as InputSource>::NoteRef>,
    pub to: String,
    pub amount: u64,
    /// ZIP-317 conventional fee in zatoshi.
    pub fee: u64,
    pub steps: usize,
    /// True when the recipient address has a shielded (Orchard) receiver the funds will go to.
    pub shielded_recipient: bool,
    pub has_memo: bool,
    /// The network and account (viewing key) the proposal was built from.
    net: crate::ZcashNet,
    account_key: String,
    /// See [`PreparedSend::commitment`].
    commitment: [u8; 32],
}

impl PreparedSend {
    /// SHA-256 over what is decided at preparation and then signed: network, account and the canonical protobuf
    /// encoding of the whole proposal (payment request with recipient, amount and memo; selected inputs; change outputs
    /// and pools; fee; anchor and target heights). An approval must name this value.
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    fn digest(
        net: crate::ZcashNet,
        account_key: &str,
        proposal: &Proposal<StandardFeeRule, <Db as InputSource>::NoteRef>,
    ) -> [u8; 32] {
        use prost::Message as _;
        let body =
            zcash_client_backend::proto::proposal::Proposal::from_standard_proposal(proposal)
                .encode_to_vec();
        intent_digest(&[net.name.as_bytes(), account_key.as_bytes(), &body])
    }
}

/// Domain-separated, length-prefixed SHA-256: no two different part lists hash the same bytes.
fn intent_digest(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(b"shadowallet-zcash-intent-v1");
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// What a successful [`sign_and_broadcast`] did, with the real time each stage took.
#[derive(Clone, Debug)]
pub struct SendReport {
    pub txids: Vec<String>,
    /// Key derivation, proof generation and signing (the reference builder does the last two in one call).
    pub prove_sign_ms: u64,
    /// Handing the signed bytes to the server and receiving its answer.
    pub submit_ms: u64,
}

/// Build a proposal paying `amount` zatoshi to `to` (a unified, or transparent address; the memo is only allowed for
/// shielded recipients). The reference builder selects the recipient pool and computes ZIP-317 fees.
pub fn prepare_send(
    w: &mut ZcashWallet,
    to: &str,
    amount: u64,
    memo: Option<&str>,
) -> Result<PreparedSend, ZcashError> {
    if !w.net.signing_enabled() {
        return Err(ZcashError::Send("mainnet signing is disabled".to_owned()));
    }
    let params = w.net.params();
    let address = Address::decode(&params, to.trim())
        .ok_or_else(|| ZcashError::Address("not a valid address for this network".to_owned()))?;
    let value =
        Zatoshis::from_u64(amount).map_err(|_| ZcashError::Send("invalid amount".to_owned()))?;
    if amount == 0 {
        return Err(ZcashError::Send(
            "the amount must be greater than zero".to_owned(),
        ));
    }
    let memo_bytes = match memo.filter(|m| !m.is_empty()) {
        None => None,
        Some(m) => Some(
            MemoBytes::from_bytes(m.as_bytes())
                .map_err(|_| ZcashError::Send("the memo is longer than 512 bytes".to_owned()))?,
        ),
    };
    let change = change_pool(
        w.net,
        w.db.chain_height()
            .map_err(|e| ZcashError::Wallet(format!("{e:?}")))?
            .ok_or_else(|| ZcashError::Send("synchronize before preparing a payment".to_owned()))?,
    );
    let proposal = propose_standard_transfer_to_address::<Db, _, std::convert::Infallible>(
        &mut w.db,
        &params,
        StandardFeeRule::Zip317,
        w.account,
        ConfirmationsPolicy::default(),
        &address,
        value,
        memo_bytes.clone(),
        None,
        change,
        None,
        None,
    )
    .map_err(|e| ZcashError::Send(format!("{e:?}")))?;
    let mut fee = 0u64;
    for step in proposal.steps() {
        fee += u64::from(step.balance().fee_required());
    }
    let shielded_recipient = match &address {
        Address::Unified(ua) => ua.orchard().is_some() || ua.sapling().is_some(),
        Address::Sapling(_) => true,
        _ => false,
    };
    if memo_bytes.is_some() && !shielded_recipient {
        return Err(ZcashError::Send(
            "a memo can only be sent to a shielded address".to_owned(),
        ));
    }
    let account_key = account_key(w)?;
    let commitment = PreparedSend::digest(w.net, &account_key, &proposal);
    Ok(PreparedSend {
        net: w.net,
        account_key,
        commitment,
        steps: proposal.steps().len(),
        proposal,
        to: to.trim().to_owned(),
        amount,
        fee,
        shielded_recipient,
        has_memo: memo_bytes.is_some(),
    })
}

fn account_key(w: &ZcashWallet) -> Result<String, ZcashError> {
    w.ufvk
        .encode(&w.net.params())
        .map_err(|e| ZcashError::Wallet(format!("{e:?}")))
}

fn change_pool(net: crate::ZcashNet, height: BlockHeight) -> ShieldedPool {
    if net.params().is_nu_active(NetworkUpgrade::Nu6_3, height) {
        ShieldedPool::Ironwood
    } else {
        ShieldedPool::Orchard
    }
}

/// Create (prove and sign) the transactions of a prepared proposal and broadcast them. `seed` is the wallet seed
/// (scoped, from the vault); the spending key is derived here and dropped at the end.
///
/// A transport failure after signing is [`ZcashError::BroadcastUncertain`] and a refusal by the server is
/// [`ZcashError::BroadcastRejected`]; both carry the txid.
pub async fn sign_and_broadcast(
    w: &mut ZcashWallet,
    client: &mut Client,
    seed: &[u8],
    account_index: u32,
    prepared: PreparedSend,
) -> Result<SendReport, ZcashError> {
    if !w.net.signing_enabled() {
        return Err(ZcashError::Send("mainnet signing is disabled".to_owned()));
    }
    let params = w.net.params();
    // a proposal is only good for the exact network and account it was built from, and only unmodified
    if prepared.net != w.net || prepared.account_key != account_key(w)? {
        return Err(ZcashError::Send(
            "the prepared payment belongs to another wallet or network".to_owned(),
        ));
    }
    if PreparedSend::digest(w.net, &prepared.account_key, &prepared.proposal) != prepared.commitment
    {
        return Err(ZcashError::Send(
            "the prepared payment no longer matches its commitment".to_owned(),
        ));
    }
    let started = std::time::Instant::now();
    let usk = crate::account::spending_key(w.net, seed, account_index)?;
    // the key must belong to the account the proposal was built for
    if usk.to_unified_full_viewing_key().encode(&params) != w.ufvk.encode(&params) {
        return Err(ZcashError::Send(
            "the seed does not match this wallet's account".to_owned(),
        ));
    }
    let mut rng = rand_core::UnwrapErr(rand::rngs::SysRng);
    let txids = create_proposed_transactions::<
        Db,
        _,
        std::convert::Infallible,
        StandardFeeRule,
        std::convert::Infallible,
        _,
    >(
        &mut w.db,
        &params,
        &zcash_client_sqlite::util::SystemClock,
        &mut rng,
        &*SAPLING_PROVER,
        &*SAPLING_PROVER,
        &SpendingKeys::from_unified_spending_key(usk),
        OvkPolicy::Sender,
        &prepared.proposal,
        None,
    )
    .map_err(|e| ZcashError::Send(format!("{e:?}")))?;
    let prove_sign_ms = started.elapsed().as_millis() as u64;
    let submitting = std::time::Instant::now();
    let mut out = Vec::new();
    for txid in txids {
        let tx = w
            .db
            .get_transaction(txid)
            .map_err(|e| ZcashError::Wallet(format!("{e:?}")))?
            .ok_or_else(|| {
                ZcashError::Send("the created transaction is missing from the wallet".to_owned())
            })?;
        let mut data = Vec::new();
        tx.write(&mut data)
            .map_err(|e| ZcashError::Send(format!("{e}")))?;
        let response = client
            .send_transaction(RawTransaction { data, height: 0 })
            .await
            .map_err(|e| ZcashError::BroadcastUncertain {
                txid: txid.to_string(),
                reason: e.to_string(),
            })?
            .into_inner();
        if response.error_code != 0 {
            return Err(ZcashError::BroadcastRejected {
                txid: txid.to_string(),
                code: response.error_code,
                reason: response.error_message,
            });
        }
        out.push(txid.to_string());
    }
    Ok(SendReport {
        txids: out,
        prove_sign_ms,
        submit_ms: submitting.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn post_upgrade_change_uses_the_supported_ironwood_pool() {
        use zcash_protocol::{ShieldedPool, consensus::BlockHeight};
        assert_eq!(
            super::change_pool(crate::TESTNET, BlockHeight::from_u32(4_133_999)),
            ShieldedPool::Orchard
        );
        assert_eq!(
            super::change_pool(crate::TESTNET, BlockHeight::from_u32(4_134_000)),
            ShieldedPool::Ironwood
        );
    }
    #[test]
    fn the_intent_digest_changes_with_every_part_and_with_part_boundaries() {
        use super::intent_digest;
        let base = intent_digest(&[b"zcash-testnet", b"account", b"proposal"]);
        assert_eq!(
            base,
            intent_digest(&[b"zcash-testnet", b"account", b"proposal"])
        );
        for other in [
            intent_digest(&[b"zcash-mainnet", b"account", b"proposal"]),
            intent_digest(&[b"zcash-testnet", b"account2", b"proposal"]),
            intent_digest(&[b"zcash-testnet", b"account", b"proposaL"]),
            intent_digest(&[b"zcash-testnet", b"accountproposal", b""]),
        ] {
            assert_ne!(base, other);
        }
    }
    #[test]
    fn official_bundled_sapling_parameters_load_with_hash_verification() {
        let _ = super::SAPLING_PROVER.verifying_keys();
    }
}
