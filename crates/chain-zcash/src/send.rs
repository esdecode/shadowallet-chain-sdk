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
}

/// Build a proposal paying `amount` zatoshi to `to` (a unified, or transparent address; the memo is only allowed for
/// shielded recipients). The reference builder selects the recipient pool and computes ZIP-317 fees.
pub fn prepare_send(
    w: &mut ZcashWallet,
    to: &str,
    amount: u64,
    memo: Option<&str>,
) -> Result<PreparedSend, ZcashError> {
    if w.net != crate::TESTNET {
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
        ShieldedPool::Orchard,
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
    Ok(PreparedSend {
        steps: proposal.steps().len(),
        proposal,
        to: to.trim().to_owned(),
        amount,
        fee,
        shielded_recipient,
        has_memo: memo_bytes.is_some(),
    })
}

/// Create (prove and sign) the transactions of a prepared proposal and broadcast them. `seed` is the wallet seed
/// (scoped, from the vault); the spending key is derived here and dropped at the end. Returns the txids.
pub async fn sign_and_broadcast(
    w: &mut ZcashWallet,
    client: &mut Client,
    seed: &[u8],
    account_index: u32,
    prepared: PreparedSend,
) -> Result<Vec<String>, ZcashError> {
    if w.net != crate::TESTNET {
        return Err(ZcashError::Send("mainnet signing is disabled".to_owned()));
    }
    let params = w.net.params();
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
            .map_err(|e| ZcashError::Server(e.to_string()))?
            .into_inner();
        if response.error_code != 0 {
            return Err(ZcashError::Send(format!(
                "the server refused the transaction ({}): {}",
                response.error_code, response.error_message
            )));
        }
        out.push(txid.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn official_bundled_sapling_parameters_load_with_hash_verification() {
        let _ = super::SAPLING_PROVER.verifying_keys();
    }
}
