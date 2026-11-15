use crate::NanoError;
use crate::address::encode_address;
use crate::block::{BlockKind, StateBlock};
use crate::rpc::{AccountState, Receivable};

/// What the user must see and approve before anything is signed.
#[derive(Clone, Debug)]
pub struct Review {
    pub kind: BlockKind,
    pub account: String,
    pub counterparty: Option<String>,
    pub amount_raw: u128,
    pub balance_after_raw: u128,
    pub representative: String,
    pub previous: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Prepared {
    pub block: StateBlock,
    pub kind: BlockKind,
    pub review: Review,
}

fn build(
    kind: BlockKind,
    block: StateBlock,
    counterparty: Option<String>,
    amount: u128,
) -> Prepared {
    let review = Review {
        kind,
        account: encode_address(&block.account),
        counterparty,
        amount_raw: amount,
        balance_after_raw: block.balance,
        representative: encode_address(&block.representative),
        previous: block.previous,
    };
    Prepared {
        block,
        kind,
        review,
    }
}

/// Nano never builds on an unconfirmed own block: that would risk forking the account chain.
fn require_settled(state: &AccountState) -> Result<(), NanoError> {
    if state.frontier != state.confirmed_frontier {
        return Err(NanoError::Block(
            "account has a block that is not confirmed yet; wait for confirmation".into(),
        ));
    }
    Ok(())
}

/// A send block: previous = frontier, balance reduced by `amount`, link = recipient key. No fee exists in Nano.
pub fn prepare_send(
    state: &AccountState,
    account: [u8; 32],
    destination: [u8; 32],
    amount: u128,
) -> Result<Prepared, NanoError> {
    if !state.exists {
        return Err(NanoError::Block(
            "account is not open: it has nothing to send".into(),
        ));
    }
    require_settled(state)?;
    if amount == 0 {
        return Err(NanoError::Amount("amount must be greater than zero".into()));
    }
    let balance = state
        .balance
        .checked_sub(amount)
        .ok_or_else(|| NanoError::Amount("amount exceeds the balance".into()))?;
    let block = StateBlock {
        account,
        previous: state.frontier,
        representative: state.representative,
        balance,
        link: destination,
    };
    Ok(build(
        BlockKind::Send,
        block,
        Some(encode_address(&destination)),
        amount,
    ))
}

/// A receive block for a pending send, or the account's open block when it has no chain yet.
/// `open_representative` is only used for an open block; an existing chain keeps its representative.
pub fn prepare_receive(
    state: &AccountState,
    account: [u8; 32],
    open_representative: [u8; 32],
    receivable: &Receivable,
) -> Result<Prepared, NanoError> {
    if receivable.amount == 0 {
        return Err(NanoError::Amount("receivable amount is zero".into()));
    }
    let (kind, previous, representative, base) = if state.exists {
        require_settled(state)?;
        (
            BlockKind::Receive,
            state.frontier,
            state.representative,
            state.balance,
        )
    } else {
        (BlockKind::Open, [0u8; 32], open_representative, 0)
    };
    let balance = base
        .checked_add(receivable.amount)
        .ok_or_else(|| NanoError::Amount("balance overflow".into()))?;
    let block = StateBlock {
        account,
        previous,
        representative,
        balance,
        link: receivable.hash,
    };
    Ok(build(
        kind,
        block,
        receivable.source.clone(),
        receivable.amount,
    ))
}

/// A change block: same balance, new representative, zero link.
pub fn prepare_change(
    state: &AccountState,
    account: [u8; 32],
    representative: [u8; 32],
) -> Result<Prepared, NanoError> {
    if !state.exists {
        return Err(NanoError::Block("account is not open".into()));
    }
    require_settled(state)?;
    let block = StateBlock {
        account,
        previous: state.frontier,
        representative,
        balance: state.balance,
        link: [0u8; 32],
    };
    Ok(build(BlockKind::Change, block, None, 0))
}
