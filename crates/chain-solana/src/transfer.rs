//! Transfer preparation, message inspection and intent verification.
//!
//! Supported (allowlisted) instructions:
//! * System `Transfer`
//! * Associated Token Account `CreateIdempotent`
//! * SPL Token / Token-2022 `TransferChecked` (extension-free mints only)
//!
//! Anything else is rejected, both when preparing and again immediately
//! before signing ([`PreparedTransfer::verify`]).

use crate::error::SolanaError;
use crate::message::{AccountMeta, Instruction, Message};
use crate::network::SolanaNetwork;
use crate::pubkey::{
    ASSOCIATED_TOKEN_PROGRAM, Pubkey, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
    associated_token_address,
};
use crate::rpc::SolanaRpc;

const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;
const SYSTEM_TRANSFER: u32 = 2;
const TOKEN_TRANSFER_CHECKED: u8 = 12;
const ATA_CREATE_IDEMPOTENT: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferKind {
    Native {
        lamports: u64,
    },
    Spl {
        mint: Pubkey,
        amount: u64,
        decimals: u8,
        token_program: Pubkey,
        source_ata: Pubkey,
        dest_ata: Pubkey,
        create_dest_ata: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferIntent {
    pub network: SolanaNetwork,
    pub from: Pubkey,
    /// Recipient wallet (owner) address, never a token account.
    pub to: Pubkey,
    pub kind: TransferKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedInstruction {
    SystemTransfer {
        from: Pubkey,
        to: Pubkey,
        lamports: u64,
    },
    CreateAta {
        payer: Pubkey,
        ata: Pubkey,
        owner: Pubkey,
        mint: Pubkey,
        token_program: Pubkey,
    },
    TokenTransferChecked {
        source: Pubkey,
        mint: Pubkey,
        destination: Pubkey,
        authority: Pubkey,
        amount: u64,
        decimals: u8,
        token_program: Pubkey,
    },
}

fn unsupported(what: impl Into<String>) -> SolanaError {
    SolanaError::UnsupportedInstruction(what.into())
}

/// Decode a serialized legacy message into allowlisted instructions only.
pub fn inspect_message(bytes: &[u8]) -> Result<(Message, Vec<DecodedInstruction>), SolanaError> {
    let message = Message::parse(bytes)?;
    if message.num_required_signatures != 1 {
        return Err(unsupported("exactly one signer is required"));
    }
    if message.instructions.is_empty() || message.instructions.len() > 2 {
        return Err(unsupported("unexpected instruction count"));
    }
    let key = |i: u8| message.account_keys[usize::from(i)];
    let mut decoded = Vec::new();
    for ix in &message.instructions {
        let program = key(ix.program_id_index);
        let acct = |n: usize| -> Result<(usize, Pubkey), SolanaError> {
            let index = usize::from(*ix.accounts.get(n).ok_or_else(|| unsupported("accounts"))?);
            Ok((index, message.account_keys[index]))
        };
        if program == SYSTEM_PROGRAM {
            if ix.data.len() != 12
                || ix.data[..4] != SYSTEM_TRANSFER.to_le_bytes()
                || ix.accounts.len() != 2
            {
                return Err(unsupported("system program: only Transfer is allowed"));
            }
            let (from_i, from) = acct(0)?;
            let (to_i, to) = acct(1)?;
            if !message.is_signer(from_i)
                || !message.is_writable(from_i)
                || !message.is_writable(to_i)
            {
                return Err(unsupported("system transfer account flags"));
            }
            let mut lamports = [0u8; 8];
            lamports.copy_from_slice(&ix.data[4..12]);
            decoded.push(DecodedInstruction::SystemTransfer {
                from,
                to,
                lamports: u64::from_le_bytes(lamports),
            });
        } else if program == *TOKEN_PROGRAM || program == *TOKEN_2022_PROGRAM {
            if ix.data.len() != 10 || ix.data[0] != TOKEN_TRANSFER_CHECKED || ix.accounts.len() != 4
            {
                return Err(unsupported(
                    "token program: only TransferChecked is allowed",
                ));
            }
            let (src_i, source) = acct(0)?;
            let (_, mint) = acct(1)?;
            let (dst_i, destination) = acct(2)?;
            let (auth_i, authority) = acct(3)?;
            if !message.is_writable(src_i)
                || !message.is_writable(dst_i)
                || !message.is_signer(auth_i)
            {
                return Err(unsupported("token transfer account flags"));
            }
            let mut amount = [0u8; 8];
            amount.copy_from_slice(&ix.data[1..9]);
            decoded.push(DecodedInstruction::TokenTransferChecked {
                source,
                mint,
                destination,
                authority,
                amount: u64::from_le_bytes(amount),
                decimals: ix.data[9],
                token_program: program,
            });
        } else if program == *ASSOCIATED_TOKEN_PROGRAM {
            if ix.data != [ATA_CREATE_IDEMPOTENT] || ix.accounts.len() != 6 {
                return Err(unsupported(
                    "associated token program: only CreateIdempotent",
                ));
            }
            let (payer_i, payer) = acct(0)?;
            let (ata_i, ata) = acct(1)?;
            let (_, owner) = acct(2)?;
            let (_, mint) = acct(3)?;
            let (_, system) = acct(4)?;
            let (_, token_program) = acct(5)?;
            if system != SYSTEM_PROGRAM
                || !(token_program == *TOKEN_PROGRAM || token_program == *TOKEN_2022_PROGRAM)
                || !message.is_signer(payer_i)
                || !message.is_writable(ata_i)
            {
                return Err(unsupported("create ata accounts"));
            }
            if ata != associated_token_address(&owner, &mint, &token_program)? {
                return Err(unsupported("associated token address mismatch"));
            }
            decoded.push(DecodedInstruction::CreateAta {
                payer,
                ata,
                owner,
                mint,
                token_program,
            });
        } else {
            return Err(unsupported(format!("program {program}")));
        }
    }
    Ok((message, decoded))
}

fn system_transfer_ix(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = SYSTEM_TRANSFER.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data,
    }
}

fn create_ata_ix(
    payer: &Pubkey,
    ata: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    program: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: *ASSOCIATED_TOKEN_PROGRAM,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*ata, false),
            AccountMeta::readonly(*owner, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::readonly(SYSTEM_PROGRAM, false),
            AccountMeta::readonly(*program, false),
        ],
        data: vec![ATA_CREATE_IDEMPOTENT],
    }
}

fn transfer_checked_ix(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
    program: &Pubkey,
) -> Instruction {
    let mut data = vec![TOKEN_TRANSFER_CHECKED];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::readonly(*authority, true),
        ],
        data,
    }
}

impl TransferIntent {
    fn expected(&self) -> Result<Vec<DecodedInstruction>, SolanaError> {
        Ok(match &self.kind {
            TransferKind::Native { lamports } => vec![DecodedInstruction::SystemTransfer {
                from: self.from,
                to: self.to,
                lamports: *lamports,
            }],
            TransferKind::Spl {
                mint,
                amount,
                decimals,
                token_program,
                source_ata,
                dest_ata,
                create_dest_ata,
            } => {
                if *source_ata != associated_token_address(&self.from, mint, token_program)?
                    || *dest_ata != associated_token_address(&self.to, mint, token_program)?
                {
                    return Err(SolanaError::UnsupportedToken(
                        "token account is not the associated account".into(),
                    ));
                }
                let mut list = Vec::new();
                if *create_dest_ata {
                    list.push(DecodedInstruction::CreateAta {
                        payer: self.from,
                        ata: *dest_ata,
                        owner: self.to,
                        mint: *mint,
                        token_program: *token_program,
                    });
                }
                list.push(DecodedInstruction::TokenTransferChecked {
                    source: *source_ata,
                    mint: *mint,
                    destination: *dest_ata,
                    authority: self.from,
                    amount: *amount,
                    decimals: *decimals,
                    token_program: *token_program,
                });
                list
            }
        })
    }
}

/// A fully prepared, reviewable, not-yet-signed transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTransfer {
    pub intent: TransferIntent,
    pub message: Message,
    pub message_bytes: Vec<u8>,
    pub fee_lamports: u64,
    pub last_valid_block_height: u64,
}

impl PreparedTransfer {
    /// Re-derive everything from the exact bytes that will be signed and
    /// compare with the reviewed intent. Fails closed on any difference:
    /// recipient, amount, mint, token program, fee payer, extra instructions.
    pub fn verify(&self) -> Result<(), SolanaError> {
        let (message, decoded) = inspect_message(&self.message_bytes)?;
        if message != self.message {
            return Err(SolanaError::SigningRefused(
                "message does not match prepared form".into(),
            ));
        }
        if message.fee_payer() != Some(&self.intent.from) {
            return Err(SolanaError::SigningRefused(
                "fee payer is not the sender".into(),
            ));
        }
        if decoded != self.intent.expected()? {
            return Err(SolanaError::SigningRefused(
                "instructions do not match the reviewed intent".into(),
            ));
        }
        Ok(())
    }

    pub async fn is_expired(&self, rpc: &SolanaRpc) -> Result<bool, SolanaError> {
        Ok(rpc.get_block_height().await? > self.last_valid_block_height)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransfer {
    pub signature: String,
    pub raw: Vec<u8>,
}

fn check_amount_policy(amount: u64) -> Result<(), SolanaError> {
    if amount == 0 {
        return Err(SolanaError::InvalidTransaction(
            "amount must be positive".into(),
        ));
    }
    Ok(())
}

async fn finish(
    rpc: &SolanaRpc,
    intent: TransferIntent,
    instructions: Vec<Instruction>,
) -> Result<PreparedTransfer, SolanaError> {
    let (blockhash, last_valid_block_height) = rpc.get_latest_blockhash().await?;
    let message = Message::new(&intent.from, &instructions, blockhash)?;
    let message_bytes = message.serialize();
    let fee_lamports = rpc
        .get_fee_for_message(&message_bytes)
        .await?
        .ok_or(SolanaError::Expired)?;
    let prepared = PreparedTransfer {
        intent,
        message,
        message_bytes,
        fee_lamports,
        last_valid_block_height,
    };
    prepared.verify()?;
    Ok(prepared)
}

/// Check that the sender can pay `outgoing + fee` and stays rent-exempt (or
/// is emptied completely).
async fn check_sender_funds(
    rpc: &SolanaRpc,
    from: &Pubkey,
    outgoing: u64,
    fee: u64,
) -> Result<(), SolanaError> {
    let balance = rpc.get_balance(from).await?;
    let need = outgoing
        .checked_add(fee)
        .ok_or_else(|| SolanaError::InsufficientFunds("overflow".into()))?;
    if balance < need {
        return Err(SolanaError::InsufficientFunds(format!(
            "balance {balance} lamports, need {need}"
        )));
    }
    let rent0 = rpc.get_minimum_balance_for_rent_exemption(0).await?;
    let remaining = balance - need;
    if remaining != 0 && remaining < rent0 {
        return Err(SolanaError::InsufficientFunds(
            "transfer would leave the account below the rent-exempt minimum".into(),
        ));
    }
    Ok(())
}

pub async fn prepare_native_transfer(
    rpc: &SolanaRpc,
    from: Pubkey,
    to: Pubkey,
    lamports: u64,
) -> Result<PreparedTransfer, SolanaError> {
    check_amount_policy(lamports)?;
    rpc.verify_network().await?;
    let rent0 = rpc.get_minimum_balance_for_rent_exemption(0).await?;
    if lamports < rent0 && rpc.get_balance(&to).await? == 0 {
        return Err(SolanaError::InvalidTransaction(format!(
            "recipient is empty; first transfer must be at least {rent0} lamports"
        )));
    }
    let intent = TransferIntent {
        network: rpc.network(),
        from,
        to,
        kind: TransferKind::Native { lamports },
    };
    let prepared = finish(rpc, intent, vec![system_transfer_ix(&from, &to, lamports)]).await?;
    check_sender_funds(rpc, &from, lamports, prepared.fee_lamports).await?;
    Ok(prepared)
}

fn token_program_for(owner: &Pubkey) -> Result<Pubkey, SolanaError> {
    if owner == &*TOKEN_PROGRAM || owner == &*TOKEN_2022_PROGRAM {
        Ok(*owner)
    } else {
        Err(SolanaError::UnsupportedToken(
            "account is not owned by a token program".into(),
        ))
    }
}

pub async fn prepare_spl_transfer(
    rpc: &SolanaRpc,
    from: Pubkey,
    to: Pubkey,
    mint: Pubkey,
    amount: u64,
) -> Result<PreparedTransfer, SolanaError> {
    check_amount_policy(amount)?;
    rpc.verify_network().await?;

    let mint_account = rpc
        .get_account_info(&mint)
        .await?
        .ok_or_else(|| SolanaError::UnsupportedToken("mint account not found".into()))?;
    let token_program = token_program_for(&mint_account.owner)?;
    if mint_account.data.len() != MINT_LEN {
        return Err(SolanaError::UnsupportedToken(
            "mint has Token-2022 extensions, which are not supported".into(),
        ));
    }
    if mint_account.data[45] != 1 {
        return Err(SolanaError::UnsupportedToken(
            "mint is not initialized".into(),
        ));
    }
    let decimals = mint_account.data[44];

    let source_ata = associated_token_address(&from, &mint, &token_program)?;
    let dest_ata = associated_token_address(&to, &mint, &token_program)?;

    let source = rpc.get_account_info(&source_ata).await?.ok_or_else(|| {
        SolanaError::InsufficientFunds("sender has no token account for this mint".into())
    })?;
    let source_amount = validate_token_account(&source, &token_program, &mint, &from)?;
    if source_amount < amount {
        return Err(SolanaError::InsufficientFunds(format!(
            "token balance {source_amount}, need {amount}"
        )));
    }

    let create_dest_ata = match rpc.get_account_info(&dest_ata).await? {
        None => true,
        Some(dest) => {
            validate_token_account(&dest, &token_program, &mint, &to)?;
            false
        }
    };

    let mut instructions = Vec::new();
    if create_dest_ata {
        instructions.push(create_ata_ix(&from, &dest_ata, &to, &mint, &token_program));
    }
    instructions.push(transfer_checked_ix(
        &source_ata,
        &mint,
        &dest_ata,
        &from,
        amount,
        decimals,
        &token_program,
    ));
    let intent = TransferIntent {
        network: rpc.network(),
        from,
        to,
        kind: TransferKind::Spl {
            mint,
            amount,
            decimals,
            token_program,
            source_ata,
            dest_ata,
            create_dest_ata,
        },
    };
    let prepared = finish(rpc, intent, instructions).await?;
    let ata_rent = if create_dest_ata {
        rpc.get_minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_LEN as u64)
            .await?
    } else {
        0
    };
    check_sender_funds(rpc, &from, ata_rent, prepared.fee_lamports).await?;
    Ok(prepared)
}

/// Validate a plain (extension-free) token account and return its amount.
fn validate_token_account(
    account: &crate::rpc::AccountInfo,
    token_program: &Pubkey,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Result<u64, SolanaError> {
    if &account.owner != token_program {
        return Err(SolanaError::UnsupportedToken(
            "token account has the wrong program".into(),
        ));
    }
    if account.data.len() != TOKEN_ACCOUNT_LEN {
        return Err(SolanaError::UnsupportedToken(
            "token account has extensions".into(),
        ));
    }
    if account.data[..32] != mint.0 {
        return Err(SolanaError::UnsupportedToken(
            "token account has the wrong mint".into(),
        ));
    }
    if account.data[32..64] != owner.0 {
        return Err(SolanaError::UnsupportedToken(
            "token account has the wrong owner".into(),
        ));
    }
    match account.data[108] {
        1 => {}
        2 => {
            return Err(SolanaError::UnsupportedToken(
                "token account is frozen".into(),
            ));
        }
        _ => {
            return Err(SolanaError::UnsupportedToken(
                "token account is not initialized".into(),
            ));
        }
    }
    let mut amount = [0u8; 8];
    amount.copy_from_slice(&account.data[64..72]);
    Ok(u64::from_le_bytes(amount))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn pk(n: u8) -> Pubkey {
        Pubkey([n; 32])
    }

    fn native_prepared(lamports: u64) -> PreparedTransfer {
        let (from, to) = (pk(1), pk(2));
        let message =
            Message::new(&from, &[system_transfer_ix(&from, &to, lamports)], [5; 32]).unwrap();
        PreparedTransfer {
            intent: TransferIntent {
                network: SolanaNetwork::Localnet,
                from,
                to,
                kind: TransferKind::Native { lamports },
            },
            message_bytes: message.serialize(),
            message,
            fee_lamports: 5000,
            last_valid_block_height: 100,
        }
    }

    fn spl_prepared(create: bool) -> PreparedTransfer {
        let (from, to, mint) = (pk(1), pk(2), pk(3));
        let program = *TOKEN_PROGRAM;
        let source = associated_token_address(&from, &mint, &program).unwrap();
        let dest = associated_token_address(&to, &mint, &program).unwrap();
        let mut ixs = Vec::new();
        if create {
            ixs.push(create_ata_ix(&from, &dest, &to, &mint, &program));
        }
        ixs.push(transfer_checked_ix(
            &source, &mint, &dest, &from, 250, 6, &program,
        ));
        let message = Message::new(&from, &ixs, [5; 32]).unwrap();
        PreparedTransfer {
            intent: TransferIntent {
                network: SolanaNetwork::Localnet,
                from,
                to,
                kind: TransferKind::Spl {
                    mint,
                    amount: 250,
                    decimals: 6,
                    token_program: program,
                    source_ata: source,
                    dest_ata: dest,
                    create_dest_ata: create,
                },
            },
            message_bytes: message.serialize(),
            message,
            fee_lamports: 5000,
            last_valid_block_height: 100,
        }
    }

    #[test]
    fn honest_transfers_verify() {
        native_prepared(1_000_000).verify().unwrap();
        spl_prepared(true).verify().unwrap();
        spl_prepared(false).verify().unwrap();
    }

    #[test]
    fn tampered_amount_or_recipient_is_refused() {
        // Replace the message with one for a different amount, keep the intent.
        let mut p = native_prepared(1_000_000);
        let other = native_prepared(9_000_000);
        p.message_bytes = other.message_bytes.clone();
        p.message = other.message;
        assert!(matches!(p.verify(), Err(SolanaError::SigningRefused(_))));

        let mut p = native_prepared(1_000_000);
        p.intent.to = pk(9);
        assert!(p.verify().is_err());

        let mut p = spl_prepared(true);
        if let TransferKind::Spl { amount, .. } = &mut p.intent.kind {
            *amount += 1;
        }
        assert!(p.verify().is_err());
    }

    #[test]
    fn wrong_mint_or_token_program_is_refused() {
        let mut p = spl_prepared(false);
        if let TransferKind::Spl { mint, .. } = &mut p.intent.kind {
            *mint = pk(4);
        }
        assert!(p.verify().is_err());

        // Same instructions under the Token-2022 program id do not match the
        // intent that declared the legacy program.
        let mut p = spl_prepared(false);
        if let TransferKind::Spl { token_program, .. } = &mut p.intent.kind {
            *token_program = *TOKEN_2022_PROGRAM;
        }
        assert!(p.verify().is_err());
    }

    #[test]
    fn modified_instruction_data_is_detected_by_inspection() {
        let p = native_prepared(10);
        // Flip the instruction discriminator (Transfer -> CreateAccount).
        let mut bytes = p.message_bytes.clone();
        let pos = bytes.len() - 12;
        bytes[pos] = 0;
        assert!(matches!(
            inspect_message(&bytes),
            Err(SolanaError::UnsupportedInstruction(_))
        ));
    }

    #[test]
    fn unknown_programs_and_extra_instructions_are_rejected() {
        let from = pk(1);
        let foreign = Instruction {
            program_id: pk(77),
            accounts: vec![AccountMeta::new(from, true)],
            data: vec![1, 2, 3],
        };
        let msg = Message::new(&from, std::slice::from_ref(&foreign), [0; 32]).unwrap();
        assert!(inspect_message(&msg.serialize()).is_err());

        // A legitimate transfer smuggling a second foreign instruction.
        let msg = Message::new(
            &from,
            &[system_transfer_ix(&from, &pk(2), 5), foreign],
            [0; 32],
        )
        .unwrap();
        assert!(inspect_message(&msg.serialize()).is_err());

        // SetAuthority / Approve style token instructions are not allowlisted.
        let program = *TOKEN_PROGRAM;
        let mut ix = transfer_checked_ix(&pk(3), &pk(4), &pk(5), &from, 1, 6, &program);
        ix.data[0] = 4; // Approve
        let msg = Message::new(&from, &[ix], [0; 32]).unwrap();
        assert!(inspect_message(&msg.serialize()).is_err());
    }

    #[test]
    fn non_associated_destination_is_refused() {
        let mut p = spl_prepared(false);
        if let TransferKind::Spl { dest_ata, .. } = &mut p.intent.kind {
            *dest_ata = pk(42);
        }
        assert!(p.verify().is_err());
    }

    #[test]
    fn multi_signer_messages_are_refused() {
        let (a, b) = (pk(1), pk(2));
        let ix = Instruction {
            program_id: SYSTEM_PROGRAM,
            accounts: vec![AccountMeta::new(a, true), AccountMeta::new(b, true)],
            data: {
                let mut d = SYSTEM_TRANSFER.to_le_bytes().to_vec();
                d.extend_from_slice(&1u64.to_le_bytes());
                d
            },
        };
        let msg = Message::new(&a, &[ix], [0; 32]).unwrap();
        assert!(inspect_message(&msg.serialize()).is_err());
    }
}
