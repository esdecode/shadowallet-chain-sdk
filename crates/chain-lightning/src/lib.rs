//! Non-custodial Lightning foundation (no channels, no payments, no chain access yet).
//!
//! Built on the maintained Lightning Development Kit (`lightning` 0.2.8, `lightning-invoice` 0.34.2, both pinned exactly); no Lightning
//! or cryptographic primitive is implemented here. What exists and is tested:
//!
//! * [`parse_invoice`]: BOLT11 parsing with explicit **network isolation**: an invoice is only accepted for the network the caller
//!   expects, a mainnet invoice is never accepted for a test network and vice versa;
//! * [`derive_node_seed`] / [`node_id`]: a domain-separated (HKDF-SHA256) seed from the wallet seed, and the node public key as LDK's
//!   `KeysManager` computes it. The seed is zeroized and never leaves this process;
//! * [`MonitorStore`]: durable, atomic storage of opaque channel-monitor blobs that **refuses a stale write** (an older `update_id`
//!   can never replace a newer one) and fails closed on a damaged file.
//!
//! # What a recovery phrase can and cannot do
//!
//! The recovery phrase restores the node identity and on-chain keys. It does **not** restore channel state: a channel's latest
//! commitment and monitor exist only in the monitor store (and any backup the user makes). Restoring an OLD copy of that state and
//! broadcasting it is how funds are lost; the store therefore only ever moves forward and the phrase alone is never claimed
//! sufficient. See [`capabilities`] for everything that is not implemented.

use std::path::Path;
use std::str::FromStr;

use hkdf::Hkdf;
use lightning::bitcoin::hashes::Hash as _;
use lightning::sign::{KeysManager, NodeSigner, Recipient};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef, Currency};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Bitcoin networks Lightning can run on. Payments are not implemented on any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LnNetwork {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl LnNetwork {
    pub const fn is_mainnet(self) -> bool {
        matches!(self, Self::Bitcoin)
    }
    /// No payment code exists, so this is `false` everywhere; asked rather than assumed.
    pub const fn payments_enabled(self) -> bool {
        false
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LnError {
    #[error("invalid invoice: {0}")]
    Invoice(String),
    #[error("invoice is for {found:?}, expected {expected:?}")]
    WrongNetwork {
        expected: LnNetwork,
        found: LnNetwork,
    },
    #[error("unsupported invoice currency")]
    UnsupportedNetwork,
    #[error("seed material is too short (need at least 16 bytes)")]
    ShortSeed,
    #[error("node key derivation failed")]
    Key,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("the monitor database is damaged ({0}); nothing was changed")]
    Corrupt(String),
    #[error("stale channel state refused for {id}: stored update {stored}, attempted {attempted}")]
    Stale {
        id: String,
        stored: u64,
        attempted: u64,
    },
    #[error("conflicting data for {id} at update {update_id}")]
    Conflict { id: String, update_id: u64 },
}

fn db<E: std::fmt::Display>(e: E) -> LnError {
    LnError::Storage(e.to_string())
}

// ------------------------------------------------------------------------------------------------- invoices

/// What a wallet needs to show before anything is paid. Nothing is paid by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInvoice {
    pub network: LnNetwork,
    /// `None` for an "any amount" invoice.
    pub amount_msat: Option<u64>,
    pub payee_node_id: String,
    pub payment_hash: String,
    pub created_unix: u64,
    pub expiry_secs: u64,
    pub expired: bool,
    pub description: Option<String>,
    pub description_hash: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn network_of(c: Currency) -> Result<LnNetwork, LnError> {
    match c {
        Currency::Bitcoin => Ok(LnNetwork::Bitcoin),
        Currency::BitcoinTestnet => Ok(LnNetwork::Testnet),
        Currency::Signet => Ok(LnNetwork::Signet),
        Currency::Regtest => Ok(LnNetwork::Regtest),
        _ => Err(LnError::UnsupportedNetwork),
    }
}

/// Parses a BOLT11 invoice (signature and structure verified by LDK) and enforces network isolation.
pub fn parse_invoice(
    text: &str,
    expected: LnNetwork,
    now_unix: u64,
) -> Result<ParsedInvoice, LnError> {
    let trimmed = text.trim();
    let trimmed = trimmed.strip_prefix("lightning:").unwrap_or(trimmed);
    let invoice = Bolt11Invoice::from_str(trimmed).map_err(|e| LnError::Invoice(e.to_string()))?;
    let found = network_of(invoice.currency())?;
    if found != expected {
        return Err(LnError::WrongNetwork { expected, found });
    }
    let created = invoice.duration_since_epoch().as_secs();
    let expiry = invoice.expiry_time().as_secs();
    let (description, description_hash) = match invoice.description() {
        Bolt11InvoiceDescriptionRef::Direct(d) => (Some(d.to_string()), None),
        Bolt11InvoiceDescriptionRef::Hash(h) => (None, Some(hex(h.0.as_byte_array()))),
    };
    Ok(ParsedInvoice {
        network: found,
        amount_msat: invoice.amount_milli_satoshis(),
        payee_node_id: invoice.recover_payee_pub_key().to_string(),
        payment_hash: hex(invoice.payment_hash().as_byte_array()),
        created_unix: created,
        expiry_secs: expiry,
        expired: now_unix >= created.saturating_add(expiry),
        description,
        description_hash,
    })
}

// ------------------------------------------------------------------------------------------------- node identity

const HKDF_SALT: &[u8] = b"shadowallet/lightning/v1";

/// Domain-separated 32-byte seed for the Lightning node, derived from the wallet's master seed with HKDF-SHA256 (RFC 5869).
/// Different wallets and different `info` values give unrelated seeds; the result never equals the master seed.
pub fn derive_node_seed(master: &[u8]) -> Result<Zeroizing<[u8; 32]>, LnError> {
    if master.len() < 16 {
        return Err(LnError::ShortSeed);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(HKDF_SALT), master)
        .expand(b"node-seed", out.as_mut())
        .map_err(|_| LnError::Key)?;
    Ok(out)
}

/// The node public key (hex, 33 bytes compressed) LDK's `KeysManager` derives from `seed`. The start time only feeds per-channel
/// key uniqueness and does not influence the node key, so a fixed value is used here; a real node must pass a fresh value.
pub fn node_id(seed: &[u8; 32]) -> Result<String, LnError> {
    let keys = KeysManager::new(seed, 0, 0, true);
    let id = keys
        .get_node_id(Recipient::Node)
        .map_err(|()| LnError::Key)?;
    Ok(id.to_string())
}

// ------------------------------------------------------------------------------------------------- monitor store

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS monitor(
  id TEXT PRIMARY KEY,
  update_id INTEGER NOT NULL,
  data BLOB NOT NULL
) WITHOUT ROWID;
";
const SCHEMA_VERSION: &str = "1";

/// Durable store of opaque channel-monitor blobs, keyed by monitor id.
///
/// * every write is one `BEGIN IMMEDIATE` transaction with `synchronous=FULL`;
/// * a write whose `update_id` is lower than the stored one is refused ([`LnError::Stale`]); an equal `update_id` with different
///   bytes is refused ([`LnError::Conflict`]); an identical repeat is a no-op;
/// * `PRAGMA quick_check` runs at open; a damaged file is reported ([`LnError::Corrupt`]), never repaired or replaced.
pub struct MonitorStore {
    conn: Connection,
}

impl MonitorStore {
    pub fn open(path: &Path) -> Result<Self, LnError> {
        let conn = Connection::open(path).map_err(db)?;
        let check: String = conn
            .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))
            .map_err(|e| LnError::Corrupt(e.to_string()))?;
        if check != "ok" {
            return Err(LnError::Corrupt(check));
        }
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
            .map_err(db)?;
        conn.execute_batch(SCHEMA).map_err(db)?;
        let version: Option<String> = conn
            .query_row("SELECT v FROM meta WHERE k='schema'", [], |r| r.get(0))
            .optional()
            .map_err(db)?;
        match version.as_deref() {
            None => {
                conn.execute(
                    "INSERT INTO meta(k,v) VALUES('schema',?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(db)?;
            }
            Some(SCHEMA_VERSION) => {}
            Some(other) => {
                return Err(LnError::Storage(format!(
                    "unsupported monitor schema {other}"
                )));
            }
        }
        Ok(Self { conn })
    }

    /// Stores `data` as monitor `id` at `update_id` (see the type documentation for the refusal rules).
    pub fn put(&mut self, id: &str, update_id: u64, data: &[u8]) -> Result<(), LnError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let stored: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT update_id, data FROM monitor WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        if let Some((stored_id, stored_data)) = stored {
            let stored_id = u64::try_from(stored_id)
                .map_err(|_| LnError::Storage("negative update id".to_owned()))?;
            if update_id < stored_id {
                return Err(LnError::Stale {
                    id: id.to_owned(),
                    stored: stored_id,
                    attempted: update_id,
                });
            }
            if update_id == stored_id {
                return if stored_data == data {
                    Ok(())
                } else {
                    Err(LnError::Conflict {
                        id: id.to_owned(),
                        update_id,
                    })
                };
            }
        }
        let update = i64::try_from(update_id)
            .map_err(|_| LnError::Storage("update id too large".to_owned()))?;
        tx.execute(
            "INSERT INTO monitor(id, update_id, data) VALUES(?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET update_id=excluded.update_id, data=excluded.data",
            params![id, update, data],
        )
        .map_err(db)?;
        tx.commit().map_err(db)
    }

    pub fn get(&self, id: &str) -> Result<Option<(u64, Vec<u8>)>, LnError> {
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT update_id, data FROM monitor WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        Ok(row.map(|(u, d)| (u.unsigned_abs(), d)))
    }

    pub fn ids(&self) -> Result<Vec<String>, LnError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM monitor ORDER BY id")
            .map_err(db)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(db)?;
        rows.collect::<Result<_, _>>().map_err(db)
    }
}

// ------------------------------------------------------------------------------------------------- capabilities

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Implemented,
    NotImplemented,
}

#[derive(Debug, Clone, Copy)]
pub struct Capability {
    pub feature: &'static str,
    pub status: Status,
    pub reason: &'static str,
}

const fn c(feature: &'static str, status: Status, reason: &'static str) -> Capability {
    Capability {
        feature,
        status,
        reason,
    }
}

/// The complete feature list with its real status. Invoice parsing alone is not Lightning support.
pub const fn capabilities() -> [Capability; 12] {
    use Status::{Implemented, NotImplemented};
    [
        c(
            "BOLT11 invoice parsing with network isolation",
            Implemented,
            "LDK parser; wrong-network invoices refused",
        ),
        c(
            "node identity from the wallet seed",
            Implemented,
            "HKDF-SHA256 domain separation, LDK KeysManager",
        ),
        c(
            "monitor persistence that refuses stale state",
            Implemented,
            "SQLite, atomic, monotonic update_id, fail-closed open",
        ),
        c(
            "peer connectivity",
            NotImplemented,
            "needs lightning-net-tokio wiring and a peer policy",
        ),
        c(
            "chain monitoring / sync",
            NotImplemented,
            "needs a chain source (Esplora/Electrum/bitcoind) and its privacy policy",
        ),
        c(
            "channel open / close",
            NotImplemented,
            "needs a funded on-chain wallet, peers and the channel manager",
        ),
        c(
            "sending and receiving payments",
            NotImplemented,
            "depends on channels; no payment code exists on any network",
        ),
        c(
            "channel backup / static channel backups",
            NotImplemented,
            "a recovery phrase alone cannot restore channels; backup design not built",
        ),
        c(
            "remote monitor backup (VSS) / watchtower",
            NotImplemented,
            "not evaluated beyond noting LDK Node supports VSS",
        ),
        c("liquidity management", NotImplemented, "needs channels"),
        c(
            "Flutter / FFI integration",
            NotImplemented,
            "no FFI surface exists for this crate yet",
        ),
        c(
            "mainnet",
            NotImplemented,
            "never enabled; mainnet invoices are refused by a test-network wallet",
        ),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    // BOLT11 test vector 1 (BOLT #11, "Please make a donation of any amount using payment_hash 0001..."): mainnet, no amount.
    const MAINNET_DONATION: &str = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

    #[test]
    fn a_standard_invoice_parses_and_its_network_is_enforced() {
        let p = parse_invoice(MAINNET_DONATION, LnNetwork::Bitcoin, 1_496_314_658 + 60).unwrap();
        assert_eq!(p.network, LnNetwork::Bitcoin);
        assert_eq!(p.amount_msat, None);
        assert_eq!(
            p.payment_hash,
            "0001020304050607080900010203040506070809000102030405060708090102"
        );
        assert_eq!(
            p.description.as_deref(),
            Some("Please consider supporting this project")
        );
        assert!(!p.expired);
        let late = parse_invoice(
            MAINNET_DONATION,
            LnNetwork::Bitcoin,
            1_496_314_658 + 3600 + 1,
        )
        .unwrap();
        assert!(late.expired);
        // A mainnet invoice is never accepted by a test-network wallet.
        for net in [LnNetwork::Testnet, LnNetwork::Signet, LnNetwork::Regtest] {
            assert!(matches!(
                parse_invoice(MAINNET_DONATION, net, 0),
                Err(LnError::WrongNetwork {
                    found: LnNetwork::Bitcoin,
                    ..
                })
            ));
        }
        // The `lightning:` URI prefix is accepted, garbage and tampering are not.
        assert!(
            parse_invoice(
                &format!("lightning:{MAINNET_DONATION}"),
                LnNetwork::Bitcoin,
                0
            )
            .is_ok()
        );
        assert!(parse_invoice("lnbc1garbage", LnNetwork::Bitcoin, 0).is_err());
        let mut tampered = MAINNET_DONATION.to_owned();
        tampered.replace_range(60..61, if &tampered[60..61] == "q" { "p" } else { "q" });
        assert!(
            parse_invoice(&tampered, LnNetwork::Bitcoin, 0).is_err(),
            "checksum/signature must fail"
        );
    }

    #[test]
    fn node_seed_is_deterministic_separated_and_never_the_master() {
        let master = [7u8; 64];
        let a = derive_node_seed(&master).unwrap();
        let b = derive_node_seed(&master).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(&a[..], &master[..32]);
        assert_ne!(*a, *derive_node_seed(&[8u8; 64]).unwrap());
        assert!(matches!(
            derive_node_seed(&[1u8; 8]),
            Err(LnError::ShortSeed)
        ));
        let id = node_id(&a).unwrap();
        assert_eq!(id.len(), 66);
        assert!(id.starts_with("02") || id.starts_with("03"));
        assert_eq!(id, node_id(&b).unwrap(), "the node identity is stable");
        assert_ne!(id, node_id(&derive_node_seed(&[8u8; 64]).unwrap()).unwrap());
    }

    #[test]
    fn the_monitor_store_only_moves_forward_and_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitors.sqlite");
        let mut s = MonitorStore::open(&path).unwrap();
        s.put("chan-1", 1, b"state-1").unwrap();
        s.put("chan-1", 2, b"state-2").unwrap();
        assert!(matches!(
            s.put("chan-1", 1, b"state-1"),
            Err(LnError::Stale {
                stored: 2,
                attempted: 1,
                ..
            })
        ));
        assert!(matches!(
            s.put("chan-1", 2, b"other"),
            Err(LnError::Conflict { .. })
        ));
        s.put("chan-1", 2, b"state-2").unwrap();
        assert_eq!(
            s.get("chan-1").unwrap(),
            Some((2, b"state-2".to_vec())),
            "the refused writes changed nothing"
        );
        s.put("chan-2", 9, b"x").unwrap();
        drop(s);
        let again = MonitorStore::open(&path).unwrap();
        assert_eq!(again.ids().unwrap(), ["chan-1", "chan-2"]);
        assert_eq!(again.get("chan-1").unwrap().unwrap().0, 2);
        assert_eq!(again.get("nope").unwrap(), None);
    }

    #[test]
    fn a_damaged_monitor_database_fails_closed_and_is_left_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitors.sqlite");
        {
            let mut s = MonitorStore::open(&path).unwrap();
            for i in 0..400u64 {
                s.put(&format!("c{i}"), 1, &[i as u8; 300]).unwrap();
            }
        }
        // fold the WAL into the main file so the damage lands in real pages
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        for (i, b) in bytes[4096 * 8..4096 * 20].iter_mut().enumerate() {
            *b = (i.wrapping_mul(131).wrapping_add(7) & 0xff) as u8;
        }
        std::fs::write(&path, &bytes).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            MonitorStore::open(&path),
            Err(LnError::Corrupt(_))
        ));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "nothing is repaired or replaced"
        );
    }

    #[test]
    fn the_capability_report_does_not_overclaim() {
        assert!(!LnNetwork::Bitcoin.payments_enabled() && !LnNetwork::Regtest.payments_enabled());
        let caps = capabilities();
        assert_eq!(
            caps.iter()
                .filter(|c| c.status == Status::Implemented)
                .count(),
            3
        );
        assert!(
            caps.iter()
                .any(|c| c.feature.contains("sending and receiving")
                    && c.status == Status::NotImplemented)
        );
        assert!(
            caps.iter().any(|c| c.feature.contains("channel backup")
                && c.reason.contains("recovery phrase alone"))
        );
    }
}
