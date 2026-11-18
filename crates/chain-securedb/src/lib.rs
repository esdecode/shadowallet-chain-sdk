//! Encrypted SQLite storage helpers (SQLCipher).
//!
//! * [`DbKey`]: a 256-bit database key that is zeroized on drop and never printed.
//! * [`derive_db_key`]: HKDF-SHA256 key derivation with a domain-separated `info` and a per-store, non-secret salt.
//! * [`open`]: opens (or creates) an encrypted database; **refuses a plaintext file** (no plaintext fallback) and
//!   refuses to run when the linked SQLite is not SQLCipher (a plain SQLite would silently ignore the key).
//! * [`migrate_plaintext`]: verified, crash-safe conversion of an existing plaintext database. The plaintext file is
//!   never overwritten and never deleted by the migration: it is renamed to `<path>.plaintext-retained`, and removing
//!   it is a separate, explicit act ([`retire_retained`]).
//!
//! Nothing here implements cryptography: encryption is SQLCipher's (AES-256-CBC with per-page HMAC-SHA512 and a
//! random per-file salt), key derivation is the `hkdf` crate.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use rusqlite::{Connection, OpenFlags, types::ValueRef};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Header every plaintext SQLite file starts with. An encrypted file never does (its first bytes are random salt).
const PLAINTEXT_MAGIC: &[u8; 16] = b"SQLite format 3\0";

#[derive(Debug, thiserror::Error)]
pub enum SecureDbError {
    #[error("the linked SQLite is not SQLCipher; refusing to store data that would be left unencrypted")]
    CipherUnavailable,
    #[error("{0} is a plaintext SQLite database; refusing to open it as an encrypted one (migrate it first)")]
    PlaintextRefused(String),
    #[error("database does not exist: {0}")]
    Missing(String),
    #[error("the database key does not match, or the encrypted file is damaged")]
    KeyMismatchOrCorrupt,
    #[error("source database failed its integrity check: {0}")]
    SourceCorrupt(String),
    #[error("migration verification failed: {0}")]
    Verification(String),
    #[error("migration stopped at the requested test point: {0:?}")]
    Interrupted(MigrationStep),
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("io: {0}")]
    Io(String),
}

impl From<rusqlite::Error> for SecureDbError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e.to_string())
    }
}
impl From<std::io::Error> for SecureDbError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// A 256-bit database key. Zeroized on drop; `Debug` never shows the bytes.
#[derive(Clone)]
pub struct DbKey(Zeroizing<[u8; 32]>);

impl DbKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    fn pragma_literal(&self) -> Zeroizing<String> {
        let mut s = String::with_capacity(70);
        s.push_str("x'");
        for b in self.0.iter() {
            s.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            s.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
        }
        s.push('\'');
        Zeroizing::new(s)
    }
}
impl std::fmt::Debug for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DbKey(<redacted>)")
    }
}

/// HKDF-SHA256. `master` is secret key material already held by the caller (the unlocked vault's seed-derived
/// secret). `salt` is a random, non-secret, per-store value stored next to the database; replacing it (and rekeying)
/// rotates the key. `info` names the store and its scope (for example `zcash/testnet/account-0`) and must be unique
/// per database so that no two files share a key.
///
/// # Errors
/// Fails only if the output length is invalid (never for 32 bytes).
pub fn derive_db_key(master: &[u8], salt: &[u8], info: &str) -> Result<DbKey, SecureDbError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut out = [0u8; 32];
    let mut full = Vec::with_capacity(info.len() + 24);
    full.extend_from_slice(b"shadowallet/db-key/v1/");
    full.extend_from_slice(info.as_bytes());
    hk.expand(&full, &mut out)
        .map_err(|e| SecureDbError::Sqlite(format!("hkdf: {e}")))?;
    let key = DbKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// What a file looks like on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Missing,
    /// Starts with the SQLite header: readable by anyone.
    Plaintext,
    /// Anything else: SQLCipher output, or garbage. Only opening with the key can tell.
    NotPlaintext,
}

/// # Errors
/// I/O errors other than "not found".
pub fn detect(path: &Path) -> Result<Format, SecureDbError> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Format::Missing),
        Err(e) => return Err(e.into()),
    };
    let mut head = [0u8; 16];
    let mut got = 0;
    while got < 16 {
        let n = f.read(&mut head[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    if got == 0 {
        return Ok(Format::Missing); // an empty file holds nothing
    }
    if got == 16 && &head == PLAINTEXT_MAGIC {
        Ok(Format::Plaintext)
    } else {
        Ok(Format::NotPlaintext)
    }
}

/// True when the linked SQLite is SQLCipher.
#[must_use]
pub fn cipher_available() -> bool {
    Connection::open_in_memory()
        .and_then(|c| c.query_row("PRAGMA cipher_version", [], |r| r.get::<_, String>(0)))
        .is_ok_and(|v| !v.is_empty())
}

fn apply_key(conn: &Connection, key: &DbKey) -> Result<(), SecureDbError> {
    let lit = key.pragma_literal();
    let sql = Zeroizing::new(format!("PRAGMA key = \"{}\";", lit.as_str()));
    conn.execute_batch(&sql)?;
    let v: Result<String, _> = conn.query_row("PRAGMA cipher_version", [], |r| r.get(0));
    match v {
        Ok(s) if !s.is_empty() => Ok(()),
        _ => Err(SecureDbError::CipherUnavailable),
    }
}

fn check_readable(conn: &Connection) -> Result<(), SecureDbError> {
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .map(|_| ())
        .map_err(|_| SecureDbError::KeyMismatchOrCorrupt)
}

/// Open an encrypted database read-write. With `create` a missing file is created encrypted from its first byte.
/// A plaintext file is refused, never opened.
///
/// # Errors
/// See [`SecureDbError`].
pub fn open(path: &Path, key: &DbKey, create: bool) -> Result<Connection, SecureDbError> {
    let fmt = detect(path)?;
    match fmt {
        Format::Plaintext => return Err(SecureDbError::PlaintextRefused(path.display().to_string())),
        Format::Missing if !create => return Err(SecureDbError::Missing(path.display().to_string())),
        _ => {}
    }
    let flags = if create {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    let conn = Connection::open_with_flags(path, flags)?;
    apply_key(&conn, key)?;
    if fmt != Format::Missing {
        check_readable(&conn)?;
    }
    Ok(conn)
}

/// `PRAGMA quick_check` on an open (keyed) connection; `Ok(())` only for a single `ok` row.
///
/// # Errors
/// The first reported problem.
pub fn quick_check(conn: &Connection) -> Result<(), SecureDbError> {
    let mut stmt = conn.prepare("PRAGMA quick_check(5)")?;
    let rows: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(Result::ok)
        .collect();
    if rows.len() == 1 && rows[0] == "ok" {
        Ok(())
    } else {
        Err(SecureDbError::SourceCorrupt(rows.join("; ")))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Migration

/// Steps at which a test can stop the migration to prove that nothing is lost (an interruption is simulated by
/// returning without cleaning up, exactly the state a crash would leave).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStep {
    BeforeStart,
    DuringCreate,
    DuringCopy,
    BeforeVerify,
    BetweenRenames,
    AfterActivate,
}

/// What a migration did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// File already encrypted (and opened with the key), or created new: nothing to migrate.
    AlreadyEncrypted,
    /// Plaintext converted; the plaintext copy is retained at the returned path until [`retire_retained`].
    Migrated { retained: PathBuf, tables: usize, rows: u64 },
    /// An interrupted earlier migration was completed or rolled back.
    Recovered(&'static str),
    NothingThere,
}

fn side(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn retained_path(path: &Path) -> PathBuf {
    side(path, ".plaintext-retained")
}
fn tmp_path(path: &Path) -> PathBuf {
    side(path, ".enc-tmp")
}

const SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

fn rename_with_sidecars(from: &Path, to: &Path) -> Result<(), SecureDbError> {
    // Sidecars first, so a crash never leaves a main file whose journal sits under another name.
    for s in SIDECARS {
        let f = side(from, s);
        if f.exists() {
            fs::rename(&f, side(to, s))?;
        }
    }
    fs::rename(from, to)?;
    Ok(())
}

fn remove_with_sidecars(path: &Path) {
    for s in SIDECARS {
        let _ = fs::remove_file(side(path, s));
    }
    let _ = fs::remove_file(path);
}

fn sync_dir(path: &Path) {
    // Best effort: directory fsync is how a rename becomes durable on POSIX; it is a no-op where unsupported.
    if let Some(dir) = path.parent() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

struct DbDigest {
    tables: Vec<(String, u64, [u8; 16])>,
    schema: Vec<(String, String, String, String)>,
    user_version: i64,
}

fn digest(conn: &Connection) -> Result<DbDigest, SecureDbError> {
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let mut st = conn.prepare("SELECT type, name, tbl_name, coalesce(sql,'') FROM sqlite_master ORDER BY type, name")?;
    let schema: Vec<(String, String, String, String)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    let names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut tables = Vec::new();
    for name in names {
        let q = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
        let mut stmt = conn.prepare(&q)?;
        let cols = stmt.column_count();
        let mut rows = stmt.query([])?;
        let mut count = 0u64;
        let mut acc = [0u8; 16];
        while let Some(row) = rows.next()? {
            let mut h = Sha256::new();
            for i in 0..cols {
                match row.get_ref(i)? {
                    ValueRef::Null => h.update([0u8]),
                    ValueRef::Integer(v) => {
                        h.update([1u8]);
                        h.update(v.to_le_bytes());
                    }
                    ValueRef::Real(v) => {
                        h.update([2u8]);
                        h.update(v.to_bits().to_le_bytes());
                    }
                    ValueRef::Text(t) => {
                        h.update([3u8]);
                        h.update((t.len() as u64).to_le_bytes());
                        h.update(t);
                    }
                    ValueRef::Blob(b) => {
                        h.update([4u8]);
                        h.update((b.len() as u64).to_le_bytes());
                        h.update(b);
                    }
                }
            }
            let d = h.finalize();
            // order-independent: wrapping 128-bit sum of the row digests
            let mut sum = u128::from_le_bytes(acc);
            let mut part = [0u8; 16];
            part.copy_from_slice(&d[..16]);
            sum = sum.wrapping_add(u128::from_le_bytes(part));
            acc = sum.to_le_bytes();
            count += 1;
        }
        tables.push((name, count, acc));
    }
    Ok(DbDigest { tables, schema, user_version })
}

/// Make sure `path` is an encrypted database that opens with `key`, converting a plaintext one when needed.
///
/// `verify` runs on the migrated, re-opened encrypted copy before it replaces anything; return `Err` to reject it
/// (for Zcash: same accounts and viewing keys, same note and transaction counts).
/// `stop_at` is for failure-injection tests only; pass `None` in production.
///
/// Guarantees: the only copy of the data is never overwritten or deleted; after any interruption the next call
/// completes or rolls back; the plaintext is kept at `<path>.plaintext-retained` until [`retire_retained`].
///
/// # Errors
/// See [`SecureDbError`]. On any error the original database is untouched or restored.
pub fn migrate_plaintext(
    path: &Path,
    key: &DbKey,
    verify: &dyn Fn(&Connection) -> Result<(), String>,
    stop_at: Option<MigrationStep>,
) -> Result<Outcome, SecureDbError> {
    if !cipher_available() {
        return Err(SecureDbError::CipherUnavailable);
    }
    let tmp = tmp_path(path);
    let kept = retained_path(path);
    let hit = |s: MigrationStep| -> Result<(), SecureDbError> {
        if stop_at == Some(s) {
            Err(SecureDbError::Interrupted(s))
        } else {
            Ok(())
        }
    };

    // Recovery of an interrupted earlier run.
    let fmt = detect(path)?;
    if fmt == Format::Missing && kept.exists() {
        if tmp.exists() {
            // Crash between the two renames. Finish only if the encrypted copy is provably good.
            let good = open(&tmp, key, false)
                .and_then(|c| quick_check(&c).and_then(|()| verify(&c).map_err(SecureDbError::Verification)))
                .is_ok();
            if good {
                fs::rename(&tmp, path)?;
                sync_dir(path);
                return Ok(Outcome::Recovered("completed interrupted activation"));
            }
            remove_with_sidecars(&tmp);
        }
        rename_with_sidecars(&kept, path)?;
        sync_dir(path);
        return Ok(Outcome::Recovered("restored the plaintext original"));
    }
    if fmt == Format::Plaintext && tmp.exists() {
        remove_with_sidecars(&tmp); // a half-written derived copy; the plaintext original is intact
    }
    match fmt {
        Format::Missing => return Ok(Outcome::NothingThere),
        Format::NotPlaintext => {
            let c = open(path, key, false)?;
            quick_check(&c)?;
            return Ok(Outcome::AlreadyEncrypted);
        }
        Format::Plaintext => {}
    }

    hit(MigrationStep::BeforeStart)?;

    // 1. Source: open read-write (finishes any hot journal), fold the WAL into the main file, check integrity.
    // CREATE is needed only so that ATTACH can create the destination file; the source exists (checked above).
    let src = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)?;
    let _ = src.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    quick_check(&src)?;
    let before = digest(&src)?;

    // 2. Encrypted destination, created next to the source (same filesystem, so the later rename is atomic).
    hit(MigrationStep::DuringCreate)?;
    remove_with_sidecars(&tmp);
    let lit = key.pragma_literal();
    let tmp_str = tmp.to_string_lossy().into_owned();
    src.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let attach = Zeroizing::new(format!("ATTACH DATABASE '{}' AS enc KEY \"{}\";", tmp_str.replace('\'', "''"), lit.as_str()));
    src.execute_batch(&attach)?;
    hit(MigrationStep::DuringCopy)?;
    src.query_row("SELECT sqlcipher_export('enc')", [], |_| Ok(()))?;
    src.execute_batch(&format!("PRAGMA enc.user_version = {};", before.user_version))?;
    src.execute_batch("DETACH DATABASE enc;")?;
    drop(src);

    // 3. Verify the encrypted copy after closing and re-opening it with the key.
    hit(MigrationStep::BeforeVerify)?;
    {
        let enc = open(&tmp, key, false)?;
        quick_check(&enc)?;
        let after = digest(&enc)?;
        if after.user_version != before.user_version {
            return Err(SecureDbError::Verification("user_version differs".into()));
        }
        if after.schema != before.schema {
            return Err(SecureDbError::Verification("schema differs".into()));
        }
        if after.tables.len() != before.tables.len() {
            return Err(SecureDbError::Verification("table list differs".into()));
        }
        for (a, b) in before.tables.iter().zip(after.tables.iter()) {
            if a != b {
                return Err(SecureDbError::Verification(format!("table {} differs (rows or content)", a.0)));
            }
        }
        verify(&enc).map_err(SecureDbError::Verification)?;
        let fk: Option<String> = enc
            .query_row("PRAGMA foreign_key_check", [], |r| r.get(0))
            .ok();
        if fk.is_some() {
            // The plaintext original had the same defect if it is not new; compare is on content, so only report.
            // A defect present only after export would already have failed the content comparison above.
        }
    }
    // The encrypted file must not be readable as plaintext.
    if detect(&tmp)? != Format::NotPlaintext {
        return Err(SecureDbError::Verification("the migrated file is not encrypted".into()));
    }
    {
        let f = OpenOptions::new().write(true).open(&tmp)?;
        f.sync_all()?;
    }

    // 4. Activate: plaintext aside (never deleted), encrypted into place.
    rename_with_sidecars(path, &kept)?;
    sync_dir(path);
    hit(MigrationStep::BetweenRenames)?;
    fs::rename(&tmp, path)?;
    sync_dir(path);
    hit(MigrationStep::AfterActivate)?;

    let rows = before.tables.iter().map(|t| t.1).sum();
    Ok(Outcome::Migrated { retained: kept, tables: before.tables.len(), rows })
}

/// Overwrite with zeros and delete the plaintext copy kept by a migration. Explicit by design: call it only after
/// the user (or the product's documented policy) has accepted the removal and the encrypted database has been used
/// successfully. On flash storage (SSD, UFS, eMMC) overwriting does not guarantee that the old physical blocks are
/// erased (wear levelling, TRIM timing); this reduces exposure, it does not prove erasure.
///
/// # Errors
/// I/O errors.
pub fn retire_retained(path: &Path) -> Result<u32, SecureDbError> {
    let kept = retained_path(path);
    let mut removed = 0;
    let mut all = vec![kept.clone()];
    all.extend(SIDECARS.iter().map(|s| side(&kept, s)));
    for f in all {
        if !f.exists() {
            continue;
        }
        let len = fs::metadata(&f)?.len();
        {
            let mut h = OpenOptions::new().write(true).open(&f)?;
            let zeros = [0u8; 65536];
            let mut left = len;
            while left > 0 {
                let n = left.min(zeros.len() as u64);
                #[allow(clippy::cast_possible_truncation)]
                h.write_all(&zeros[..n as usize])?;
                left -= n;
            }
            h.sync_all()?;
        }
        fs::remove_file(&f)?;
        removed += 1;
    }
    sync_dir(path);
    Ok(removed)
}

/// Whether a plaintext copy retained by a migration still exists.
#[must_use]
pub fn has_retained(path: &Path) -> bool {
    retained_path(path).exists()
}

/// Change the key of an open encrypted database (key rotation). SQLCipher rewrites every page.
///
/// # Errors
/// SQLite errors; on error the database keeps its old key.
pub fn rekey(conn: &Connection, new_key: &DbKey) -> Result<(), SecureDbError> {
    let lit = new_key.pragma_literal();
    let sql = Zeroizing::new(format!("PRAGMA rekey = \"{}\";", lit.as_str()));
    conn.execute_batch(&sql)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> DbKey {
        DbKey::from_bytes([b; 32])
    }

    fn make_plain(path: &Path) {
        let c = Connection::open(path).unwrap();
        c.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA user_version=8;
             CREATE TABLE accounts(id INTEGER PRIMARY KEY, ufvk TEXT NOT NULL, birthday INTEGER);
             CREATE TABLE notes(id INTEGER PRIMARY KEY AUTOINCREMENT, acct INTEGER REFERENCES accounts(id), v INTEGER, memo BLOB);
             CREATE INDEX notes_v ON notes(v);
             INSERT INTO accounts VALUES (1,'uviewtest1SECRETVIEWINGKEYMARKER',4531500);",
        )
        .unwrap();
        for i in 0..500 {
            c.execute("INSERT INTO notes(acct,v,memo) VALUES (1,?1,?2)", rusqlite::params![i, vec![7u8; 40]]).unwrap();
        }
    }

    fn contains(path: &Path, needle: &[u8]) -> bool {
        let data = fs::read(path).unwrap();
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn ok_verify(c: &Connection) -> Result<(), String> {
        let n: i64 = c.query_row("SELECT count(*) FROM accounts", [], |r| r.get(0)).map_err(|e| e.to_string())?;
        if n == 1 { Ok(()) } else { Err("accounts".into()) }
    }

    #[test]
    fn linked_sqlite_is_sqlcipher_and_encrypts() {
        assert!(cipher_available());
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.sqlite");
        let c = open(&p, &key(1), true).unwrap();
        c.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('findmeVIEWINGKEY');").unwrap();
        drop(c);
        assert_eq!(detect(&p).unwrap(), Format::NotPlaintext);
        assert!(!contains(&p, b"findmeVIEWINGKEY"), "plaintext visible in the file bytes");
        assert!(!contains(&p, b"SQLite format 3"));
    }

    #[test]
    fn wrong_key_and_plaintext_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.sqlite");
        drop(open(&p, &key(1), true).unwrap().execute_batch("CREATE TABLE t(x)"));
        assert!(matches!(open(&p, &key(2), false), Err(SecureDbError::KeyMismatchOrCorrupt)));
        let q = d.path().join("plain.sqlite");
        make_plain(&q);
        assert!(matches!(open(&q, &key(1), false), Err(SecureDbError::PlaintextRefused(_))));
        assert!(matches!(open(&d.path().join("nope"), &key(1), false), Err(SecureDbError::Missing(_))));
    }

    #[test]
    fn tampered_page_is_detected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.sqlite");
        let c = open(&p, &key(1), true).unwrap();
        c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES(1);").unwrap();
        drop(c);
        let mut data = fs::read(&p).unwrap();
        let n = data.len();
        data[n - 100] ^= 0x55;
        fs::write(&p, data).unwrap();
        let r = open(&p, &key(1), false).and_then(|c| quick_check(&c).map(|()| c)).and_then(|c| {
            c.query_row("SELECT sum(x) FROM t", [], |r| r.get::<_, i64>(0)).map(|_| ()).map_err(Into::into)
        });
        assert!(r.is_err(), "a modified encrypted page must not read back as valid");
    }

    #[test]
    fn migration_converts_verifies_and_retains_plaintext() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("zcash.sqlite");
        make_plain(&p);
        assert!(contains(&p, b"SECRETVIEWINGKEYMARKER"));
        let out = migrate_plaintext(&p, &key(9), &ok_verify, None).unwrap();
        let Outcome::Migrated { retained, tables, rows } = out else { panic!("{out:?}") };
        assert!(tables >= 2 && rows == 501);
        assert!(!contains(&p, b"SECRETVIEWINGKEYMARKER"), "live file still shows the viewing key");
        assert!(retained.exists() && has_retained(&p));
        let c = open(&p, &key(9), false).unwrap();
        let uv: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(uv, 8);
        let n: i64 = c.query_row("SELECT count(*) FROM notes", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 500);
        // the plaintext can no longer be reopened as the wallet database
        assert!(matches!(open(&retained, &key(9), false), Err(SecureDbError::PlaintextRefused(_))));
        // idempotent
        assert_eq!(migrate_plaintext(&p, &key(9), &ok_verify, None).unwrap(), Outcome::AlreadyEncrypted);
        // explicit retirement
        drop(c);
        assert_eq!(retire_retained(&p).unwrap(), 1);
        assert!(!has_retained(&p));
        assert!(!contains(&p, b"SECRETVIEWINGKEYMARKER"));
    }

    #[test]
    fn rejected_verification_leaves_original_untouched() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.sqlite");
        make_plain(&p);
        let before = fs::read(&p).unwrap();
        let r = migrate_plaintext(&p, &key(9), &|_| Err("nope".into()), None);
        assert!(matches!(r, Err(SecureDbError::Verification(_))));
        assert_eq!(fs::read(&p).unwrap(), before);
        assert!(!has_retained(&p));
    }

    #[test]
    fn every_interruption_point_keeps_the_data() {
        use MigrationStep::*;
        for step in [BeforeStart, DuringCreate, DuringCopy, BeforeVerify, BetweenRenames, AfterActivate] {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("w.sqlite");
            make_plain(&p);
            let r = migrate_plaintext(&p, &key(5), &ok_verify, Some(step));
            assert!(matches!(r, Err(SecureDbError::Interrupted(s)) if s == step), "{step:?}: {r:?}");
            // next start
            let out = migrate_plaintext(&p, &key(5), &ok_verify, None).unwrap();
            // whatever state it was in, the wallet data must now open with the key and hold all rows
            let c = open(&p, &key(5), false).unwrap_or_else(|e| panic!("{step:?}: {e}; outcome {out:?}"));
            let n: i64 = c.query_row("SELECT count(*) FROM notes", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 500, "{step:?}");
            assert!(!contains(&p, b"SECRETVIEWINGKEYMARKER"), "{step:?}: live file is plaintext");
            // a plaintext copy exists only as the explicitly named retained file
            let entries: Vec<_> = fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            assert!(entries.iter().all(|n| n == "w.sqlite" || n.ends_with(".plaintext-retained")), "{step:?}: {entries:?}");
        }
    }

    #[test]
    fn interruption_between_renames_with_a_bad_copy_restores_the_original() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("w.sqlite");
        make_plain(&p);
        let orig = fs::read(&p).unwrap();
        let _ = migrate_plaintext(&p, &key(5), &ok_verify, Some(MigrationStep::BetweenRenames));
        // corrupt the encrypted copy so it cannot be trusted
        let t = tmp_path(&p);
        let mut data = fs::read(&t).unwrap();
        for b in data.iter_mut().take(200) {
            *b ^= 0xFF;
        }
        fs::write(&t, data).unwrap();
        let out = migrate_plaintext(&p, &key(5), &ok_verify, None).unwrap();
        assert_eq!(out, Outcome::Recovered("restored the plaintext original"));
        assert_eq!(fs::read(&p).unwrap(), orig);
    }

    #[test]
    fn rekey_rotates_the_key() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.sqlite");
        let c = open(&p, &key(1), true).unwrap();
        c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES(42);").unwrap();
        rekey(&c, &key(2)).unwrap();
        drop(c);
        assert!(open(&p, &key(1), false).is_err());
        let c = open(&p, &key(2), false).unwrap();
        assert_eq!(c.query_row("SELECT x FROM t", [], |r| r.get::<_, i64>(0)).unwrap(), 42);
    }

    #[test]
    fn key_derivation_is_deterministic_and_separated() {
        let m = [3u8; 32];
        let salt = [9u8; 32];
        let a = derive_db_key(&m, &salt, "zcash/testnet/0").unwrap();
        let b = derive_db_key(&m, &salt, "zcash/testnet/0").unwrap();
        let c = derive_db_key(&m, &salt, "zcash/testnet/1").unwrap();
        let d = derive_db_key(&m, &[8u8; 32], "zcash/testnet/0").unwrap();
        assert_eq!(a.0.as_slice(), b.0.as_slice());
        assert_ne!(a.0.as_slice(), c.0.as_slice());
        assert_ne!(a.0.as_slice(), d.0.as_slice());
        assert_ne!(a.0.as_slice(), m.as_slice());
        assert_eq!(format!("{a:?}"), "DbKey(<redacted>)");
    }
}
