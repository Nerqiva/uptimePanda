//! Backup and restore validation.
//!
//! [`Db::backup_to`](crate::db::Db::backup_to) performs the actual snapshot
//! (`VACUUM INTO`, implemented on `Db`). This module adds the validation
//! half of the restore flow: [`validate_backup`] checks a candidate backup
//! file (SQLite magic header + `PRAGMA integrity_check`) without touching
//! the live database.
//!
//! The full "upload → validate → swap" restore flow is exposed in SEG-16;
//! only the raw APIs and their tests live here.

use std::io::Read;
use std::path::Path;

use rusqlite::OpenFlags;

use super::{Db, DbError, Result};

impl Db {
    /// Run `PRAGMA integrity_check` against the live database; succeeds
    /// only if the result is exactly `ok`.
    pub async fn integrity_check(&self) -> Result<()> {
        let rows = self.integrity_check_rows().await?;
        if rows.len() == 1 && rows[0] == "ok" {
            Ok(())
        } else {
            Err(DbError::Integrity(rows.join("; ")))
        }
    }

    pub(crate) async fn integrity_check_rows(&self) -> Result<Vec<String>> {
        let rows = self
            .connection()
            .call(|c| -> rusqlite::Result<Vec<String>> {
                let mut stmt = c.prepare("PRAGMA integrity_check")?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }
}

/// Validate a backup file without opening it as the live database:
///
/// 1. The first 16 bytes must be the `SQLite format 3\0` magic header.
/// 2. Opening the file read-only and running `PRAGMA integrity_check`
///    must return exactly `ok`.
///
/// Our databases are tiny, so the (normally expensive) integrity check is
/// acceptable here.
pub fn validate_backup(path: &Path) -> Result<()> {
    let mut file = std::fs::File::open(path)?;
    let mut magic = [0u8; 16];
    file.read_exact(&mut magic).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            DbError::InvalidBackup(format!(
                "{} is smaller than the SQLite header",
                path.display()
            ))
        } else {
            DbError::Io(e)
        }
    })?;
    if magic != *b"SQLite format 3\0" {
        return Err(DbError::InvalidBackup(format!(
            "{} is not a SQLite 3 database (bad magic header)",
            path.display()
        )));
    }

    let conn = rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let rows = conn
        .prepare("PRAGMA integrity_check")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() == 1 && rows[0] == "ok" {
        Ok(())
    } else {
        Err(DbError::Integrity(rows.join("; ")))
    }
}
