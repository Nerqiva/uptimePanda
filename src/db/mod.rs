// The module is the application's public persistence API, consumed by
// later segments (SEG-04..SEG-16). The binary does not call it yet, so the
// only consumers are the unit tests; silence dead_code until the wiring lands.
#![allow(dead_code)]

//! Database module — the only persistence path for the app.
//!
//! A single [`tokio_rusqlite::Connection`] handle to one SQLite file (or an
//! in-memory database in tests). All work goes through the background
//! thread; SQLite serializes writers anyway, and one connection keeps the
//! 512 MB memory budget honest.
//!
//! File-backed databases are opened with `PRAGMA journal_mode=WAL`,
//! `foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`. In-memory
//! databases get everything except WAL (`journal_mode` is reported as
//! `memory` there). Migrations run automatically on [`Db::open`] /
//! [`Db::in_memory`] via [`schema::migrate`].

pub mod backup;
pub mod models;
pub mod queries;
pub mod schema;

#[cfg(test)]
mod tests;

use std::path::Path;

use rusqlite::params;
use time::{Duration, OffsetDateTime};
use tokio_rusqlite::Connection;

pub use models::*;

/// Errors surfaced by the database module.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The background connection thread failed in a non-rusqlite way
    /// (connection closed, or a `DbError` escaped from a nested `call`).
    #[error("database task error: {0}")]
    Task(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("timestamp parse error: {0}")]
    TimeParse(#[from] time::error::Parse),

    #[error("timestamp format error: {0}")]
    TimeFormat(#[from] time::error::Format),

    #[error("integrity check failed: {0}")]
    Integrity(String),

    #[error("invalid backup: {0}")]
    InvalidBackup(String),

    /// A caller supplied or read a value that failed validation
    /// (unknown key, out-of-bounds value, or a cross-field invariant).
    #[error("validation error: {0}")]
    Validation(String),
}

impl From<tokio_rusqlite::Error<rusqlite::Error>> for DbError {
    fn from(e: tokio_rusqlite::Error<rusqlite::Error>) -> Self {
        match e {
            tokio_rusqlite::Error::Error(inner) => DbError::Sqlite(inner),
            other => DbError::Task(other.to_string()),
        }
    }
}

impl From<tokio_rusqlite::Error<DbError>> for DbError {
    fn from(e: tokio_rusqlite::Error<DbError>) -> Self {
        match e {
            tokio_rusqlite::Error::Error(inner) => inner,
            other => DbError::Task(other.to_string()),
        }
    }
}

/// Convenience alias for this module's results.
pub type Result<T> = std::result::Result<T, DbError>;

/// Number of `browser_events` rows kept by [`Db::cleanup_expired_history`].
const BROWSER_EVENTS_CAP: i64 = 500;

/// A handle to the application's single SQLite connection.
///
/// Cheap to clone (the inner handle is reference-counted by the background
/// thread's channel).
#[derive(Clone, Debug)]
pub struct Db {
    conn: Connection,
}

impl Db {
    /// Open (creating if necessary) the database at `path`, apply pragmas
    /// (including `journal_mode=WAL`), run migrations, and return a handle.
    pub async fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).await?;
        conn.call(|c| {
            c.pragma_update(None, "journal_mode", "WAL")?;
            c.execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 5000;
                 PRAGMA synchronous = NORMAL;",
            )
        })
        .await?;
        conn.call(schema::migrate).await?;
        Ok(Self { conn })
    }

    /// Open an in-memory database (tests). WAL is not applicable to
    /// in-memory databases; `journal_mode` stays `memory`.
    pub async fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().await?;
        conn.call(|c| {
            c.execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 5000;
                 PRAGMA synchronous = NORMAL;",
            )
        })
        .await?;
        conn.call(schema::migrate).await?;
        Ok(Self { conn })
    }

    /// Access to the raw background connection handle. Internal helpers use
    /// this; callers should prefer the `Db` methods.
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Enforce the retention policy:
    ///
    /// 1. Delete `visit_history` rows with `started_at` older than
    ///    `now - retention_days` (a negative value is treated as 0, i.e.
    ///    everything in the past is fair game).
    /// 2. Trim `browser_events` to the newest [`BROWSER_EVENTS_CAP`] rows.
    /// 3. `PRAGMA wal_checkpoint(TRUNCATE)` to shrink the WAL file
    ///    (a no-op for in-memory databases).
    ///
    /// Returns the number of rows deleted by steps 1 and 2.
    pub async fn cleanup_expired_history(&self, retention_days: i64) -> Result<CleanupStats> {
        let retention_days = retention_days.max(0);
        let cutoff =
            models::format_db_ts(OffsetDateTime::now_utc() - Duration::days(retention_days))?;
        let stats = self
            .conn
            .call(move |c| -> rusqlite::Result<models::CleanupStats> {
                let visit_history_deleted = c.execute(
                    "DELETE FROM visit_history WHERE started_at < ?1",
                    params![cutoff],
                )? as u64;
                let browser_events_deleted = c.execute(
                    "DELETE FROM browser_events
                     WHERE id NOT IN (
                         SELECT id FROM browser_events ORDER BY id DESC LIMIT ?1
                     )",
                    params![BROWSER_EVENTS_CAP],
                )? as u64;
                // A non-WAL (in-memory) database returns a synthetic row
                // (0, -1, -1) here; we only care that it does not error.
                let _ = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    row.get::<_, i64>(0)
                })?;
                Ok(models::CleanupStats {
                    visit_history_deleted,
                    browser_events_deleted,
                })
            })
            .await?;
        Ok(stats)
    }

    /// Write a compacted snapshot of the database to `dest` via
    /// `VACUUM INTO`. If `dest` exists it is removed first (i.e. backup
    /// always overwrites). The source connection is unaffected.
    pub async fn backup_to(&self, dest: &Path) -> Result<()> {
        if dest.exists() {
            std::fs::remove_file(dest)?;
        }
        let dest_s = dest
            .as_os_str()
            .to_str()
            .ok_or_else(|| {
                DbError::InvalidBackup(format!(
                    "destination path is not valid UTF-8: {}",
                    dest.display()
                ))
            })?
            .to_owned();
        self.conn
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute("VACUUM INTO ?1", params![dest_s])
            })
            .await?;
        Ok(())
    }
}
