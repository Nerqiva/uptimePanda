//! Schema definition and forward-only migrations.
//!
//! Migrations are tracked with the SQLite `PRAGMA user_version` header field:
//! `user_version == 0` means the database has never been migrated, so the
//! embedded DDL for schema version 1 is applied and `user_version` is bumped
//! to [`SCHEMA_VERSION`]. All DDL uses `IF NOT EXISTS` so a crash between
//! committing the DDL transaction and recording the version simply replays
//! the (idempotent) DDL on the next open.
//!
//! `user_version` is intentionally set *after* the DDL transaction commits:
//! whether the pragma participates in a transaction varies across SQLite
//! builds, and the idempotent DDL makes a partially-applied migration safe
//! to re-run.

use rusqlite::Connection;

/// Current schema version. Bump this (never reuse a version number) whenever
/// a future migration is added.
pub const SCHEMA_VERSION: i64 = 1;

/// All DDL for schema version 1. Every statement is idempotent.
const SCHEMA_V1_DDL: &str = "
CREATE TABLE IF NOT EXISTS browser_profiles (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL UNIQUE,
    description         TEXT NOT NULL DEFAULT '',
    user_agent          TEXT NULL,
    enabled             INTEGER NOT NULL DEFAULT 1,
    configuration_json  TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) STRICT;

CREATE TABLE IF NOT EXISTS websites (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    name                    TEXT NOT NULL,
    url                     TEXT NOT NULL,
    enabled                 INTEGER NOT NULL DEFAULT 1,
    profile_id              INTEGER NULL REFERENCES browser_profiles(id) ON DELETE SET NULL,
    monitoring_mode         TEXT NOT NULL DEFAULT 'basic'
                            CHECK (monitoring_mode IN ('basic', 'interaction')),
    min_interval_seconds    INTEGER NOT NULL DEFAULT 480,
    max_interval_seconds    INTEGER NOT NULL DEFAULT 780,
    min_session_seconds     INTEGER NOT NULL DEFAULT 15,
    max_session_seconds     INTEGER NOT NULL DEFAULT 60,
    last_visit_at           TEXT NULL,
    next_visit_at           TEXT NULL,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (min_interval_seconds <= max_interval_seconds),
    CHECK (min_session_seconds <= max_session_seconds)
) STRICT;

CREATE TABLE IF NOT EXISTS cookies (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id              INTEGER NOT NULL REFERENCES browser_profiles(id) ON DELETE CASCADE,
    domain                  TEXT NOT NULL,
    encrypted_cookie_data   TEXT NOT NULL,
    expires_at              TEXT NULL,
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS cookies_profile_domain ON cookies(profile_id, domain);

CREATE TABLE IF NOT EXISTS interaction_sequences (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    website_id          INTEGER NOT NULL UNIQUE REFERENCES websites(id) ON DELETE CASCADE,
    enabled             INTEGER NOT NULL DEFAULT 1,
    configuration_json  TEXT NOT NULL DEFAULT '[]',
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) STRICT;

CREATE TABLE IF NOT EXISTS visit_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    website_id      INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    profile_id      INTEGER NULL,
    started_at      TEXT NOT NULL,
    completed_at    TEXT NULL,
    duration_ms     INTEGER NULL,
    http_status     INTEGER NULL,
    final_url       TEXT NULL,
    outcome         TEXT NOT NULL
                    CHECK (outcome IN ('success', 'timeout', 'navigation_error',
                                       'browser_crash', 'interaction_error')),
    error_message   TEXT NULL,
    browser_pid     INTEGER NULL,
    memory_usage    INTEGER NULL
) STRICT;

CREATE TABLE IF NOT EXISTS scheduler_state (
    website_id          INTEGER PRIMARY KEY REFERENCES websites(id) ON DELETE CASCADE,
    next_visit_at       TEXT NULL,
    last_execution_at   TEXT NULL,
    retry_count         INTEGER NOT NULL DEFAULT 0,
    job_status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (job_status IN ('pending', 'running', 'paused', 'retry', 'disabled')),
    lease_expires_at    TEXT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS browser_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    memory_usage    INTEGER NULL,
    details         TEXT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS application_settings (
    setting_key     TEXT PRIMARY KEY,
    setting_value   TEXT NOT NULL,
    updated_at      TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_visit_history_website_id ON visit_history(website_id);
CREATE INDEX IF NOT EXISTS idx_visit_history_started_at ON visit_history(started_at);
CREATE INDEX IF NOT EXISTS idx_scheduler_state_next_visit_at ON scheduler_state(next_visit_at);
CREATE INDEX IF NOT EXISTS idx_websites_next_visit_at ON websites(next_visit_at);
CREATE INDEX IF NOT EXISTS idx_cookies_profile_id ON cookies(profile_id);
";

/// Apply pending migrations to `conn`. Safe to call on every open; already
/// migrated databases are left untouched.
///
/// Intended to run inside a `tokio_rusqlite::Connection::call` closure.
pub fn migrate(conn: &mut Connection) -> crate::db::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 1 {
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA_V1_DDL)?;
        tx.commit()?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

/// Read the current `user_version`. Exposed for diagnostics and tests.
pub fn user_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
}
