//! Query API. Every function runs inside the background connection thread
//! via `Connection::call`. Later segments extend this module; only the
//! highest-value queries live here.
//!
//! Atomic scheduler claim uses the `UPDATE … RETURNING` pattern:
//!
//! ```sql
//! UPDATE scheduler_state SET job_status='running', lease_expires_at=?2
//! WHERE website_id = (SELECT website_id FROM scheduler_state
//!                     WHERE job_status IN ('pending','retry')
//!                       AND (next_visit_at IS NULL OR next_visit_at <= ?1)
//!                     ORDER BY next_visit_at LIMIT 1)
//!   AND job_status IN ('pending','retry')
//! RETURNING *
//! ```
//!
//! The subquery picks the due job with the smallest `next_visit_at` and the
//! outer `UPDATE … WHERE job_status IN (…)` acts as a compare-and-swap: if
//! two callers race, exactly one affects the row and gets it back from
//! `RETURNING`. A caller that loses the race gets zero rows from
//! `RETURNING`, i.e. `Ok(None)`.

use rusqlite::{OptionalExtension, Row, params};
use time::{Duration, OffsetDateTime};

use super::models::*;
use super::{Db, Result};

fn website_from_row(row: &Row<'_>) -> rusqlite::Result<Website> {
    Ok(Website {
        id: row.get("id")?,
        name: row.get("name")?,
        url: row.get("url")?,
        enabled: row.get("enabled")?,
        profile_id: row.get("profile_id")?,
        monitoring_mode: MonitoringMode::from_db_str(5, &row.get::<_, String>("monitoring_mode")?)?,
        min_interval_seconds: row.get("min_interval_seconds")?,
        max_interval_seconds: row.get("max_interval_seconds")?,
        min_session_seconds: row.get("min_session_seconds")?,
        max_session_seconds: row.get("max_session_seconds")?,
        last_visit_at: parse_db_ts_opt(row.get("last_visit_at")?, 10)?,
        next_visit_at: parse_db_ts_opt(row.get("next_visit_at")?, 11)?,
        created_at: parse_db_ts(&row.get::<_, String>("created_at")?, 12)?,
        updated_at: parse_db_ts(&row.get::<_, String>("updated_at")?, 13)?,
    })
}

fn scheduler_state_from_row(row: &Row<'_>) -> rusqlite::Result<SchedulerState> {
    Ok(SchedulerState {
        website_id: row.get("website_id")?,
        next_visit_at: parse_db_ts_opt(row.get("next_visit_at")?, 1)?,
        last_execution_at: parse_db_ts_opt(row.get("last_execution_at")?, 2)?,
        retry_count: row.get("retry_count")?,
        job_status: JobStatus::from_db_str(4, &row.get::<_, String>("job_status")?)?,
        lease_expires_at: parse_db_ts_opt(row.get("lease_expires_at")?, 5)?,
    })
}

fn visit_history_from_row(row: &Row<'_>) -> rusqlite::Result<VisitHistoryRow> {
    Ok(VisitHistoryRow {
        id: row.get("id")?,
        website_id: row.get("website_id")?,
        profile_id: row.get("profile_id")?,
        started_at: parse_db_ts(&row.get::<_, String>("started_at")?, 3)?,
        completed_at: parse_db_ts_opt(row.get("completed_at")?, 4)?,
        duration_ms: row.get("duration_ms")?,
        http_status: row.get("http_status")?,
        final_url: row.get("final_url")?,
        outcome: Outcome::from_db_str(8, &row.get::<_, String>("outcome")?)?,
        error_message: row.get("error_message")?,
        browser_pid: row.get("browser_pid")?,
        memory_usage: row.get("memory_usage")?,
    })
}

const WEBSITE_COLUMNS: &str = "id, name, url, enabled, profile_id, monitoring_mode, \
     min_interval_seconds, max_interval_seconds, min_session_seconds, max_session_seconds, \
     last_visit_at, next_visit_at, created_at, updated_at";

const VISIT_HISTORY_COLUMNS: &str = "id, website_id, profile_id, started_at, completed_at, \
     duration_ms, http_status, final_url, outcome, error_message, browser_pid, memory_usage";

impl Db {
    /// All websites with `enabled = 1`, ordered by creation.
    pub async fn list_enabled_websites(&self) -> Result<Vec<Website>> {
        let rows = self
            .connection()
            .call(|c| -> rusqlite::Result<Vec<Website>> {
                let mut stmt = c.prepare(&format!(
                    "SELECT {WEBSITE_COLUMNS} FROM websites WHERE enabled = 1 ORDER BY id"
                ))?;
                let websites = stmt
                    .query_map([], website_from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(websites)
            })
            .await?;
        Ok(rows)
    }

    /// Fetch a single website by id.
    pub async fn get_website(&self, id: i64) -> Result<Option<Website>> {
        let row = self
            .connection()
            .call(move |c| -> rusqlite::Result<Option<Website>> {
                c.query_row(
                    &format!("SELECT {WEBSITE_COLUMNS} FROM websites WHERE id = ?1"),
                    params![id],
                    website_from_row,
                )
                .optional()
            })
            .await?;
        Ok(row)
    }

    /// Insert a website. The `id` on the input is ignored; the
    /// `AUTOINCREMENT` id is returned.
    pub async fn insert_website(&self, website: &Website) -> Result<i64> {
        let website = website.clone();
        let created_at = format_db_ts(website.created_at)?;
        let updated_at = format_db_ts(website.updated_at)?;
        let last_visit_at = website.last_visit_at.map(format_db_ts).transpose()?;
        let next_visit_at = website.next_visit_at.map(format_db_ts).transpose()?;
        let id = self
            .connection()
            .call(move |c| -> rusqlite::Result<i64> {
                c.execute(
                    "INSERT INTO websites
                        (name, url, enabled, profile_id, monitoring_mode,
                         min_interval_seconds, max_interval_seconds,
                         min_session_seconds, max_session_seconds,
                         last_visit_at, next_visit_at, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    params![
                        website.name,
                        website.url,
                        website.enabled,
                        website.profile_id,
                        website.monitoring_mode.as_str(),
                        website.min_interval_seconds,
                        website.max_interval_seconds,
                        website.min_session_seconds,
                        website.max_session_seconds,
                        last_visit_at,
                        next_visit_at,
                        created_at,
                        updated_at,
                    ],
                )?;
                Ok(c.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    /// Update a website. `updated_at` is always set to now by this function.
    /// Returns `true` when a row was actually updated.
    pub async fn update_website(&self, website: &Website) -> Result<bool> {
        let website = website.clone();
        let updated_at = format_db_ts(OffsetDateTime::now_utc())?;
        let last_visit_at = website.last_visit_at.map(format_db_ts).transpose()?;
        let next_visit_at = website.next_visit_at.map(format_db_ts).transpose()?;
        let affected = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute(
                    "UPDATE websites SET
                        name = ?2, url = ?3, enabled = ?4, profile_id = ?5,
                        monitoring_mode = ?6, min_interval_seconds = ?7,
                        max_interval_seconds = ?8, min_session_seconds = ?9,
                        max_session_seconds = ?10, last_visit_at = ?11,
                        next_visit_at = ?12, updated_at = ?13
                     WHERE id = ?1",
                    params![
                        website.id,
                        website.name,
                        website.url,
                        website.enabled,
                        website.profile_id,
                        website.monitoring_mode.as_str(),
                        website.min_interval_seconds,
                        website.max_interval_seconds,
                        website.min_session_seconds,
                        website.max_session_seconds,
                        last_visit_at,
                        next_visit_at,
                        updated_at,
                    ],
                )
            })
            .await?;
        Ok(affected > 0)
    }

    /// Delete a website. Dependent `visit_history`, `scheduler_state` and
    /// `interaction_sequences` rows cascade; the linked profile keeps its
    /// cookies (they are only cleared when the *profile* is deleted).
    /// Returns `true` when a row was actually deleted.
    pub async fn delete_website(&self, id: i64) -> Result<bool> {
        let affected = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute("DELETE FROM websites WHERE id = ?1", params![id])
            })
            .await?;
        Ok(affected > 0)
    }

    /// Record a finished visit. The `id` on the input is ignored;
    /// the `AUTOINCREMENT` id is returned.
    pub async fn record_visit(&self, visit: &VisitHistoryRow) -> Result<i64> {
        let visit = visit.clone();
        let started_at = format_db_ts(visit.started_at)?;
        let completed_at = visit.completed_at.map(format_db_ts).transpose()?;
        let id = self
            .connection()
            .call(move |c| -> rusqlite::Result<i64> {
                c.execute(
                    "INSERT INTO visit_history
                        (website_id, profile_id, started_at, completed_at, duration_ms,
                         http_status, final_url, outcome, error_message,
                         browser_pid, memory_usage)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        visit.website_id,
                        visit.profile_id,
                        started_at,
                        completed_at,
                        visit.duration_ms,
                        visit.http_status,
                        visit.final_url,
                        visit.outcome.as_str(),
                        visit.error_message,
                        visit.browser_pid,
                        visit.memory_usage,
                    ],
                )?;
                Ok(c.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    /// Most recent visits, newest first. `limit` is clamped to `0..=10_000`.
    /// Pass `Some(website_id)` to filter to a single website.
    pub async fn recent_visits(
        &self,
        limit: i64,
        website_id: Option<i64>,
    ) -> Result<Vec<VisitHistoryRow>> {
        let limit = limit.clamp(0, 10_000);
        let rows = self
            .connection()
            .call(move |c| -> rusqlite::Result<Vec<VisitHistoryRow>> {
                let mut stmt = c.prepare(&format!(
                    "SELECT {VISIT_HISTORY_COLUMNS} FROM visit_history
                     WHERE (?2 IS NULL OR website_id = ?2)
                     ORDER BY started_at DESC LIMIT ?1"
                ))?;
                let visits = stmt
                    .query_map(params![limit, website_id], visit_history_from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(visits)
            })
            .await?;
        Ok(rows)
    }

    /// Insert or replace the scheduler row for a website.
    pub async fn upsert_scheduler_state(&self, state: &SchedulerState) -> Result<()> {
        let state = state.clone();
        let next_visit_at = state.next_visit_at.map(format_db_ts).transpose()?;
        let last_execution_at = state.last_execution_at.map(format_db_ts).transpose()?;
        let lease_expires_at = state.lease_expires_at.map(format_db_ts).transpose()?;
        self.connection()
            .call(move |c| -> rusqlite::Result<()> {
                c.execute(
                    "INSERT INTO scheduler_state
                        (website_id, next_visit_at, last_execution_at,
                         retry_count, job_status, lease_expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(website_id) DO UPDATE SET
                        next_visit_at = excluded.next_visit_at,
                        last_execution_at = excluded.last_execution_at,
                        retry_count = excluded.retry_count,
                        job_status = excluded.job_status,
                        lease_expires_at = excluded.lease_expires_at",
                    params![
                        state.website_id,
                        next_visit_at,
                        last_execution_at,
                        state.retry_count,
                        state.job_status.as_str(),
                        lease_expires_at,
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Atomically claim the next due job (`pending`/`retry` and
    /// `next_visit_at` in the past or NULL), marking it `running` with a
    /// lease expiring `lease_seconds` after `now`. Returns `None` when
    /// nothing is due or the claim lost the race.
    ///
    /// Exactly one concurrent caller can claim a given row — the outer
    /// `UPDATE` re-checks `job_status`, so the loser's `RETURNING` is empty.
    pub async fn claim_due_job(
        &self,
        now: OffsetDateTime,
        lease_seconds: i64,
    ) -> Result<Option<SchedulerState>> {
        let now_s = format_db_ts(now)?;
        let lease_s = format_db_ts(now + Duration::seconds(lease_seconds))?;
        let claimed = self
            .connection()
            .call(move |c| -> rusqlite::Result<Option<SchedulerState>> {
                c.query_row(
                    "UPDATE scheduler_state
                     SET job_status = 'running', lease_expires_at = ?2
                     WHERE website_id = (
                         SELECT website_id FROM scheduler_state
                         WHERE job_status IN ('pending', 'retry')
                           AND (next_visit_at IS NULL OR next_visit_at <= ?1)
                         ORDER BY next_visit_at
                         LIMIT 1
                     )
                       AND job_status IN ('pending', 'retry')
                     RETURNING website_id, next_visit_at, last_execution_at,
                               retry_count, job_status, lease_expires_at",
                    params![now_s, lease_s],
                    scheduler_state_from_row,
                )
                .optional()
            })
            .await?;
        Ok(claimed)
    }

    /// Requeue stale jobs: any `running` row whose `lease_expires_at` has
    /// passed by at least `lease_slack_seconds` (or is NULL) goes back to
    /// `pending` and its lease is cleared. Returns the number of rows
    /// recovered.
    pub async fn recover_stale_running(&self, lease_slack_seconds: i64) -> Result<u64> {
        let cutoff =
            format_db_ts(OffsetDateTime::now_utc() - Duration::seconds(lease_slack_seconds))?;
        let recovered = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute(
                    "UPDATE scheduler_state
                     SET job_status = 'pending', lease_expires_at = NULL
                     WHERE job_status = 'running'
                       AND (lease_expires_at IS NULL OR lease_expires_at < ?1)",
                    params![cutoff],
                )
            })
            .await?;
        Ok(recovered as u64)
    }
}

// ---------------------------------------------------------------------------
// application_settings — deliberately tiny raw helpers; typed access and
// validation live in `crate::config`.
// ---------------------------------------------------------------------------

impl Db {
    /// Read a raw `application_settings` value, if the key is present.
    pub async fn get_application_setting(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_owned();
        let value = self
            .connection()
            .call(move |c| -> rusqlite::Result<Option<String>> {
                c.query_row(
                    "SELECT setting_value FROM application_settings WHERE setting_key = ?1",
                    params![key],
                    |row| row.get(0),
                )
                .optional()
            })
            .await?;
        Ok(value)
    }

    /// Insert the key/value only if the key is absent. Returns `true` when a
    /// row was inserted (i.e. the seed was applied), `false` when the key
    /// already existed.
    pub async fn seed_application_setting_if_absent(&self, key: &str, value: &str) -> Result<bool> {
        let key = key.to_owned();
        let value = value.to_owned();
        let inserted = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute(
                    "INSERT OR IGNORE INTO application_settings
                        (setting_key, setting_value, updated_at)
                     VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    params![key, value],
                )
            })
            .await?;
        Ok(inserted > 0)
    }

    /// Insert or overwrite a raw `application_settings` value.
    pub async fn upsert_application_setting(&self, key: &str, value: &str) -> Result<()> {
        let key = key.to_owned();
        let value = value.to_owned();
        self.connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute(
                    "INSERT INTO application_settings
                        (setting_key, setting_value, updated_at)
                     VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                     ON CONFLICT(setting_key) DO UPDATE SET
                        setting_value = excluded.setting_value,
                        updated_at = excluded.updated_at",
                    params![key, value],
                )
            })
            .await?;
        Ok(())
    }

    /// All `application_settings` rows as `(key, value)` pairs, ordered by key.
    pub async fn all_application_settings(&self) -> Result<Vec<(String, String)>> {
        let rows = self
            .connection()
            .call(|c| -> rusqlite::Result<Vec<(String, String)>> {
                let mut stmt = c.prepare(
                    "SELECT setting_key, setting_value FROM application_settings ORDER BY setting_key",
                )?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }
}
