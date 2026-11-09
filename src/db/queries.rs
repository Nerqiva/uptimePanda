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
        active_window_start: row.get("active_window_start")?,
        active_window_end: row.get("active_window_end")?,
        timezone: row.get("timezone")?,
    })
}

fn browser_profile_from_row(row: &Row<'_>) -> rusqlite::Result<BrowserProfile> {
    Ok(BrowserProfile {
        id: row.get("id")?,
        name: row.get("name")?,
        description: row.get("description")?,
        user_agent: row.get("user_agent")?,
        enabled: row.get("enabled")?,
        configuration_json: row.get("configuration_json")?,
        created_at: parse_db_ts(&row.get::<_, String>("created_at")?, 6)?,
        updated_at: parse_db_ts(&row.get::<_, String>("updated_at")?, 7)?,
    })
}

fn cookie_record_from_row(row: &Row<'_>) -> rusqlite::Result<CookieRecord> {
    Ok(CookieRecord {
        id: row.get("id")?,
        profile_id: row.get("profile_id")?,
        domain: row.get("domain")?,
        encrypted_cookie_data: row.get("encrypted_cookie_data")?,
        expires_at: parse_db_ts_opt(row.get("expires_at")?, 4)?,
        updated_at: parse_db_ts(&row.get::<_, String>("updated_at")?, 5)?,
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
     last_visit_at, next_visit_at, created_at, updated_at, \
     active_window_start, active_window_end, timezone";

const PROFILE_COLUMNS: &str = "id, name, description, user_agent, enabled, \
    configuration_json, created_at, updated_at";

const COOKIE_COLUMNS: &str = "id, profile_id, domain, encrypted_cookie_data, \
    expires_at, updated_at";

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
                         last_visit_at, next_visit_at, created_at, updated_at,
                         active_window_start, active_window_end, timezone)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
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
                        website.active_window_start,
                        website.active_window_end,
                        website.timezone,
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
                        next_visit_at = ?12, updated_at = ?13,
                        active_window_start = ?14, active_window_end = ?15,
                        timezone = ?16
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
                        website.active_window_start,
                        website.active_window_end,
                        website.timezone,
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

    /// Read the scheduler row for a website, if any.
    pub async fn get_scheduler_state(&self, website_id: i64) -> Result<Option<SchedulerState>> {
        let row = self
            .connection()
            .call(move |c| -> rusqlite::Result<Option<SchedulerState>> {
                c.query_row(
                    "SELECT website_id, next_visit_at, last_execution_at,
                            retry_count, job_status, lease_expires_at
                     FROM scheduler_state WHERE website_id = ?1",
                    params![website_id],
                    scheduler_state_from_row,
                )
                .optional()
            })
            .await?;
        Ok(row)
    }

    /// All `(scheduler_state, website)` pairs whose state is claimable
    /// (`pending`/`retry`) and whose website is `enabled = 1`. Used by the
    /// scheduler to (re)build its in-memory heap after boot and completions.
    pub async fn list_claimable_scheduler_jobs(&self) -> Result<Vec<(SchedulerState, Website)>> {
        let pairs = self
            .connection()
            .call(|c| -> rusqlite::Result<Vec<(SchedulerState, Website)>> {
                let states = {
                    let mut stmt = c.prepare(
                        "SELECT website_id, next_visit_at, last_execution_at,
                                retry_count, job_status, lease_expires_at
                         FROM scheduler_state
                         WHERE job_status IN ('pending', 'retry')
                         ORDER BY next_visit_at",
                    )?;
                    stmt.query_map([], scheduler_state_from_row)?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                let mut out = Vec::with_capacity(states.len());
                let stmt_sql = format!("SELECT {WEBSITE_COLUMNS} FROM websites WHERE id = ?1");
                for state in states {
                    let website =
                        c.query_row(&stmt_sql, params![state.website_id], website_from_row)?;
                    if website.enabled {
                        out.push((state, website));
                    }
                }
                Ok(out)
            })
            .await?;
        Ok(pairs)
    }

    /// Ids of `enabled` websites that have no `scheduler_state` row yet.
    /// Used to reconcile fresh databases on scheduler boot.
    pub async fn list_enabled_website_ids_missing_scheduler_state(&self) -> Result<Vec<i64>> {
        let ids = self
            .connection()
            .call(|c| -> rusqlite::Result<Vec<i64>> {
                let mut stmt = c.prepare(
                    "SELECT id FROM websites
                     WHERE enabled = 1
                       AND id NOT IN (SELECT website_id FROM scheduler_state)
                     ORDER BY id",
                )?;
                let ids = stmt
                    .query_map([], |row| row.get(0))?
                    .collect::<rusqlite::Result<Vec<i64>>>()?;
                Ok(ids)
            })
            .await?;
        Ok(ids)
    }

    /// Mark a website's scheduler row as permanently non-schedulable
    /// (`job_status = 'disabled'`, no lease, no next visit). Used when an
    /// `enabled = 0` website is encountered at claim/emit time.
    pub async fn mark_scheduler_state_disabled(&self, website_id: i64) -> Result<()> {
        self.set_scheduler_state_status(website_id, JobStatus::Disabled, None, 0)
            .await
    }

    /// Overwrite a scheduler row's scheduling fields in one shot. `next_visit_at`
    /// of `None` clears the schedule; `retry_count` is written as given.
    /// `lease_expires_at` is cleared to `NULL`; `last_execution_at` is preserved.
    pub async fn set_scheduler_state_status(
        &self,
        website_id: i64,
        job_status: JobStatus,
        next_visit_at: Option<OffsetDateTime>,
        retry_count: i64,
    ) -> Result<()> {
        let existing = self.get_scheduler_state(website_id).await?;
        let last_execution_at = existing.and_then(|s| s.last_execution_at);
        self.upsert_scheduler_state(&SchedulerState {
            website_id,
            next_visit_at,
            last_execution_at,
            retry_count,
            job_status,
            lease_expires_at: None,
        })
        .await
    }

    /// Targeted variant of [`Self::claim_due_job`] used by the scheduler's
    /// priority queue. Claims `website_id` for execution if — and only if —
    /// the row is in a claimable state. Runs in a single transaction so the
    /// state check and the `running` transition are atomic.
    ///
    /// * [`ClaimKind::Scheduled`]: row must be `pending`/`retry` and due
    ///   (`next_visit_at` NULL or `<= now`). This is the normal path and is
    ///   redundant with [`Self::claim_due_job`], but targets the website the
    ///   heap popped so emit order follows the in-memory queue.
    /// * [`ClaimKind::Manual`]: row must be `pending`/`retry`/`paused`; the
    ///   `next_visit_at` gate is bypassed (manual visits run on user intent).
    ///
    /// On success returns the *previous* `job_status` (needed to preserve
    /// "paused" across a manual visit) and the claimed row. The `UPDATE`
    /// re-checks the previous `job_status`, so two racing claimants cannot
    /// both win.
    pub async fn claim_website_job(
        &self,
        website_id: i64,
        now: OffsetDateTime,
        lease_seconds: i64,
        kind: ClaimKind,
    ) -> Result<Option<(JobStatus, SchedulerState)>> {
        let lease_s = format_db_ts(now + Duration::seconds(lease_seconds))?;
        let claimed = self
            .connection()
            .call(
                move |c| -> rusqlite::Result<Option<(JobStatus, SchedulerState)>> {
                    let tx = c.transaction()?;
                    let previous = tx
                        .query_row(
                            "SELECT website_id, next_visit_at, last_execution_at,
                                retry_count, job_status, lease_expires_at
                         FROM scheduler_state WHERE website_id = ?1",
                            params![website_id],
                            scheduler_state_from_row,
                        )
                        .optional()?;
                    let Some(previous) = previous else {
                        return Ok(None);
                    };
                    let old_status = previous.job_status;
                    let claimable_status = match kind {
                        ClaimKind::Scheduled => {
                            matches!(old_status, JobStatus::Pending | JobStatus::Retry)
                        }
                        ClaimKind::Manual => matches!(
                            old_status,
                            JobStatus::Pending | JobStatus::Retry | JobStatus::Paused
                        ),
                    };
                    let due = match kind {
                        ClaimKind::Scheduled => {
                            previous.next_visit_at.map(|n| n <= now).unwrap_or(true)
                        }
                        ClaimKind::Manual => true,
                    };
                    if !claimable_status || !due {
                        return Ok(None);
                    }
                    let updated = tx.execute(
                        "UPDATE scheduler_state
                     SET job_status = 'running', lease_expires_at = ?2
                     WHERE website_id = ?1 AND job_status = ?3",
                        params![website_id, lease_s, old_status.as_str()],
                    )?;
                    if updated != 1 {
                        return Ok(None);
                    }
                    let claimed = tx.query_row(
                        "SELECT website_id, next_visit_at, last_execution_at,
                            retry_count, job_status, lease_expires_at
                     FROM scheduler_state WHERE website_id = ?1",
                        params![website_id],
                        scheduler_state_from_row,
                    )?;
                    tx.commit()?;
                    Ok(Some((old_status, claimed)))
                },
            )
            .await?;
        Ok(claimed)
    }
}

/// How the scheduler is claiming a job. See
/// [`Db::claim_website_job`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    /// Normal scheduled claim; requires the job to be due.
    Scheduled,
    /// Manual "visit now" claim; bypasses the interval/window gates.
    Manual,
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

// ---------------------------------------------------------------------------
// browser_events — coarse health/recycle milestones (SEG-06).
// ---------------------------------------------------------------------------

impl Db {
    /// Insert a `browser_events` row. `memory_usage` is the browser resident
    /// set size in bytes when relevant (e.g. `started`, `health_warn`).
    ///
    /// `event_type` is free text (no CHECK constraint in the schema); the
    /// values used by the process manager are: `started`, `health_warn`,
    /// `restarting`, `restarted`, `crashed`, `respawn_failed`, `crash_loop`,
    /// `stopped`. `details` carries PIDs, ports and reasons — never secrets.
    pub async fn insert_browser_event(
        &self,
        event_type: &str,
        memory_usage: Option<i64>,
        details: Option<&str>,
    ) -> Result<i64> {
        let event_type = event_type.to_owned();
        let details = details.map(str::to_owned);
        let timestamp = crate::db::models::format_db_ts(OffsetDateTime::now_utc())?;
        let id = self
            .connection()
            .call(move |c| -> rusqlite::Result<i64> {
                c.execute(
                    "INSERT INTO browser_events (event_type, timestamp, memory_usage, details)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![event_type, timestamp, memory_usage, details],
                )?;
                Ok(c.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }
}

// ---------------------------------------------------------------------------
// browser_profiles — CRUD (SEG-07)
// ---------------------------------------------------------------------------

/// Keep in sync with `browser::sessions::MAX_USER_AGENT_LEN`.
const MAX_USER_AGENT_LEN: usize = 512;

fn check_user_agent_len(ua: Option<&str>) -> Result<()> {
    if let Some(ua) = ua
        && ua.len() > MAX_USER_AGENT_LEN
    {
        return Err(super::DbError::Validation(format!(
            "user_agent must be at most {MAX_USER_AGENT_LEN} bytes, got {}",
            ua.len()
        )));
    }
    Ok(())
}

impl Db {
    /// Insert a browser profile. The `id` on the input is ignored; the
    /// `AUTOINCREMENT` id is returned. `user_agent` longer than
    /// [`MAX_USER_AGENT_LEN`] bytes is rejected with [`super::DbError::Validation`].
    pub async fn create_profile(&self, profile: &BrowserProfile) -> Result<i64> {
        check_user_agent_len(profile.user_agent.as_deref())?;
        let profile = profile.clone();
        let created_at = format_db_ts(profile.created_at)?;
        let updated_at = format_db_ts(profile.updated_at)?;
        let id = self
            .connection()
            .call(move |c| -> rusqlite::Result<i64> {
                c.execute(
                    "INSERT INTO browser_profiles
                        (name, description, user_agent, enabled,
                         configuration_json, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        profile.name,
                        profile.description,
                        profile.user_agent,
                        profile.enabled,
                        profile.configuration_json,
                        created_at,
                        updated_at,
                    ],
                )?;
                Ok(c.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    /// Fetch a single profile by id.
    pub async fn profile_by_id(&self, id: i64) -> Result<Option<BrowserProfile>> {
        let row = self
            .connection()
            .call(move |c| -> rusqlite::Result<Option<BrowserProfile>> {
                c.query_row(
                    &format!("SELECT {PROFILE_COLUMNS} FROM browser_profiles WHERE id = ?1"),
                    params![id],
                    browser_profile_from_row,
                )
                .optional()
            })
            .await?;
        Ok(row)
    }

    /// Fetch a single profile by its unique name.
    pub async fn profile_by_name(&self, name: &str) -> Result<Option<BrowserProfile>> {
        let name = name.to_owned();
        let row = self
            .connection()
            .call(move |c| -> rusqlite::Result<Option<BrowserProfile>> {
                c.query_row(
                    &format!("SELECT {PROFILE_COLUMNS} FROM browser_profiles WHERE name = ?1"),
                    params![name],
                    browser_profile_from_row,
                )
                .optional()
            })
            .await?;
        Ok(row)
    }

    /// All profiles, ordered by id.
    pub async fn list_profiles(&self) -> Result<Vec<BrowserProfile>> {
        let rows = self
            .connection()
            .call(|c| -> rusqlite::Result<Vec<BrowserProfile>> {
                let mut stmt = c.prepare(&format!(
                    "SELECT {PROFILE_COLUMNS} FROM browser_profiles ORDER BY id"
                ))?;
                let profiles = stmt
                    .query_map([], browser_profile_from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(profiles)
            })
            .await?;
        Ok(rows)
    }

    /// Update a profile. `updated_at` is always set to now by this function.
    /// Returns `true` when a row was actually updated.
    pub async fn update_profile(&self, profile: &BrowserProfile) -> Result<bool> {
        check_user_agent_len(profile.user_agent.as_deref())?;
        let profile = profile.clone();
        let updated_at = format_db_ts(OffsetDateTime::now_utc())?;
        let affected = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute(
                    "UPDATE browser_profiles SET
                        name = ?2, description = ?3, user_agent = ?4,
                        enabled = ?5, configuration_json = ?6, updated_at = ?7
                     WHERE id = ?1",
                    params![
                        profile.id,
                        profile.name,
                        profile.description,
                        profile.user_agent,
                        profile.enabled,
                        profile.configuration_json,
                        updated_at,
                    ],
                )
            })
            .await?;
        Ok(affected > 0)
    }

    /// Enable or disable a profile without touching any other column.
    /// Returns `true` when a row was actually updated.
    pub async fn set_profile_enabled(&self, id: i64, enabled: bool) -> Result<bool> {
        let updated_at = format_db_ts(OffsetDateTime::now_utc())?;
        let affected = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute(
                    "UPDATE browser_profiles SET enabled = ?2, updated_at = ?3
                     WHERE id = ?1",
                    params![id, enabled, updated_at],
                )
            })
            .await?;
        Ok(affected > 0)
    }

    /// Delete a profile. Its `cookies` rows cascade (`ON DELETE CASCADE`);
    /// websites that referenced it keep their configuration with
    /// `profile_id` set to NULL (`ON DELETE SET NULL`). Returns `true` when
    /// a row was actually deleted.
    pub async fn delete_profile(&self, id: i64) -> Result<bool> {
        let affected = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute("DELETE FROM browser_profiles WHERE id = ?1", params![id])
            })
            .await?;
        Ok(affected > 0)
    }
}

// ---------------------------------------------------------------------------
// cookies — encrypted jar rows, one per (profile_id, domain) (SEG-07)
// ---------------------------------------------------------------------------

impl Db {
    /// Insert or replace the cookie jar row for `(profile_id, domain)`.
    /// Returns the row id. `expires_at` is `MAX(per-cookie expiry)` —
    /// `None` when any cookie in the jar is a session cookie.
    pub async fn upsert_cookie_jar(
        &self,
        profile_id: i64,
        domain: &str,
        encrypted_cookie_data: &str,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<i64> {
        let domain = domain.to_owned();
        let data = encrypted_cookie_data.to_owned();
        let expires_at = expires_at.map(format_db_ts).transpose()?;
        let id = self
            .connection()
            .call(move |c| -> rusqlite::Result<i64> {
                c.execute(
                    "INSERT INTO cookies
                        (profile_id, domain, encrypted_cookie_data, expires_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                     ON CONFLICT(profile_id, domain) DO UPDATE SET
                        encrypted_cookie_data = excluded.encrypted_cookie_data,
                        expires_at = excluded.expires_at,
                        updated_at = excluded.updated_at",
                    params![profile_id, domain, data, expires_at],
                )?;
                Ok(c.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    /// All jars for a profile, ordered by domain.
    pub async fn list_cookie_jars(&self, profile_id: i64) -> Result<Vec<CookieRecord>> {
        let rows = self
            .connection()
            .call(move |c| -> rusqlite::Result<Vec<CookieRecord>> {
                let mut stmt = c.prepare(&format!(
                    "SELECT {COOKIE_COLUMNS} FROM cookies WHERE profile_id = ?1 ORDER BY domain"
                ))?;
                let jars = stmt
                    .query_map(params![profile_id], cookie_record_from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(jars)
            })
            .await?;
        Ok(rows)
    }

    /// Atomically replace the whole jar set of a profile: every existing
    /// `(profile_id, domain)` row is deleted, then the provided
    /// `(domain, data, expires_at)` tuples are inserted — in one transaction.
    /// This is the "live jar wins" policy (see `browser::sessions`).
    /// Returns the number of rows inserted.
    pub async fn replace_profile_cookies(
        &self,
        profile_id: i64,
        jars: Vec<(String, String, Option<OffsetDateTime>)>,
    ) -> Result<u64> {
        let jars = jars
            .into_iter()
            .map(|(domain, data, expires_at)| {
                Ok::<_, crate::db::DbError>((
                    domain,
                    data,
                    expires_at.map(format_db_ts).transpose()?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let inserted = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                let tx = c.transaction()?;
                tx.execute(
                    "DELETE FROM cookies WHERE profile_id = ?1",
                    params![profile_id],
                )?;
                let mut n = 0usize;
                {
                    let mut stmt = tx.prepare(
                        "INSERT INTO cookies
                            (profile_id, domain, encrypted_cookie_data, expires_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    )?;
                    for (domain, data, expires_at) in &jars {
                        stmt.execute(params![profile_id, domain, data, expires_at])?;
                        n += 1;
                    }
                }
                tx.commit()?;
                Ok(n)
            })
            .await?;
        Ok(inserted as u64)
    }

    /// Delete every cookie jar of a profile. Returns rows deleted.
    pub async fn delete_profile_cookies(&self, profile_id: i64) -> Result<u64> {
        let affected = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute(
                    "DELETE FROM cookies WHERE profile_id = ?1",
                    params![profile_id],
                )
            })
            .await?;
        Ok(affected as u64)
    }

    /// Delete the cookie jar for one `(profile_id, domain)`. Returns
    /// `true` when a row was deleted.
    pub async fn delete_profile_cookies_for_domain(
        &self,
        profile_id: i64,
        domain: &str,
    ) -> Result<u64> {
        let domain = domain.to_owned();
        let affected = self
            .connection()
            .call(move |c| -> rusqlite::Result<usize> {
                c.execute(
                    "DELETE FROM cookies WHERE profile_id = ?1 AND domain = ?2",
                    params![profile_id, domain],
                )
            })
            .await?;
        Ok(affected as u64)
    }
}
