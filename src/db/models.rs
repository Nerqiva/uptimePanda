//! Row models — the transport types shared with later segments.
//!
//! All timestamps are RFC 3339 UTC `TEXT` in SQLite and
//! [`OffsetDateTime`] in Rust. Values written by this module use the exact
//! shape produced by the column defaults (`strftime('%Y-%m-%dT%H:%M:%fZ','now')`,
//! i.e. `YYYY-MM-DDTHH:MM:SS.fffZ`) so lexicographic ordering in SQL matches
//! chronological ordering.
//!
//! Booleans are SQLite `INTEGER` 0/1 in the database and plain `bool` in Rust.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Format used for every timestamp this module writes to SQLite, matching the
/// `strftime('%Y-%m-%dT%H:%M:%fZ','now')` column defaults.
pub(crate) const DB_TIMESTAMP_FORMAT: &[time::format_description::FormatItem<'_>] = time::macros::format_description!(
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
);

/// Format a timestamp as stored in SQLite.
pub(crate) fn format_db_ts(t: OffsetDateTime) -> crate::db::Result<String> {
    Ok(t.format(DB_TIMESTAMP_FORMAT)?)
}

/// Parse a stored timestamp back into an `OffsetDateTime`.
///
/// Accepts both the `...Z` shape written by this module (and by the column
/// defaults) and any other valid RFC 3339 offset — lexicographic ordering is
/// only guaranteed among values written through this module.
pub(crate) fn parse_db_ts(s: &str, col: usize) -> rusqlite::Result<OffsetDateTime> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Parse a stored timestamp into an `Option<OffsetDateTime>` (NULL-aware).
pub(crate) fn parse_db_ts_opt(
    s: Option<String>,
    col: usize,
) -> rusqlite::Result<Option<OffsetDateTime>> {
    s.map(|v| parse_db_ts(&v, col)).transpose()
}

macro_rules! db_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// SQLite `TEXT` value stored in the database.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }

            /// Reverse of [`Self::as_str`].
            pub fn from_db_str(col: usize, s: &str) -> rusqlite::Result<Self> {
                match s {
                    $($text => Ok(Self::$variant),)+
                    other => Err(rusqlite::Error::FromSqlConversionFailure(
                        col,
                        rusqlite::types::Type::Text,
                        format!("invalid {:?} value: {other:?}", stringify!($name)).into(),
                    )),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

db_enum! {
    /// `websites.monitoring_mode`.
    MonitoringMode {
        Basic => "basic",
        Interaction => "interaction",
    }
}

db_enum! {
    /// `visit_history.outcome`.
    Outcome {
        Success => "success",
        Timeout => "timeout",
        NavigationError => "navigation_error",
        BrowserCrash => "browser_crash",
        InteractionError => "interaction_error",
    }
}

db_enum! {
    /// `scheduler_state.job_status`.
    JobStatus {
        Pending => "pending",
        Running => "running",
        Paused => "paused",
        Retry => "retry",
        Disabled => "disabled",
    }
}

/// `websites` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Website {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub profile_id: Option<i64>,
    pub monitoring_mode: MonitoringMode,
    pub min_interval_seconds: i64,
    pub max_interval_seconds: i64,
    pub min_session_seconds: i64,
    pub max_session_seconds: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_visit_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub next_visit_at: Option<OffsetDateTime>,
    /// `"HH:MM"` local wall-clock start of the daily active monitoring
    /// window, interpreted in `timezone`. `NULL` (or a missing end)
    /// means the website is always active. Added in schema v2.
    pub active_window_start: Option<String>,
    /// `"HH:MM"` local wall-clock end of the daily active monitoring window
    /// (may wrap past midnight, e.g. `22:00`–`06:00`). `NULL` means always
    /// active. Added in schema v2.
    pub active_window_end: Option<String>,
    /// IANA timezone name (e.g. `Europe/Berlin`) for the window; `NULL`
    /// falls back to the deployment `TZ` (itself defaulting to `UTC`).
    /// Added in schema v2.
    pub timezone: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// `browser_profiles` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserProfile {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub user_agent: Option<String>,
    pub enabled: bool,
    pub configuration_json: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// `cookies` row. Only the encrypted blob is ever stored or transported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CookieRecord {
    pub id: i64,
    pub profile_id: i64,
    pub domain: String,
    /// Encrypted cookie payload (`enc:v1:` envelope, base64). Never plaintext.
    pub encrypted_cookie_data: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// `interaction_sequences` row (one per website, max).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InteractionSequence {
    pub id: i64,
    pub website_id: i64,
    pub enabled: bool,
    pub configuration_json: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// `visit_history` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisitHistoryRow {
    /// Ignored on insert (`AUTOINCREMENT` assigns the real id).
    pub id: i64,
    pub website_id: i64,
    pub profile_id: Option<i64>,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
    /// Whole-visit duration in milliseconds.
    pub duration_ms: Option<i64>,
    pub http_status: Option<i64>,
    pub final_url: Option<String>,
    pub outcome: Outcome,
    pub error_message: Option<String>,
    pub browser_pid: Option<i64>,
    /// Resident set size of the browser in bytes, sampled during the visit.
    pub memory_usage: Option<i64>,
}

/// `scheduler_state` row — persistent source of truth for the scheduler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchedulerState {
    pub website_id: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    pub next_visit_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_execution_at: Option<OffsetDateTime>,
    pub retry_count: i64,
    pub job_status: JobStatus,
    #[serde(with = "time::serde::rfc3339::option")]
    pub lease_expires_at: Option<OffsetDateTime>,
}

/// `browser_events` row — coarse health/recycle milestones only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserEvent {
    pub id: i64,
    pub event_type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Browser resident set size in bytes, when relevant to the event.
    pub memory_usage: Option<i64>,
    pub details: Option<String>,
}

/// `application_settings` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Setting {
    pub setting_key: String,
    pub setting_value: String,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Result of [`crate::db::Db::cleanup_expired_history`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupStats {
    /// Rows deleted from `visit_history` (older than the retention cutoff).
    pub visit_history_deleted: u64,
    /// Rows deleted from `browser_events` (only to trim the table to 500).
    pub browser_events_deleted: u64,
}
