//! Resource manager — `/proc` parsers, the 512 MB budget self-check and the
//! pre-flight memory guard (SEG-15).
//!
//! No `sysinfo` crate; everything is parsed from `/proc` directly. The
//! parsers are pure string functions so they can be unit-tested against
//! fixtures. The live readers ([`mem_available_mb`], [`app_rss_mb`],
//! [`sys_total_mb`]) are thin wrappers returning `Option` — a machine
//! without `/proc` (or a hook read) degrades to "unknown", never to a panic.

use crate::browser::manager::BrowserStats;
use crate::db::Db;
use crate::scheduler::SchedulerHandle;

/// MemAvailable (MB) below which starting a new visit is refused. Below this
/// the box (512 MB target) cannot absorb a browser page load without risking
/// an OOM kill. The refusal is transient: the scheduler retries with backoff.
pub const RESOURCE_GUARD_MIN_AVAILABLE_MB: u64 = 120;

/// MemAvailable (MB) below which boot logs a `tight_memory` warning and the
/// dashboard shows a banner. The app still runs.
pub const TIGHT_BUDGET_MIN_AVAILABLE_MB: u64 = 350;

// ---------------------------------------------------------------------------
// Pure parsers (unit-tested against fixtures)
// ---------------------------------------------------------------------------

/// Value of `key` in `/proc/meminfo` content, in kB. The line looks like
/// `MemAvailable:   123456 kB`; other units are rejected.
fn parse_meminfo_kb(meminfo: &str, key: &str) -> Option<u64> {
    for line in meminfo.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        // Guard against a prefix hit on a longer key name ("MemTotal" vs
        // "MemTotalExtra"): the character after the key must be ':'.
        let Some(rest) = rest.strip_prefix(':') else {
            continue;
        };
        let value = rest.trim().strip_suffix("kB")?.trim();
        return value.parse::<u64>().ok();
    }
    None
}

/// Parse the MemAvailable line of `/proc/meminfo` content, in MB.
pub(crate) fn parse_mem_available_mb(meminfo: &str) -> Option<u64> {
    parse_meminfo_kb(meminfo, "MemAvailable").map(|kb| kb / 1024)
}

/// Parse the MemTotal line of `/proc/meminfo` content, in MB.
pub(crate) fn parse_mem_total_mb(meminfo: &str) -> Option<u64> {
    parse_meminfo_kb(meminfo, "MemTotal").map(|kb| kb / 1024)
}

/// Parse VmRSS from `/proc/self/status` content, in MB.
pub(crate) fn parse_app_rss_mb(status: &str) -> Option<u64> {
    crate::browser::manager::parse_vm_rss_kb(status).map(|kb| kb / 1024)
}

// ---------------------------------------------------------------------------
// Live readers
// ---------------------------------------------------------------------------

/// MemAvailable of the whole host in MB (`/proc/meminfo`). `None` when the
/// file is unreadable or the line is missing.
pub fn mem_available_mb() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_mem_available_mb(&raw)
}

/// MemTotal of the whole host in MB (`/proc/meminfo`). Used for boot
/// diagnostics and the `mem_total_mb` field of `/api/system`.
pub fn sys_total_mb() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_mem_total_mb(&raw)
}

/// Resident set size of this process in MB (`/proc/self/status`).
pub fn app_rss_mb() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_app_rss_mb(&raw)
}

// ---------------------------------------------------------------------------
// Guard / budget decisions (pure — the live checks are one-liners over these)
// ---------------------------------------------------------------------------

/// Boot self-check: too little headroom for the 512 MB target.
///
/// `total_mb` is accepted for symmetry with the boot log line (both totals
/// are logged when this fires); the decision is strictly
/// `MemAvailable < TIGHT_BUDGET_MIN_AVAILABLE_MB`.
pub fn tight_budget(_total_mb: u64, avail_mb: u64) -> bool {
    avail_mb < TIGHT_BUDGET_MIN_AVAILABLE_MB
}

/// Pre-flight guard: refuse to start a visit when `MemAvailable` is below
/// [`RESOURCE_GUARD_MIN_AVAILABLE_MB`]. Pure, so the boundary is unit-tested.
pub fn should_refuse(avail_mb: u64) -> bool {
    avail_mb < RESOURCE_GUARD_MIN_AVAILABLE_MB
}

// ---------------------------------------------------------------------------
// Snapshot assembly for /api/system
// ---------------------------------------------------------------------------

/// Assembled resource snapshot behind `/api/system`. All numeric fields are
/// concrete numbers (`0` when the value could not be read) so the JSON stays
/// fully typed.
#[derive(Debug, Clone)]
pub struct ResourceSnapshot {
    pub app_rss_mb: u64,
    /// `None` when the browser feature is disabled (binary missing) or the
    /// manager has not sampled yet in a meaningful way.
    pub lightpanda: Option<BrowserStats>,
    pub mem_available_mb: u64,
    pub mem_total_mb: u64,
    pub queue_length: usize,
    pub db_size_mb: f64,
}

impl ResourceSnapshot {
    /// Collect the live snapshot. A database error on [`Db::db_size_mb`]
    /// degrades `db_size_mb` to `0.0` — the endpoint never fails on this.
    pub async fn collect(
        db: &Db,
        manager: Option<&crate::browser::manager::BrowserManager>,
        scheduler: Option<&SchedulerHandle>,
    ) -> Self {
        Self {
            app_rss_mb: app_rss_mb().unwrap_or(0),
            lightpanda: manager.map(|m| m.stats()),
            mem_available_mb: mem_available_mb().unwrap_or(0),
            mem_total_mb: sys_total_mb().unwrap_or(0),
            queue_length: scheduler.map(|s| s.queue_length()).unwrap_or(0),
            db_size_mb: db.db_size_mb().await.unwrap_or(0.0),
        }
    }
}

// ---------------------------------------------------------------------------
// db_size_warn enforcement (called after every retention pass)
// ---------------------------------------------------------------------------

/// Check `db_size_mb` against the `db_size_warn_mb` setting (advisory). On
/// breach, emit a `tracing::warn!` and record a `db_size_warn` row in
/// `browser_events` (`details` carries `db_size_mb=X threshold=Y`; never
/// secrets). Best-effort: failures are logged, never propagated.
pub async fn enforce_db_size_warn(db: &Db) {
    let db_size_mb = match db.db_size_mb().await {
        Ok(mb) => mb,
        Err(e) => {
            tracing::error!(error = %e, "db_size_warn: failed to measure database size");
            return;
        }
    };
    let threshold_mb = crate::config::typed_i64(db, "db_size_warn_mb")
        .await
        .unwrap_or(64);
    if db_size_mb > threshold_mb as f64 {
        tracing::warn!(
            db_size_mb,
            threshold_mb,
            "database size exceeds db_size_warn_mb"
        );
        let details = format!("db_size_mb={db_size_mb:.1} threshold={threshold_mb}");
        if let Err(e) = db
            .insert_browser_event("db_size_warn", None, Some(&details))
            .await
        {
            tracing::error!(error = %e, "db_size_warn: failed to record browser_events row");
        }
    }
}

// ---------------------------------------------------------------------------
// Application RSS watchdog (SEG-15)
// ---------------------------------------------------------------------------

/// App RSS (MB) above which the watchdog counts a sample as "over threshold".
pub const APP_RSS_WARN_MB: u64 = 60;

/// Sustained-over-threshold window before `app_memory_high` is emitted.
const SUSTAINED_WINDOW_S: u64 = 300;

/// Minimum gap between two `app_memory_high` events.
const EMIT_RATE_LIMIT_S: u64 = 900;

/// State for the application-RSS watchdog. Pure data — advanced one sample
/// at a time by [`tick`].
#[derive(Debug, Default)]
pub struct WatchdogState {
    /// Consecutive samples strictly above [`APP_RSS_WARN_MB`].
    consecutive_over: u32,
    /// Monotonic sample counter (one per [`tick`] call).
    sample_seq: u64,
    /// `sample_seq` of the last emitted `app_memory_high`, if any.
    last_emit_seq: Option<u64>,
}

impl WatchdogState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Details of an `app_memory_high` emission decided by [`tick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogEmission {
    /// The RSS sample (MB) that tripped the watchdog.
    pub rss_mb: u64,
    /// How long the app has been over threshold, `consecutive_over * interval_s`.
    pub sustained_s: u64,
}

fn ceil_div(a: u64, b: u64) -> u64 {
    a.div_ceil(b)
}

/// Advance the watchdog by one sample. `interval_s` is the poll interval in
/// seconds (clamped to ≥1). Returns `Some(..)` exactly when an
/// `app_memory_high` event should be recorded: the consecutive over-threshold
/// count has reached `ceil(300 / interval_s)` and no event was emitted within
/// the last `ceil(900 / interval_s)` samples. A sample at or below the
/// threshold resets the consecutive counter (the rate-limit window is kept).
pub(crate) fn tick(
    state: &mut WatchdogState,
    rss_mb: u64,
    interval_s: i64,
) -> Option<WatchdogEmission> {
    let interval = interval_s.max(1) as u64;
    state.sample_seq += 1;
    if rss_mb <= APP_RSS_WARN_MB {
        state.consecutive_over = 0;
        return None;
    }
    state.consecutive_over += 1;
    let needed = ceil_div(SUSTAINED_WINDOW_S, interval);
    if u64::from(state.consecutive_over) < needed {
        return None;
    }
    let rate_limit_samples = ceil_div(EMIT_RATE_LIMIT_S, interval);
    if let Some(last) = state.last_emit_seq
        && state.sample_seq - last < rate_limit_samples
    {
        return None;
    }
    state.last_emit_seq = Some(state.sample_seq);
    Some(WatchdogEmission {
        rss_mb,
        sustained_s: u64::from(state.consecutive_over) * interval,
    })
}

/// Spawn the application-RSS watchdog: every `rss_poll_interval_s` seconds
/// (re-read live on each iteration) sample [`app_rss_mb`] and, after a
/// sustained 5-minute over-threshold stretch, record an `app_memory_high`
/// row in `browser_events` (`memory_usage` = RSS in bytes). Rate-limited to
/// one event per 15 minutes. Never panics — unreadable settings or `/proc`
/// samples just skip the tick. Lives until the runtime drops it at process
/// exit.
pub fn spawn_app_rss_watchdog(db: Db) {
    tokio::spawn(async move {
        let mut state = WatchdogState::new();
        loop {
            let interval_s = match crate::config::typed_i64(&db, "rss_poll_interval_s").await {
                Ok(v) => v.clamp(1, 3600),
                Err(e) => {
                    tracing::error!(error = %e, "app_rss_watchdog: unreadable rss_poll_interval_s; skipping tick");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };
            tokio::time::sleep(std::time::Duration::from_secs(interval_s as u64)).await;
            let Some(rss_mb) = app_rss_mb() else {
                continue;
            };
            let Some(emission) = tick(&mut state, rss_mb, interval_s) else {
                continue;
            };
            let sustained_s = emission.sustained_s;
            let details = format!(
                "app_rss_mb={} threshold={} sustained={}s",
                emission.rss_mb, APP_RSS_WARN_MB, sustained_s
            );
            tracing::warn!(
                app_rss_mb = emission.rss_mb,
                sustained_s,
                "application RSS above 60 MB sustained; recording app_memory_high"
            );
            let rss_bytes = (emission.rss_mb as i64) * 1024 * 1024;
            if let Err(e) = db
                .insert_browser_event("app_memory_high", Some(rss_bytes), Some(&details))
                .await
            {
                tracing::error!(error = %e, "app_rss_watchdog: failed to record browser_events row");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMINFO_8G: &str = "\
MemTotal:        8167824 kB
MemFree:         1024000 kB
MemAvailable:    5123456 kB
Buffers:          200000 kB
Cached:          1500000 kB
SwapCached:            0 kB
";

    const STATUS_SAMPLE: &str = "\
Name:\tuptimepanda
Umask:\t0022
State:\tS (sleeping)
VmPeak:\t  245760 kB
VmSize:\t  245760 kB
VmRSS:\t   20480 kB
VmData:\t   10240 kB
Threads:\t12
";

    #[test]
    fn meminfo_fixture_parses_available_and_total() {
        assert_eq!(parse_mem_available_mb(MEMINFO_8G), Some(5003)); // 5123456 kB / 1024
        assert_eq!(parse_mem_total_mb(MEMINFO_8G), Some(7976)); // 8167824 kB / 1024
    }

    #[test]
    fn meminfo_missing_memavailable_is_none() {
        let no_available = "MemTotal:        8167824 kB\nMemFree:         1024000 kB\n";
        assert_eq!(parse_mem_available_mb(no_available), None);
        assert_eq!(parse_mem_available_mb(""), None);
        assert_eq!(parse_mem_available_mb("MemAvailable:\n"), None);
        assert_eq!(
            parse_mem_available_mb("MemAvailable: not-a-number kB\n"),
            None
        );
        // Wrong unit is rejected rather than misparsed.
        assert_eq!(parse_mem_available_mb("MemAvailable: 1024 MB\n"), None);
        // A key that merely starts with the name must not match.
        assert_eq!(
            parse_mem_available_mb("MemAvailableExtra: 1024000 kB\n"),
            None
        );
    }

    #[test]
    fn status_fixture_parses_app_rss() {
        assert_eq!(parse_app_rss_mb(STATUS_SAMPLE), Some(20)); // 20480 kB / 1024
        assert_eq!(parse_app_rss_mb("Name:\tx\n"), None);
    }

    #[test]
    fn tight_budget_matrix() {
        // Below 350 MB available → tight, regardless of total.
        assert!(tight_budget(512, 0));
        assert!(tight_budget(512, 349));
        assert!(tight_budget(8192, 100));
        // At/above the threshold → not tight.
        assert!(!tight_budget(512, 350));
        assert!(!tight_budget(512, 2048));
        assert!(!tight_budget(8192, 5123456 / 1024));
    }

    // --- db_size_warn enforcement (real in-memory database) ---

    fn test_website() -> crate::db::Website {
        let now = time::OffsetDateTime::now_utc();
        crate::db::Website {
            id: 0,
            name: "warn-test".to_string(),
            url: "https://warn-test.example.com/".to_string(),
            enabled: true,
            profile_id: None,
            monitoring_mode: crate::db::MonitoringMode::Basic,
            min_interval_seconds: 480,
            max_interval_seconds: 780,
            min_session_seconds: 15,
            max_session_seconds: 60,
            last_visit_at: None,
            next_visit_at: None,
            created_at: now,
            updated_at: now,
            active_window_start: None,
            active_window_end: None,
            timezone: None,
        }
    }

    #[tokio::test]
    async fn db_size_warn_no_event_when_under_threshold() {
        let db = crate::db::Db::in_memory().await.expect("db");
        crate::config::seed_settings(&db).await.expect("seed");
        enforce_db_size_warn(&db).await;
        let events = db.recent_browser_events(10).await.expect("events");
        assert!(
            events.iter().all(|e| e.event_type != "db_size_warn"),
            "under-threshold database must not record db_size_warn"
        );
    }

    #[tokio::test]
    async fn db_size_warn_records_event_when_over_threshold() {
        let db = crate::db::Db::in_memory().await.expect("db");
        crate::config::seed_settings(&db).await.expect("seed");
        // Lower the threshold to the validator's floor (16 MB).
        db.upsert_application_setting("db_size_warn_mb", "16")
            .await
            .expect("set threshold");
        let website_id = db.insert_website(&test_website()).await.expect("insert");
        // Push the main database past 16 MB with one large row.
        let big = "x".repeat(17 * 1024 * 1024);
        let now = time::OffsetDateTime::now_utc();
        db.record_visit(&crate::db::VisitHistoryRow {
            id: 0,
            website_id,
            profile_id: None,
            started_at: now,
            completed_at: Some(now),
            duration_ms: Some(1),
            http_status: None,
            final_url: None,
            outcome: crate::db::Outcome::Success,
            error_message: Some(big),
            browser_pid: None,
            memory_usage: None,
        })
        .await
        .expect("record big visit");
        let size_mb = db.db_size_mb().await.expect("measure");
        assert!(size_mb > 16.0, "fixture must exceed 16 MB, got {size_mb}");

        enforce_db_size_warn(&db).await;
        let events = db.recent_browser_events(10).await.expect("events");
        let warn = events
            .iter()
            .find(|e| e.event_type == "db_size_warn")
            .expect("db_size_warn event recorded");
        let details = warn.details.as_deref().unwrap_or_default();
        assert!(details.contains("db_size_mb="), "{details}");
        assert!(details.contains("threshold=16"), "{details}");
    }

    #[test]
    fn resource_guard_boundary() {
        assert!(should_refuse(0));
        assert!(should_refuse(119));
        assert!(!should_refuse(120)); // exactly at the floor: allowed
        assert!(!should_refuse(121));
        assert!(!should_refuse(4096));
    }

    // --- app RSS watchdog state machine ---

    #[test]
    fn watchdog_emits_after_sustained_window_at_5s_interval() {
        let mut s = WatchdogState::new();
        // ceil(300/5) = 60 consecutive over-threshold samples required.
        for i in 1..60 {
            assert_eq!(tick(&mut s, 61, 5), None, "sample {i} must not emit yet");
        }
        let ev = tick(&mut s, 61, 5).expect("60th consecutive sample emits");
        assert_eq!(ev.rss_mb, 61);
        assert_eq!(ev.sustained_s, 300);
    }

    #[test]
    fn watchdog_emits_after_sustained_window_at_60s_interval() {
        let mut s = WatchdogState::new();
        // ceil(300/60) = 5 consecutive over-threshold samples required.
        for _ in 0..4 {
            assert_eq!(tick(&mut s, 100, 60), None);
        }
        let ev = tick(&mut s, 100, 60).expect("5th consecutive sample emits");
        assert_eq!(ev.sustained_s, 300);
    }

    #[test]
    fn watchdog_dip_resets_consecutive_counter() {
        let mut s = WatchdogState::new();
        for _ in 0..59 {
            assert_eq!(tick(&mut s, 61, 5), None);
        }
        // Dip at/below the threshold resets the streak.
        assert_eq!(tick(&mut s, 60, 5), None);
        for _ in 0..59 {
            assert_eq!(tick(&mut s, 61, 5), None);
        }
        let ev = tick(&mut s, 61, 5).expect("full streak after dip emits");
        assert_eq!(ev.sustained_s, 300);
    }

    #[test]
    fn watchdog_rate_limits_to_one_event_per_15_minutes() {
        let mut s = WatchdogState::new();
        // First emission at sample 60 (60 * 5s = 300s sustained).
        for _ in 0..59 {
            assert_eq!(tick(&mut s, 61, 5), None);
        }
        assert!(tick(&mut s, 61, 5).is_some());
        // Samples 61..=179 (119 more, 600s elapsed) stay under the 15-min
        // rate limit: ceil(900/5) = 180 samples between emissions.
        for i in 61..180 {
            assert_eq!(tick(&mut s, 61, 5), None, "sample {i} rate-limited");
        }
        // Sample 240 would be 15 min after sample 60... use exact window:
        // last emission at seq 60, rate limit 180 samples → seq 240 emits.
        for i in 180..240 {
            assert_eq!(tick(&mut s, 61, 5), None, "sample {i} still rate-limited");
        }
        assert!(tick(&mut s, 61, 5).is_some(), "window elapsed, emits again");
    }

    #[test]
    fn watchdog_sample_at_threshold_is_not_over() {
        let mut s = WatchdogState::new();
        assert_eq!(tick(&mut s, 60, 5), None);
        assert_eq!(s.consecutive_over, 0);
    }

    #[test]
    fn watchdog_zero_or_negative_interval_is_clamped() {
        let mut s = WatchdogState::new();
        // interval_s <= 0 must not panic or divide by zero; clamped to 1s,
        // so ceil(300/1) = 300 samples needed.
        assert_eq!(tick(&mut s, 61, 0), None);
        assert_eq!(tick(&mut s, 61, -5), None);
    }
}
