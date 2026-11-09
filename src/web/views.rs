//! View models for askama templates (SEG-11).
//!
//! Everything user-facing is pre-formatted here — templates stay dumb.
//! Values are plain data; askama escapes everything by default.

use askama::Template;
use time::OffsetDateTime;

use crate::browser::sessions::USER_AGENT_PRESETS;
use crate::db::models::Outcome;
use crate::web::templates::LayoutChrome;

// ---------------------------------------------------------------------------
// Toast / small fragments
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "partials/toast.html")]
pub struct ToastPartial {
    pub kind: &'static str,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

pub struct OverviewStats {
    pub websites_total: i64,
    pub websites_enabled: i64,
    pub active: i64,
    pub visits_24h: i64,
    pub success_24h: i64,
    pub fail_24h: i64,
    pub success_rate: String,
    pub browser_running: bool,
    pub browser_sub: String,
    pub browser_rss_mb: String,
    pub mem_restart_mb: i64,
    pub mem_warn_mb: i64,
    pub next_visit: String,
    pub queue_len: usize,
}

#[derive(Template)]
#[template(path = "overview.html")]
pub struct OverviewPage {
    pub chrome: LayoutChrome,
    pub stats: OverviewStats,
    /// Next five scheduled visits, earliest first. Empty-state rendered
    /// by the template when this is empty.
    pub upcoming: Vec<UpcomingVisitView>,
}

/// One row of the overview "Upcoming visits" table.
pub struct UpcomingVisitView {
    pub website_name: String,
    pub profile_name: String,
    /// `fmt_ts_local` + relative suffix, e.g. `2026-11-09 15:04:05 Asia/Omsk`.
    pub next_visit_label: String,
    pub time_until_label: String,
}

#[derive(Template)]
#[template(path = "partials/overview_grid.html")]
pub struct OverviewGridFragment {
    pub stats: OverviewStats,
}

// ---------------------------------------------------------------------------
// Websites
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct WebsiteRowView {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub host_path: String,
    pub mode: String,
    pub enabled: bool,
    /// `\" \"` when unset — matches the `<option value=\"\">` for the default.
    pub profile_id_label: String,
    pub min_interval_seconds: i64,
    pub max_interval_seconds: i64,
    pub min_session_seconds: i64,
    pub max_session_seconds: i64,
    pub interval_label: String,
    pub last_visit_label: String,
}

#[derive(Clone)]
pub struct WebsiteEntryView {
    pub website: WebsiteRowView,
    pub profile_name: String,
    pub paused: bool,
    pub next_visit_label: String,
}

#[derive(Clone)]
pub struct ProfileOptionView {
    pub id: i64,
    pub name: String,
}

#[derive(Template)]
#[template(path = "websites.html")]
pub struct WebsitesPage {
    pub chrome: LayoutChrome,
    pub entries: Vec<WebsiteEntryView>,
    pub profiles: Vec<ProfileOptionView>,
    pub form_error: String,
    /// Prefills for the "Add website" form, read live from the
    /// `default_*` settings keys (SEG-14 hot-apply).
    pub default_min_interval_seconds: i64,
    pub default_max_interval_seconds: i64,
    pub default_min_session_seconds: i64,
    pub default_max_session_seconds: i64,
}

#[derive(Template)]
#[template(path = "partials/websites_table.html")]
pub struct WebsitesTableFragment {
    pub chrome: LayoutChrome,
    pub entries: Vec<WebsiteEntryView>,
    pub oob: bool,
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ProfileEntryView {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub user_agent: String,
    pub ua_preset: String,
    pub ua_label: String,
    pub cookie_count: i64,
    pub earliest_expiry: String,
    pub assigned: String,
}

#[derive(Clone)]
pub struct UaPresetView {
    pub id: &'static str,
    pub label: &'static str,
}

pub const UA_PRESET_VIEWS: [UaPresetView; 4] = [
    UaPresetView {
        id: USER_AGENT_PRESETS[0].id,
        label: USER_AGENT_PRESETS[0].label,
    },
    UaPresetView {
        id: USER_AGENT_PRESETS[1].id,
        label: USER_AGENT_PRESETS[1].label,
    },
    UaPresetView {
        id: USER_AGENT_PRESETS[2].id,
        label: USER_AGENT_PRESETS[2].label,
    },
    UaPresetView {
        id: USER_AGENT_PRESETS[3].id,
        label: USER_AGENT_PRESETS[3].label,
    },
];

#[derive(Template)]
#[template(path = "profiles.html")]
pub struct ProfilesPage {
    pub chrome: LayoutChrome,
    pub entries: Vec<ProfileEntryView>,
    pub presets: &'static [UaPresetView],
}

#[derive(Template)]
#[template(path = "partials/profiles_grid.html")]
pub struct ProfilesGridFragment {
    pub chrome: LayoutChrome,
    pub entries: Vec<ProfileEntryView>,
    pub oob: bool,
}

// ---------------------------------------------------------------------------
// Interactions editor
// ---------------------------------------------------------------------------

pub struct InteractionLimitsView {
    pub max_actions: usize,
    pub total_budget_s: u64,
    pub max_click_wait_ms: u64,
    pub max_scroll_ops: u32,
}

#[derive(Template)]
#[template(path = "interactions.html")]
pub struct InteractionsPage {
    pub chrome: LayoutChrome,
    pub website_id: i64,
    pub website_name: String,
    pub enabled: bool,
    pub action_count: usize,
    pub mode_label: String,
    pub sequence_json: String,
    pub errors: Vec<String>,
    pub limits: InteractionLimitsView,
}

#[derive(Template)]
#[template(path = "partials/form_error.html")]
pub struct FormErrorFragment {
    pub id: String,
    pub message: String,
    pub oob: bool,
}

#[derive(Template)]
#[template(path = "partials/interaction_errors.html")]
pub struct InteractionErrorsFragment {
    pub oob: bool,
    pub errors: Vec<String>,
}

#[derive(Template)]
#[template(path = "partials/interaction_textarea.html")]
pub struct InteractionTextareaFragment {
    pub oob: bool,
    pub sequence_json: String,
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

pub struct OutcomeOptionView {
    pub value: &'static str,
    pub label: &'static str,
}

/// One chip on the browser-events table filter on the System page.
pub struct EventTypeOptionView {
    pub value: &'static str,
    pub label: &'static str,
}

/// The six event types the System page offers as filter chips. `all` is
/// handled implicitly (no `event_type` query param).
pub const EVENT_TYPE_OPTIONS: [EventTypeOptionView; 6] = [
    EventTypeOptionView {
        value: "restarting",
        label: "restarting",
    },
    EventTypeOptionView {
        value: "restarted",
        label: "restarted",
    },
    EventTypeOptionView {
        value: "crashed",
        label: "crashed",
    },
    EventTypeOptionView {
        value: "health_warn",
        label: "health_warn",
    },
    EventTypeOptionView {
        value: "db_size_warn",
        label: "db_size_warn",
    },
    EventTypeOptionView {
        value: "app_memory_high",
        label: "app_memory_high",
    },
];

/// Type guard for the `event_type` query param: only the six known
/// values are honoured; anything else falls back to "all".
pub fn normalize_event_type(raw: Option<&str>) -> Option<&'static str> {
    let raw = raw?.trim();
    EVENT_TYPE_OPTIONS
        .iter()
        .find(|o| o.value == raw)
        .map(|o| o.value)
}

pub const OUTCOME_OPTIONS: [OutcomeOptionView; 5] = [
    OutcomeOptionView {
        value: "success",
        label: "success",
    },
    OutcomeOptionView {
        value: "timeout",
        label: "timeout",
    },
    OutcomeOptionView {
        value: "navigation_error",
        label: "navigation_error",
    },
    OutcomeOptionView {
        value: "browser_crash",
        label: "browser_crash",
    },
    OutcomeOptionView {
        value: "interaction_error",
        label: "interaction_error",
    },
];

#[derive(Clone)]
pub struct WebsiteOptionView {
    pub id: i64,
    pub name: String,
}

/// One filter chip on the history page (outcomes) — precomputed href so
/// the template never string-builds URLs.
pub struct ChipView {
    pub label: String,
    pub href: String,
    pub active: bool,
}

#[derive(Clone)]
pub struct HistoryRowView {
    pub started_label: String,
    pub website_name: String,
    pub profile_name: String,
    pub duration_label: String,
    pub outcome: String,
    pub outcome_class: &'static str,
    pub http_status: String,
    pub error: String,
}

#[derive(Template)]
#[template(path = "history.html")]
pub struct HistoryPage {
    pub chrome: LayoutChrome,
    pub websites: Vec<WebsiteOptionView>,
    pub selected_website: i64,
    /// Outcome filter chips (value `all` first), hrefs precomputed so each
    /// preserves the current `website_id`.
    pub outcome_chips: Vec<ChipView>,
    pub selected_outcome: String,
    pub total: i64,
    pub page: i64,
    pub total_pages: i64,
    pub filter_query: String,
    pub entries: Vec<HistoryRowView>,
}

#[derive(Template)]
#[template(path = "partials/history_rows.html")]
pub struct HistoryRowsFragment {
    pub entries: Vec<HistoryRowView>,
    pub page: i64,
    pub total_pages: i64,
    pub filter_query: String,
    pub oob: bool,
}

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct BrowserEventView {
    pub timestamp_label: String,
    pub event_type: String,
    pub warn: bool,
    pub memory_label: String,
    pub details: String,
}

/// One `.db` file in BACKUP_DIR, for the System page backup list.
pub struct BackupFileView {
    /// Bare filename — validated by the caller; rendered escaped.
    pub name: String,
    pub size_label: String,
    pub mtime_label: String,
}

/// One chip on the browser-events `event_type` filter — href precomputed.
pub struct EventTypeChipView {
    pub label: &'static str,
    pub href: String,
    pub active: bool,
}

#[derive(Template)]
#[template(path = "system.html")]
pub struct SystemPage {
    pub chrome: LayoutChrome,
    pub browser_available: bool,
    pub events: Vec<BrowserEventView>,
    pub stats: SystemStatsView,
    /// Listed `.db` files in BACKUP_DIR, newest first.
    pub backups: Vec<BackupFileView>,
    /// Render the restore-pending banner (flag or `application_settings`
    /// row — whichever says a restore is pending).
    pub restore_pending: bool,
    /// Currently selected `event_type` filter (`""` = all).
    pub event_type: String,
    /// Event-type filter chips (the six known types), hrefs precomputed.
    pub event_type_chips: Vec<EventTypeChipView>,
}

pub struct SystemStatsView {
    pub browser_running: bool,
    pub browser_sub: String,
    pub rss_mb: String,
    pub rss_mb_int: u64,
    pub mem_restart_mb: i64,
    pub rss_ratio: String,
    pub cpu_pct: String,
    pub uptime_label: String,
    pub restarts_total: u64,
    pub queue_len: usize,
    pub next_visit: String,
    pub db_size_mb: String,
    pub mem_available_mb: String,
    /// This process's RSS (`/proc/self/status`), MB.
    pub app_rss_mb: String,
    /// MemAvailable < 350 MB — drives the tight-budget badge.
    pub tight_budget: bool,
    /// `db_size_mb` exceeds the `db_size_warn_mb` setting — drives the badge.
    pub db_over_warn: bool,
    pub db_warn_mb: i64,
}

#[derive(Template)]
#[template(path = "partials/system_stats.html")]
pub struct SystemStatsFragment {
    pub stats: SystemStatsView,
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// One rendered row of the settings page — shared by the full page render
/// and the single-row / restore-all HTMX fragments.
pub struct SettingRowView {
    pub key: String,
    pub value: String,
    pub default: String,
    pub bounds: String,
    pub help: String,
    /// Editor kind: `number` | `text` | `bool` | `select` | `fixed`.
    pub input_kind: &'static str,
    /// `min`/`max` attribute strings for numeric inputs (`""` when N/A).
    pub min_attr: String,
    pub max_attr: String,
    /// `value == default` — drives the small "default" badge.
    pub default_badge: bool,
    /// Subtle "restart required" chip (log_level, sqlite_maintenance_on_boot).
    pub needs_restart: bool,
    /// Read-only row (concurrent_visits — pinned to 1 by design).
    pub read_only: bool,
    /// Render `hx-swap-oob="outerHTML"` so the fragment replaces the row
    /// during full restore responses instead of targeted swaps.
    pub oob: bool,
    pub csrf: String,
    /// Options for the `select` editor (log_level). Empty for other kinds.
    pub select_options: Vec<SelectOptionView>,
    /// `inputmode` attribute for text-ish editors.
    pub inputmode: &'static str,
}

/// A `<select>` option with its `selected` flag precomputed, so the
/// template never compares values.
pub struct SelectOptionView {
    pub value: &'static str,
    pub selected: bool,
}

pub struct SettingGroupView {
    pub title: &'static str,
    pub blurb: &'static str,
    /// Stable anchor id (`browser-memory`, ...) for deep links.
    pub anchor: &'static str,
    pub rows: Vec<SettingRowView>,
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsPage {
    pub chrome: LayoutChrome,
    pub groups: Vec<SettingGroupView>,
    pub total_keys: usize,
    pub default_keys: usize,
}

/// Single-row fragment — rendered standalone on PATCH save/rejection and
/// included by `settings.html` / `partials/settings_restore.html` during
/// full-page and full-restore renders.
#[derive(Template)]
#[template(path = "partials/setting_row.html")]
pub struct SettingRowFragment<'a> {
    /// Askama variable name is the field name — the template uses `s.*`.
    pub s: &'a SettingRowView,
}

#[derive(Template)]
#[template(path = "partials/settings_restore.html")]
pub struct SettingsRestoreFragment {
    pub rows: Vec<SettingRowView>,
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

pub fn outcome_class(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Success => "ok",
        Outcome::Timeout | Outcome::NavigationError => "warn",
        Outcome::BrowserCrash | Outcome::InteractionError => "err",
    }
}

/// Relative suffix for a future timestamp: `"in 45s"`, `"in 12m"`,
/// `"in 3h"`, `"in 2d"`. Present or past timestamps render as `"due"`.
pub fn time_until(t: &OffsetDateTime) -> String {
    time_until_at(t, OffsetDateTime::now_utc())
}

/// Deterministic core of [`time_until`] — `now` is injected so tests can
/// pin the boundary values exactly.
pub(crate) fn time_until_at(t: &OffsetDateTime, now: OffsetDateTime) -> String {
    let secs = (*t - now).whole_seconds();
    if secs <= 0 {
        return "due".to_string();
    }
    if secs < 60 {
        format!("in {secs}s")
    } else if secs < 3_600 {
        format!("in {}m", secs / 60)
    } else if secs < 86_400 {
        format!("in {}h", secs / 3_600)
    } else {
        format!("in {}d", secs / 86_400)
    }
}

/// Table timestamp in the deployment display timezone
/// (`DISPLAY_TZ` / `TZ`), e.g. `2026-11-09 15:04:05`. Column headers say
/// `(local)`.
pub fn fmt_ts_local(t: &OffsetDateTime) -> String {
    crate::web::templates::ts(t)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_until_renders_due_and_units() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("epoch");
        let at = |secs: i64| now + time::Duration::seconds(secs);
        assert_eq!(time_until_at(&now, now), "due");
        assert_eq!(
            time_until_at(&(now - time::Duration::seconds(1)), now),
            "due"
        );
        assert_eq!(time_until_at(&at(1), now), "in 1s");
        assert_eq!(time_until_at(&at(45), now), "in 45s");
        assert_eq!(time_until_at(&at(59), now), "in 59s");
        assert_eq!(time_until_at(&at(60), now), "in 1m");
        assert_eq!(time_until_at(&at(719), now), "in 11m");
        assert_eq!(time_until_at(&at(720), now), "in 12m");
        assert_eq!(time_until_at(&at(3_599), now), "in 59m");
        assert_eq!(time_until_at(&at(3_600), now), "in 1h");
        assert_eq!(time_until_at(&at(3 * 3_600), now), "in 3h");
        assert_eq!(time_until_at(&at(86_399), now), "in 23h");
        assert_eq!(time_until_at(&at(86_400), now), "in 1d");
        assert_eq!(time_until_at(&at(2 * 86_400), now), "in 2d");
    }

    #[test]
    fn time_until_matches_documented_samples() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("epoch");
        let at = |secs: i64| now + time::Duration::seconds(secs);
        assert_eq!(time_until_at(&at(45), now), "in 45s");
        assert_eq!(time_until_at(&at(12 * 60), now), "in 12m");
        assert_eq!(time_until_at(&at(3 * 3_600), now), "in 3h");
    }

    #[test]
    fn time_until_public_wrapper_does_not_panic_in_the_past() {
        let past = OffsetDateTime::from_unix_timestamp(1_000_000_000).expect("epoch");
        assert_eq!(time_until(&past), "due");
    }

    #[test]
    fn fmt_ts_local_renders_body_without_suffix() {
        let t = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("epoch");
        let out = fmt_ts_local(&t);
        assert!(!out.ends_with("UTC"), "no UTC suffix: {out}");
        assert_eq!(out.len(), 19, "YYYY-MM-DD HH:MM:SS body: {out}");
    }

    #[test]
    fn normalize_event_type_accepts_only_known_values() {
        assert_eq!(normalize_event_type(None), None);
        assert_eq!(normalize_event_type(Some("")), None);
        assert_eq!(normalize_event_type(Some("bogus")), None);
        assert_eq!(normalize_event_type(Some("CRASHED")), None);
        assert_eq!(normalize_event_type(Some(" crashed")), Some("crashed"));
        for known in [
            "restarting",
            "restarted",
            "crashed",
            "health_warn",
            "db_size_warn",
            "app_memory_high",
        ] {
            assert_eq!(normalize_event_type(Some(known)), Some(known));
        }
    }
}
