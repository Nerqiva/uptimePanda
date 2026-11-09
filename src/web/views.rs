//! View models for askama templates (SEG-11).
//!
//! Everything user-facing is pre-formatted here — templates stay dumb.
//! Values are plain data; askama escapes everything by default.

use askama::Template;

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
    pub outcomes: &'static [OutcomeOptionView],
    pub selected_website: i64,
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

#[derive(Template)]
#[template(path = "system.html")]
pub struct SystemPage {
    pub chrome: LayoutChrome,
    pub browser_available: bool,
    pub events: Vec<BrowserEventView>,
    pub stats: SystemStatsView,
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
}

#[derive(Template)]
#[template(path = "partials/system_stats.html")]
pub struct SystemStatsFragment {
    pub stats: SystemStatsView,
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

pub struct SettingRowView {
    pub key: String,
    pub value: String,
    pub default: String,
    pub bounds: String,
    pub help: String,
    pub inputmode: &'static str,
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsPage {
    pub chrome: LayoutChrome,
    pub settings: Vec<SettingRowView>,
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
