//! Askama templates wiring (SEG-11).
//!
//! `askama_axum` is deliberately not used — each page struct implements
//! [`Template`] and renders into an `axum::response::Html<String>` via
//! [`render_ok`]. Templates live in `templates/` (askama default), escape by
//! default; no user input is ever rendered raw.

use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use time::OffsetDateTime;

use crate::security;
use crate::state::AppState;
use crate::web::csrf;

// ---------------------------------------------------------------------------
// Shared chrome
// ---------------------------------------------------------------------------

/// Fields every authenticated page needs. Embed as `chrome: LayoutChrome`.
pub struct LayoutChrome {
    pub title: String,
    pub active: &'static str,
    pub csrf: String,
    pub version: &'static str,
}

impl LayoutChrome {
    pub fn new(state: &AppState, title: &str, active: &'static str, expiry_unix: i64) -> Self {
        Self {
            title: title.to_string(),
            active,
            csrf: csrf::csrf_token(&state.session_key, expiry_unix),
            version: state.version.trim(),
        }
    }
}

/// Render a template, mapping askama failures into the 500 path.
pub fn render_ok<T: Template>(template: &T) -> Result<Html<String>, crate::error::AppError> {
    Ok(Html(template.render()?))
}

/// Minimal standalone error page (403/404/500).
pub fn error_page(status: StatusCode, code: &str, message: &str) -> Response {
    #[derive(Template)]
    #[template(path = "error.html")]
    struct ErrorPage {
        code: String,
        message: String,
    }
    let page = ErrorPage {
        code: code.to_string(),
        message: message.to_string(),
    };
    match page.render() {
        Ok(body) => (status, Html(body)).into_response(),
        Err(_) => (status, "error").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers (pre-format in handlers; templates stay dumb)
// ---------------------------------------------------------------------------

const TS_FMT: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

pub fn ts(t: &OffsetDateTime) -> String {
    t.format(TS_FMT).unwrap_or_else(|_| t.to_string())
}

pub fn ts_opt(t: &Option<OffsetDateTime>) -> String {
    t.as_ref().map(ts).unwrap_or_else(|| "—".to_string())
}

pub fn duration_ms_label(ms: Option<i64>) -> String {
    match ms {
        None => "—".to_string(),
        Some(ms) if ms < 10_000 => format!("{ms} ms"),
        Some(ms) => format!("{:.1} s", ms as f64 / 1000.0),
    }
}

pub fn human_uptime(total_s: u64) -> String {
    let days = total_s / 86_400;
    let hours = (total_s % 86_400) / 3_600;
    let mins = (total_s % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m {}s", total_s % 60)
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
}

/// URL → `scheme://host[:port]/path` (no query/fragment/userinfo); falls
/// back to a truncated raw string when the URL cannot be parsed.
pub fn host_path_lossy(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) => security::host_path(&u),
        Err(_) => truncate(raw, 120),
    }
}
