//! Route table — SEG-11 dashboard endpoints.
//!
//! Route classes:
//! - **Public**: `/health` (no browser, no DB write), `/login`, `/logout`,
//!   `/public/*` (vendored static assets, traversal-guarded).
//! - **Protected** (session cookie `uptime_session`, via `require_auth`):
//!   everything else, including `/api/system` and `/fragments/*`.
//! - **CSRF**: every mutating route verifies the double-submit token (form
//!   field `csrf_token` or `X-CSRF-Token` header) before touching state.
//!   Mismatch — 403 + minimal HTML page.
//!
//! Mutation responses content-negotiate: htmx requests (`HX-Request`) get
//! 200 + out-of-band fragments (`hx-swap-oob` toast / refreshed grid);
//! plain form posts get 303 redirects or 400 error pages (so curl and the
//! no-JS path work too).

use std::collections::HashMap;
use std::path::PathBuf;

use askama::Template;
use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, patch, post};
use serde::Deserialize;

use crate::browser::sessions::USER_AGENT_PRESETS;
use crate::db::queries::{HistoryEntry, WebsiteListEntry};
use crate::db::{MonitoringMode, Outcome};
use crate::error::AppError;
use crate::security;
use crate::state::{AppState, SharedState};
use crate::web::auth::{self, SessionInfo};
use crate::web::templates::{self, LayoutChrome, ts, ts_opt};
use crate::web::views::*;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn build_router(state: SharedState) -> axum::Router {
    let protected = axum::Router::new()
        .route("/", get(overview_page))
        .route("/fragments/overview", get(overview_fragment))
        .route("/fragments/system", get(system_fragment))
        .route("/fragments/history-rows", get(history_rows_fragment))
        .route("/websites", get(websites_page).post(websites_create))
        .route(
            "/websites/{id}",
            patch(websites_update).delete(websites_delete),
        )
        .route("/websites/{id}/delete", post(websites_delete))
        .route("/websites/{id}/visit", post(websites_visit))
        .route("/websites/{id}/pause", post(websites_pause))
        .route("/websites/{id}/resume", post(websites_resume))
        .route(
            "/websites/{id}/interactions",
            get(interactions_page).post(interactions_save),
        )
        .route(
            "/websites/{id}/interactions/clear",
            post(interactions_clear),
        )
        .route("/profiles", get(profiles_page).post(profiles_create))
        .route(
            "/profiles/{id}",
            patch(profiles_update).delete(profiles_delete),
        )
        .route("/profiles/{id}/delete", post(profiles_delete))
        .route("/profiles/{id}/cookies/clear", post(profiles_cookies_clear))
        .route(
            "/profiles/cookies/clear-all",
            post(profiles_cookies_clear_all),
        )
        .route("/history", get(history_page))
        .route("/system", get(system_page))
        .route("/system/restart", post(system_restart))
        .route(
            "/settings",
            get(settings_page)
                .patch(settings_update)
                .post(settings_update),
        )
        .route("/api/system", get(api_system))
        .route("/backup", post(backup_create))
        // Raw .db upload; 64 MB body limit instead of the global 64 KB.
        .route(
            "/backup/restore",
            post(backup_restore)
                .route_layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024)),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    axum::Router::new()
        .route("/health", get(health))
        .merge(auth::build_login_routes())
        .route("/public/{*path}", get(public_file))
        .merge(protected)
        .fallback(not_found)
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        // SEG-13: outermost — every response, incl. fallbacks, gets the
        // security header set (see web::headers).
        .layer(middleware::from_fn(crate::web::headers::security_headers))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn wants_htmx(headers: &HeaderMap) -> bool {
    headers
        .get("hx-request")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn html(templates_result: Result<Html<String>, AppError>) -> Result<Response, AppError> {
    Ok(templates_result?.into_response())
}

/// Render a toast fragment (`hx-swap-oob=beforeend:#toast-region`).
fn toast(kind: &'static str, message: String) -> String {
    templates::render_ok(&ToastPartial { kind, message })
        .map(|h| h.0)
        .unwrap_or_else(|_| "<div class=\"toast err\">toast failed</div>".to_string())
}

/// Form/validation failure: htmx gets 200 + OOB error fragment (htmx does
/// not swap bodies of >=400 responses), plain clients get a 400 page.
fn mutation_error(
    target_id: &str,
    message: &str,
    redirect_to: &str,
    headers: &HeaderMap,
) -> Response {
    if wants_htmx(headers) {
        let fragment = templates::render_ok(&FormErrorFragment {
            id: target_id.to_string(),
            message: message.to_string(),
            oob: true,
        })
        .map(|h| h.0)
        .unwrap_or_else(|_| {
            format!(
                "<div class=\"note err\" role=\"alert\">{}</div>",
                escape_basic(message)
            )
        });
        Html(fragment).into_response()
    } else {
        let _ = redirect_to;
        templates::error_page(StatusCode::BAD_REQUEST, "400", message)
    }
}

fn escape_basic(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn build_chrome(
    state: &AppState,
    title: &str,
    active: &'static str,
    _session: &SessionInfo,
) -> LayoutChrome {
    LayoutChrome::new(state, title, active)
}

fn render_fmt<T: Template>(t: &T) -> Result<String, AppError> {
    Ok(t.render()?)
}

// ---------------------------------------------------------------------------
// /health, /public/*, fallback
// ---------------------------------------------------------------------------

/// `GET /health` — no browser activity, no DB write.
async fn health() -> Response {
    const VERSION: &str = include_str!("../../VERSION");
    axum::Json(serde_json::json!({ "status": "ok", "version": VERSION.trim() })).into_response()
}

async fn not_found() -> Response {
    templates::error_page(StatusCode::NOT_FOUND, "404", "That page does not exist.")
}

fn content_type_for(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("map") => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// `GET /public/*path` — hand-rolled static handler. The canonicalized
/// candidate must stay inside `public/`; anything else is 404.
async fn public_file(Path(path): Path<String>) -> Response {
    let base = match PathBuf::from("public").canonicalize() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "public directory unavailable");
            return StatusCode::NOT_FOUND.into_response();
        }
    };
    let candidate = match base.join(&path).canonicalize() {
        Ok(c) => c,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    if !candidate.starts_with(&base) || !candidate.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let bytes = match std::fs::read(&candidate) {
        Ok(b) => b,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut response = Response::new(axum::body::Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type_for(&candidate)),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("public, max-age=3600"),
    );
    response
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

struct BrowserSummary {
    running: bool,
    pid: Option<u32>,
    sub: String,
    rss_mb_label: String,
    rss_mb: f64,
    cpu_pct: f64,
    uptime_s: u64,
    restarts_total: u64,
    mem_threshold_mb: i64,
}

fn browser_summary(state: &AppState) -> BrowserSummary {
    match &state.manager {
        Some(mgr) => {
            let s = mgr.stats();
            let sub = if s.running {
                format!(
                    "pid {} · port {} · {} restart(s)",
                    s.pid.unwrap_or(0),
                    s.port,
                    s.restarts_total
                )
            } else {
                "lightpanda not running".to_string()
            };
            BrowserSummary {
                running: s.running,
                pid: s.pid,
                sub,
                rss_mb_label: format!("{:.1}", s.rss_mb),
                rss_mb: s.rss_mb,
                cpu_pct: s.cpu_pct,
                uptime_s: s.uptime_s,
                restarts_total: s.restarts_total,
                mem_threshold_mb: s.mem_threshold_mb,
            }
        }
        None => BrowserSummary {
            running: false,
            pid: None,
            sub: "lightpanda unavailable (browser features disabled)".to_string(),
            rss_mb_label: "0.0".to_string(),
            rss_mb: 0.0,
            cpu_pct: 0.0,
            uptime_s: 0,
            restarts_total: 0,
            mem_threshold_mb: 200,
        },
    }
}

async fn collect_overview(state: &AppState) -> Result<OverviewStats, AppError> {
    let since = time::OffsetDateTime::now_utc() - time::Duration::hours(24);
    let websites_total = state.db.count_websites().await?;
    let websites_enabled = state.db.count_enabled_websites().await?;
    let active = state.db.count_active_websites().await?;
    let visits_24h = state.db.count_visits_since(since).await?;
    let outcomes = state.db.outcome_counts_since(since).await?;
    let mut success_24h = 0i64;
    let mut fail_24h = 0i64;
    for (outcome, count) in &outcomes {
        if *outcome == Outcome::Success {
            success_24h = *count;
        } else {
            fail_24h += count;
        }
    }
    let success_rate = if visits_24h > 0 {
        format!("{:.0}%", (success_24h as f64 / visits_24h as f64) * 100.0)
    } else {
        "—".to_string()
    };

    let browser = browser_summary(state);
    let mem_warn_mb = crate::config::typed_i64(&state.db, "memory_warn_mb")
        .await
        .unwrap_or(160);

    let queue_len = state
        .scheduler
        .as_ref()
        .map(|s| s.queue_length())
        .unwrap_or(0);
    let next_visit = match state.db.next_scheduled_visit_at().await? {
        Some(t) => ts(&t),
        None => "none".to_string(),
    };

    Ok(OverviewStats {
        websites_total,
        websites_enabled,
        active,
        visits_24h,
        success_24h,
        fail_24h,
        success_rate,
        browser_running: browser.running,
        browser_sub: browser.sub,
        browser_rss_mb: browser.rss_mb_label,
        mem_restart_mb: browser.mem_threshold_mb,
        mem_warn_mb,
        next_visit,
        queue_len,
    })
}

async fn overview_page(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
) -> Result<Response, AppError> {
    let stats = collect_overview(&state).await?;
    let chrome = build_chrome(&state, "Overview", "overview", &session);
    html(templates::render_ok(&OverviewPage { chrome, stats }))
}

async fn overview_fragment(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
) -> Result<Response, AppError> {
    let _ = session;
    let stats = collect_overview(&state).await?;
    html(templates::render_ok(&OverviewGridFragment { stats }))
}

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

fn mem_available_mb() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
    raw.lines().find_map(|line| {
        line.strip_prefix("MemAvailable:").and_then(|v| {
            v.trim()
                .trim_end_matches("kB")
                .trim()
                .parse::<u64>()
                .ok()
                .map(|kb| kb / 1024)
        })
    })
}

fn db_size_mb(state: &AppState) -> Option<f64> {
    let mut total = std::fs::metadata(&state.database_path).ok()?.len();
    for suffix in ["-wal", "-shm"] {
        let mut name = state.database_path.as_os_str().to_owned();
        name.push(suffix);
        if let Ok(meta) = std::fs::metadata(std::path::PathBuf::from(name)) {
            total += meta.len();
        }
    }
    Some(total as f64 / (1024.0 * 1024.0))
}

async fn collect_system_stats(state: &AppState) -> Result<SystemStatsView, AppError> {
    let browser = browser_summary(state);
    let queue_len = state
        .scheduler
        .as_ref()
        .map(|s| s.queue_length())
        .unwrap_or(0);
    let next_visit = match state.db.next_scheduled_visit_at().await? {
        Some(t) => format!("next visit {}", ts(&t)),
        None => "no scheduled visits".to_string(),
    };
    Ok(SystemStatsView {
        browser_running: browser.running,
        browser_sub: browser.sub,
        rss_mb: format!("{:.1}", browser.rss_mb),
        rss_mb_int: browser.rss_mb as u64,
        mem_restart_mb: browser.mem_threshold_mb,
        rss_ratio: if browser.mem_threshold_mb > 0 {
            format!(
                "{:.0}%",
                (browser.rss_mb / browser.mem_threshold_mb as f64) * 100.0
            )
        } else {
            "—".to_string()
        },
        cpu_pct: format!("{:.1}", browser.cpu_pct),
        uptime_label: templates::human_uptime(browser.uptime_s),
        restarts_total: browser.restarts_total,
        queue_len,
        next_visit,
        db_size_mb: db_size_mb(state)
            .map(|mb| format!("{mb:.1}"))
            .unwrap_or_else(|| "—".to_string()),
        mem_available_mb: mem_available_mb()
            .map(|mb| mb.to_string())
            .unwrap_or_else(|| "—".to_string()),
    })
}

async fn system_page(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
) -> Result<Response, AppError> {
    let chrome = build_chrome(&state, "System", "system", &session);
    let browser_available = state.manager.is_some();
    let stats = collect_system_stats(&state).await?;
    let events = state
        .db
        .recent_browser_events(50)
        .await?
        .into_iter()
        .map(|ev| BrowserEventView {
            timestamp_label: ts(&ev.timestamp),
            event_type: ev.event_type.clone(),
            warn: matches!(
                ev.event_type.as_str(),
                "health_warn" | "crashed" | "crash_loop" | "respawn_failed"
            ),
            memory_label: ev
                .memory_usage
                .map(|bytes| format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0)))
                .unwrap_or_else(|| "—".to_string()),
            details: ev
                .details
                .as_deref()
                .map(|d| templates::truncate(d, 200))
                .unwrap_or_default(),
        })
        .collect();
    html(templates::render_ok(&SystemPage {
        chrome,
        browser_available,
        events,
        stats,
    }))
}

async fn system_fragment(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
) -> Result<Response, AppError> {
    let _ = session;
    let stats = collect_system_stats(&state).await?;
    html(templates::render_ok(&SystemStatsFragment { stats }))
}

async fn system_restart(
    State(state): State<SharedState>,
    _session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    let message = match &state.manager {
        Some(mgr) => match mgr.force_restart().await {
            Ok(()) => ("ok", "Browser restart requested.".to_string()),
            Err(e) => ("err", format!("Restart failed: {e}")),
        },
        None => (
            "err",
            "Lightpanda is not available; nothing to restart.".to_string(),
        ),
    };
    if wants_htmx(&headers) {
        Ok(Html(toast(message.0, message.1)).into_response())
    } else {
        Ok(Redirect::to("/system").into_response())
    }
}

#[derive(Deserialize)]
pub struct CsrfOnlyForm {
    /// Consumed by the `require_auth` middleware; kept so the form shape
    /// stays explicit and the field is documented.
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    csrf_token: String,
}

async fn api_system(State(state): State<SharedState>, session: Extension<SessionInfo>) -> Response {
    let _ = session;
    let browser = browser_summary(&state);
    let present = state.manager.is_some();
    let payload = serde_json::json!({
        "app_version": state.version.trim(),
        "browser_running": browser.running,
        "lightpanda_rss_mb": if present { Some(browser.rss_mb) } else { None },
        "lightpanda_cpu_pct": if present { Some(browser.cpu_pct) } else { None },
        "browser_pid": browser.pid,
        "browser_uptime_s": if present { Some(browser.uptime_s) } else { None },
        "browser_restarts_total": if present { Some(browser.restarts_total) } else { None },
        "queue_length": state.scheduler.as_ref().map(|s| s.queue_length()).unwrap_or(0),
        "db_size_mb": db_size_mb(&state),
        "mem_available_mb": mem_available_mb(),
    });
    axum::Json(payload).into_response()
}

// ---------------------------------------------------------------------------
// Websites
// ---------------------------------------------------------------------------

async fn build_website_entries(state: &AppState) -> Result<Vec<WebsiteEntryView>, AppError> {
    let rows = state.db.list_websites_with_state().await?;
    Ok(rows.into_iter().map(website_entry_view).collect())
}

fn website_entry_view(entry: WebsiteListEntry) -> WebsiteEntryView {
    let w = entry.website;
    WebsiteEntryView {
        website: WebsiteRowView {
            id: w.id,
            name: w.name.clone(),
            url: w.url.clone(),
            host_path: templates::host_path_lossy(&w.url),
            mode: w.monitoring_mode.as_str().to_string(),
            enabled: w.enabled,
            profile_id_label: w.profile_id.map(|p| p.to_string()).unwrap_or_default(),
            min_interval_seconds: w.min_interval_seconds,
            max_interval_seconds: w.max_interval_seconds,
            min_session_seconds: w.min_session_seconds,
            max_session_seconds: w.max_session_seconds,
            interval_label: format!("{}–{} s", w.min_interval_seconds, w.max_interval_seconds),
            last_visit_label: ts_opt(&w.last_visit_at),
        },
        profile_name: entry.profile_name.unwrap_or_else(|| "default".to_string()),
        paused: entry.job_status == Some(crate::db::JobStatus::Paused),
        next_visit_label: ts_opt(&entry.next_visit_at),
    }
}

async fn websites_page(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
) -> Result<Response, AppError> {
    let chrome = build_chrome(&state, "Websites", "websites", &session);
    let entries = build_website_entries(&state).await?;
    let pages = state.db.list_profiles().await?;
    let profiles = pages
        .into_iter()
        .map(|p| ProfileOptionView {
            id: p.id,
            name: p.name,
        })
        .collect();
    html(templates::render_ok(&WebsitesPage {
        chrome,
        entries,
        profiles,
        form_error: String::new(),
    }))
}

#[derive(Deserialize)]
pub struct WebsiteForm {
    name: String,
    url: String,
    enabled: Option<String>,
    profile_id: Option<String>,
    monitoring_mode: String,
    min_interval_seconds: i64,
    max_interval_seconds: i64,
    min_session_seconds: i64,
    max_session_seconds: i64,
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    csrf_token: String,
}

struct ValidatedWebsite {
    name: String,
    url: String,
    enabled: bool,
    profile_id: Option<i64>,
    mode: MonitoringMode,
    min_interval_seconds: i64,
    max_interval_seconds: i64,
    min_session_seconds: i64,
    max_session_seconds: i64,
}

async fn validate_website_form(
    state: &AppState,
    form: &WebsiteForm,
) -> Result<ValidatedWebsite, String> {
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return Err("Name is required.".to_string());
    }
    if name.chars().count() > 200 {
        return Err("Name must be at most 200 characters.".to_string());
    }

    let url = form.url.trim().to_string();
    if url.is_empty() || url.len() > 2048 {
        return Err("A URL of at most 2048 characters is required.".to_string());
    }
    // SSRF guard — same rules as visit time. 400 with the reason on failure.
    security::validate_target(&url)
        .await
        .map_err(|e| format!("URL rejected: {e}"))?;

    let mode = match form.monitoring_mode.trim() {
        "basic" => MonitoringMode::Basic,
        "interaction" => MonitoringMode::Interaction,
        other => {
            return Err(format!(
                "monitoring_mode must be 'basic' or 'interaction', got {other:?}"
            ));
        }
    };

    if form.min_interval_seconds < 30 || form.max_interval_seconds > 86_400 {
        return Err("Intervals must be within 30..=86400 seconds.".to_string());
    }
    if form.min_interval_seconds > form.max_interval_seconds {
        return Err(format!(
            "min_interval_seconds ({}) must be <= max_interval_seconds ({})",
            form.min_interval_seconds, form.max_interval_seconds
        ));
    }
    if form.min_session_seconds < 5 || form.max_session_seconds > 3600 {
        return Err("Sessions must be within 5..=3600 seconds.".to_string());
    }
    if form.min_session_seconds > form.max_session_seconds {
        return Err(format!(
            "min_session_seconds ({}) must be <= max_session_seconds ({})",
            form.min_session_seconds, form.max_session_seconds
        ));
    }

    let profile_id = match form
        .profile_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            let id: i64 = raw
                .parse()
                .map_err(|_| format!("profile_id must be an integer, got {raw:?}"))?;
            if state
                .db
                .profile_by_id(id)
                .await
                .map_err(|e| e.to_string())?
                .is_none()
            {
                return Err(format!("profile_id {id} does not exist"));
            }
            Some(id)
        }
        None => None,
    };

    let enabled = matches!(
        form.enabled.as_deref(),
        Some("on") | Some("1") | Some("true")
    );

    Ok(ValidatedWebsite {
        name,
        url,
        enabled,
        profile_id,
        mode,
        min_interval_seconds: form.min_interval_seconds,
        max_interval_seconds: form.max_interval_seconds,
        min_session_seconds: form.min_session_seconds,
        max_session_seconds: form.max_session_seconds,
    })
}

fn websites_fragment_and_toast(
    state: &AppState,
    session: &SessionInfo,
    entries: Vec<WebsiteEntryView>,
    kind: &'static str,
    message: String,
) -> String {
    let chrome = build_chrome(state, "Websites", "websites", session);
    let mut body = render_fmt(&WebsitesTableFragment {
        chrome,
        entries,
        oob: true,
    })
    .unwrap_or_else(|_| toast("err", "Failed to render table.".to_string()));
    body.push_str(&toast(kind, message));
    body
}

async fn websites_create(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<WebsiteForm>,
) -> Result<Response, AppError> {
    let validated = match validate_website_form(&state, &form).await {
        Ok(v) => v,
        Err(msg) => {
            return Ok(mutation_error(
                "website-form-error",
                &msg,
                "/websites",
                &headers,
            ));
        }
    };

    let now = time::OffsetDateTime::now_utc();
    let model = crate::db::Website {
        id: 0,
        name: validated.name,
        url: validated.url,
        enabled: validated.enabled,
        profile_id: validated.profile_id,
        monitoring_mode: validated.mode,
        min_interval_seconds: validated.min_interval_seconds,
        max_interval_seconds: validated.max_interval_seconds,
        min_session_seconds: validated.min_session_seconds,
        max_session_seconds: validated.max_session_seconds,
        last_visit_at: None,
        next_visit_at: None,
        created_at: now,
        updated_at: now,
        active_window_start: None,
        active_window_end: None,
        timezone: None,
    };
    let id = state.db.insert_website(&model).await?;
    // Register the scheduler entry (jittered next visit, or a disabled row
    // when the monitor is disabled).
    if let Some(sched) = &state.scheduler
        && let Err(e) = sched.set_paused(id, false).await
    {
        tracing::error!(website_id = id, error = %e, "failed to register website with scheduler");
    }

    if wants_htmx(&headers) {
        let entries = build_website_entries(&state).await?;
        Ok(Html(websites_fragment_and_toast(
            &state,
            &session,
            entries,
            "ok",
            format!("Website created (id {id})."),
        ))
        .into_response())
    } else {
        Ok(Redirect::to("/websites").into_response())
    }
}

async fn websites_update(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<WebsiteForm>,
) -> Result<Response, AppError> {
    let Some(existing) = state.db.get_website(id).await? else {
        return Ok(mutation_error(
            "website-form-error",
            "Website not found.",
            "/websites",
            &headers,
        ));
    };

    let validated = match validate_website_form(&state, &form).await {
        Ok(v) => v,
        Err(msg) => {
            return Ok(mutation_error(
                "website-form-error",
                &msg,
                "/websites",
                &headers,
            ));
        }
    };

    let model = crate::db::Website {
        id,
        name: validated.name,
        url: validated.url,
        enabled: validated.enabled,
        profile_id: validated.profile_id,
        monitoring_mode: validated.mode,
        min_interval_seconds: validated.min_interval_seconds,
        max_interval_seconds: validated.max_interval_seconds,
        min_session_seconds: validated.min_session_seconds,
        max_session_seconds: validated.max_session_seconds,
        last_visit_at: existing.last_visit_at,
        next_visit_at: existing.next_visit_at,
        created_at: existing.created_at,
        updated_at: existing.updated_at,
        active_window_start: existing.active_window_start,
        active_window_end: existing.active_window_end,
        timezone: existing.timezone,
    };
    state.db.update_website(&model).await?;
    if let Some(sched) = &state.scheduler
        && let Err(e) = sched.set_paused(id, false).await
    {
        tracing::error!(website_id = id, error = %e, "failed to re-register website with scheduler");
    }

    if wants_htmx(&headers) {
        let entries = build_website_entries(&state).await?;
        Ok(Html(websites_fragment_and_toast(
            &state,
            &session,
            entries,
            "ok",
            "Website updated.".to_string(),
        ))
        .into_response())
    } else {
        Ok(Redirect::to("/websites").into_response())
    }
}

async fn websites_delete(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    let existed = state.db.delete_website(id).await?;

    if wants_htmx(&headers) {
        let entries = build_website_entries(&state).await?;
        let (kind, message) = if existed {
            ("ok", "Website deleted.".to_string())
        } else {
            ("err", "Website not found.".to_string())
        };
        Ok(Html(websites_fragment_and_toast(
            &state, &session, entries, kind, message,
        ))
        .into_response())
    } else if existed {
        Ok(Redirect::to("/websites").into_response())
    } else {
        Ok(templates::error_page(
            StatusCode::NOT_FOUND,
            "404",
            "Website not found.",
        ))
    }
}

async fn websites_visit(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    let message = match &state.scheduler {
        Some(sched) => match sched.enqueue_manual(id).await {
            Ok(crate::scheduler::EnqueueAck::Queued { position }) => {
                ("ok", format!("Visit queued (position {position})."))
            }
            Ok(crate::scheduler::EnqueueAck::NotEnabled) => (
                "err",
                "This website is disabled — enable it first.".to_string(),
            ),
            Ok(crate::scheduler::EnqueueAck::QueueFull) => {
                ("err", "Queue is full; try again shortly.".to_string())
            }
            Ok(crate::scheduler::EnqueueAck::Unknown) => ("err", "Unknown website.".to_string()),
            Err(e) => {
                tracing::error!(website_id = id, error = %e, "manual enqueue failed");
                ("err", "Visit could not be queued (see logs).".to_string())
            }
        },
        None => (
            "err",
            "Scheduler unavailable — lightpanda is not installed.".to_string(),
        ),
    };
    Ok(manual_action_response(&state, &session, &headers, message, "/websites").await)
}

async fn websites_pause(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    set_paused_response(id, true, &state, &session, &headers).await
}

async fn websites_resume(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    set_paused_response(id, false, &state, &session, &headers).await
}

async fn set_paused_response(
    id: i64,
    paused: bool,
    state: &SharedState,
    session: &SessionInfo,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    let message = match &state.scheduler {
        Some(sched) => match sched.set_paused(id, paused).await {
            Ok(true) => (
                "ok",
                if paused {
                    "Website paused.".to_string()
                } else {
                    "Website resumed.".to_string()
                },
            ),
            Ok(false) => ("err", "Unknown website.".to_string()),
            Err(e) => {
                tracing::error!(website_id = id, error = %e, "pause/resume failed");
                ("err", "Pause/resume failed (see logs).".to_string())
            }
        },
        None => (
            "err",
            "Scheduler unavailable — lightpanda is not installed.".to_string(),
        ),
    };
    Ok(manual_action_response(state, session, headers, message, "/websites").await)
}

/// Shared tail for visit/pause/resume: htmx → 200 + refreshed table + toast;
/// plain → 303 back to the websites page.
async fn manual_action_response(
    state: &AppState,
    session: &SessionInfo,
    headers: &HeaderMap,
    message: (&'static str, String),
    redirect_to: &str,
) -> Response {
    if wants_htmx(headers) {
        match build_website_entries(state).await {
            Ok(entries) => Html(websites_fragment_and_toast(
                state, session, entries, message.0, message.1,
            ))
            .into_response(),
            Err(_) => Html(toast("err", message.1)).into_response(),
        }
    } else {
        let _ = message;
        Redirect::to(redirect_to).into_response()
    }
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

async fn build_profile_entries(state: &AppState) -> Result<Vec<ProfileEntryView>, AppError> {
    let profiles = state.db.list_profiles().await?;
    let cookie_counts: HashMap<i64, i64> = state.db.cookie_counts().await?.into_iter().collect();
    let earliest: HashMap<i64, Option<time::OffsetDateTime>> = state
        .db
        .cookie_earliest_expiry()
        .await?
        .into_iter()
        .collect();
    let mut assigned: HashMap<i64, Vec<String>> = HashMap::new();
    for (profile_id, site_name) in state.db.profile_website_assignments().await? {
        assigned.entry(profile_id).or_default().push(site_name);
    }

    Ok(profiles
        .into_iter()
        .map(|p| {
            let ua = p.user_agent.clone();
            let ua_preset = USER_AGENT_PRESETS
                .iter()
                .find(|preset| ua.as_deref() == Some(preset.ua))
                .map(|preset| preset.id)
                .unwrap_or(if ua.is_some() { "custom" } else { "" });
            let ua_label = match &ua {
                None => "Engine default".to_string(),
                Some(_) => USER_AGENT_PRESETS
                    .iter()
                    .find(|preset| ua.as_deref() == Some(preset.ua))
                    .map(|preset| preset.label)
                    .unwrap_or("Custom (compatibility test)")
                    .to_string(),
            };
            let assigned_sites = assigned
                .get(&p.id)
                .map(|names| {
                    if names.len() > 4 {
                        format!("{} +{} more", names[..4].join(", "), names.len() - 4)
                    } else {
                        names.join(", ")
                    }
                })
                .unwrap_or_else(|| "—".to_string());
            ProfileEntryView {
                id: p.id,
                name: p.name,
                description: p.description,
                enabled: p.enabled,
                user_agent: ua.unwrap_or_default(),
                ua_preset: ua_preset.to_string(),
                ua_label,
                cookie_count: cookie_counts.get(&p.id).copied().unwrap_or(0),
                earliest_expiry: earliest
                    .get(&p.id)
                    .and_then(|o| o.as_ref())
                    .map(ts)
                    .unwrap_or_default(),
                assigned: assigned_sites,
            }
        })
        .collect())
}

fn profiles_fragment_and_toast(
    state: &AppState,
    session: &SessionInfo,
    entries: Vec<ProfileEntryView>,
    kind: &'static str,
    message: String,
) -> String {
    let chrome = build_chrome(state, "Profiles", "profiles", session);
    let mut body = render_fmt(&ProfilesGridFragment {
        chrome,
        entries,
        oob: true,
    })
    .unwrap_or_else(|_| toast("err", "Failed to render profiles.".to_string()));
    body.push_str(&toast(kind, message));
    body
}

async fn profiles_page(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
) -> Result<Response, AppError> {
    let chrome = build_chrome(&state, "Profiles", "profiles", &session);
    let entries = build_profile_entries(&state).await?;
    html(templates::render_ok(&ProfilesPage {
        chrome,
        entries,
        presets: &UA_PRESET_VIEWS,
    }))
}

#[derive(Deserialize)]
pub struct ProfileForm {
    name: String,
    description: String,
    ua_preset: String,
    user_agent: String,
    enabled: Option<String>,
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    csrf_token: String,
}

struct ValidatedProfile {
    name: String,
    description: String,
    user_agent: Option<String>,
    enabled: bool,
}

fn validate_profile_form(form: &ProfileForm) -> Result<ValidatedProfile, String> {
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return Err("Name is required.".to_string());
    }
    if name.chars().count() > 100 {
        return Err("Name must be at most 100 characters.".to_string());
    }
    let description = form.description.trim().to_string();
    if description.chars().count() > 300 {
        return Err("Description must be at most 300 characters.".to_string());
    }

    let custom = form.user_agent.trim();
    let resolved: Option<String> = if !custom.is_empty() {
        if custom.len() > 512 {
            return Err("Custom user-agent must be at most 512 bytes.".to_string());
        }
        Some(custom.to_string())
    } else {
        let preset = form.ua_preset.trim();
        if preset.is_empty() || preset == "custom" {
            None // engine default
        } else {
            Some(
                USER_AGENT_PRESETS
                    .iter()
                    .find(|p| p.id == preset)
                    .map(|p| p.ua.to_string())
                    .ok_or_else(|| format!("unknown UA preset: {preset:?}"))?,
            )
        }
    };

    Ok(ValidatedProfile {
        name,
        description,
        user_agent: resolved,
        enabled: matches!(
            form.enabled.as_deref(),
            Some("on") | Some("1") | Some("true")
        ),
    })
}

fn profile_model(
    id: i64,
    v: ValidatedProfile,
    existing: Option<crate::db::BrowserProfile>,
) -> crate::db::BrowserProfile {
    let now = time::OffsetDateTime::now_utc();
    crate::db::BrowserProfile {
        id,
        name: v.name,
        description: v.description,
        user_agent: v.user_agent,
        enabled: v.enabled,
        configuration_json: existing
            .as_ref()
            .map(|e| e.configuration_json.clone())
            .unwrap_or_else(|| "{}".to_string()),
        created_at: existing.map(|e| e.created_at).unwrap_or(now),
        updated_at: now,
    }
}

async fn profiles_grid_response(
    state: &AppState,
    session: &SessionInfo,
    headers: &HeaderMap,
    kind: &'static str,
    message: String,
) -> Result<Response, AppError> {
    if wants_htmx(headers) {
        // Grid refresh failures degrade to a toast-only response.
        match build_profile_entries(state).await {
            Ok(entries) => Ok(Html(profiles_fragment_and_toast(
                state, session, entries, kind, message,
            ))
            .into_response()),
            Err(_) => Ok(Html(toast("err", message)).into_response()),
        }
    } else {
        Ok(Redirect::to("/profiles").into_response())
    }
}

#[allow(clippy::too_many_arguments)]
async fn profiles_create(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<ProfileForm>,
) -> Result<Response, AppError> {
    let validated = match validate_profile_form(&form) {
        Ok(v) => v,
        Err(msg) => {
            return Ok(mutation_error(
                "profile-form-error",
                &msg,
                "/profiles",
                &headers,
            ));
        }
    };
    let model = profile_model(0, validated, None);
    let id = state.db.create_profile(&model).await?;
    profiles_grid_response(
        &state,
        &session,
        &headers,
        "ok",
        format!("Profile created (id {id})."),
    )
    .await
}

async fn profiles_update(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<ProfileForm>,
) -> Result<Response, AppError> {
    let Some(existing) = state.db.profile_by_id(id).await? else {
        return Ok(mutation_error(
            "profile-form-error",
            "Profile not found.",
            "/profiles",
            &headers,
        ));
    };
    let validated = match validate_profile_form(&form) {
        Ok(v) => v,
        Err(msg) => {
            return Ok(mutation_error(
                "profile-form-error",
                &msg,
                "/profiles",
                &headers,
            ));
        }
    };
    let model = profile_model(id, validated, Some(existing));
    state.db.update_profile(&model).await?;
    profiles_grid_response(
        &state,
        &session,
        &headers,
        "ok",
        "Profile updated.".to_string(),
    )
    .await
}

async fn profiles_delete(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    let existed = state.db.delete_profile(id).await?;
    let (kind, message) = if existed {
        ("ok", "Profile deleted.".to_string())
    } else {
        ("err", "Profile not found.".to_string())
    };
    profiles_grid_response(&state, &session, &headers, kind, message).await
}

async fn profiles_cookies_clear(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    let deleted = state.db.delete_profile_cookies(id).await?;
    profiles_grid_response(
        &state,
        &session,
        &headers,
        "ok",
        format!("Cleared {deleted} cookie jar row(s)."),
    )
    .await
}

async fn profiles_cookies_clear_all(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    let mut total = 0u64;
    for profile in state.db.list_profiles().await? {
        total += state.db.delete_profile_cookies(profile.id).await?;
    }
    profiles_grid_response(
        &state,
        &session,
        &headers,
        "ok",
        format!("Cleared {total} cookie jar row(s) across all profiles."),
    )
    .await
}

// ---------------------------------------------------------------------------
// Interaction editor
// ---------------------------------------------------------------------------

const EMPTY_SEQUENCE_JSON: &str = "{\n  \"actions\": [],\n  \"on_error\": \"abort\"\n}";

struct InteractionContext {
    website_id: i64,
    website_name: String,
    website_url: String,
    enabled: bool,
    action_count: usize,
    sequence_json: String,
}

async fn load_interaction_context(
    state: &AppState,
    website_id: i64,
) -> Result<Option<InteractionContext>, AppError> {
    let Some(site) = state.db.get_website(website_id).await? else {
        return Ok(None);
    };
    let (enabled, configuration_json) = match state.db.get_interaction_sequence(website_id).await? {
        Some(seq) => (seq.enabled, seq.configuration_json),
        None => (true, EMPTY_SEQUENCE_JSON.to_string()),
    };
    let (action_count, sequence_json) =
        match crate::interactions::actions::parse_sequence_json(&configuration_json) {
            Ok(seq) => (
                seq.actions.len(),
                serde_json::to_string_pretty(&seq).unwrap_or(configuration_json),
            ),
            Err(_) => (0, configuration_json),
        };
    Ok(Some(InteractionContext {
        website_id,
        website_name: site.name,
        website_url: site.url,
        enabled,
        action_count,
        sequence_json,
    }))
}

async fn interaction_limits(state: &AppState) -> InteractionLimitsView {
    let max_actions = crate::config::typed_i64(&state.db, "max_actions_per_sequence")
        .await
        .unwrap_or(50) as usize;
    let max_click_wait_ms = crate::config::typed_i64(&state.db, "interaction_click_wait_max_ms")
        .await
        .unwrap_or(10_000) as u64;
    let max_scroll_ops = crate::config::typed_i64(&state.db, "interaction_scroll_max_ops")
        .await
        .unwrap_or(20) as u32;
    let cap_s = crate::config::typed_i64(&state.db, "max_session_seconds_cap")
        .await
        .unwrap_or(300) as u64;
    InteractionLimitsView {
        max_actions,
        total_budget_s: cap_s,
        max_click_wait_ms,
        max_scroll_ops,
    }
}

async fn interactions_page(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
) -> Result<Response, AppError> {
    let Some(ctx) = load_interaction_context(&state, id).await? else {
        return Ok(templates::error_page(
            StatusCode::NOT_FOUND,
            "404",
            "Website not found.",
        ));
    };
    let chrome = build_chrome(&state, "Interactions", "websites", &session);
    html(templates::render_ok(&InteractionsPage {
        chrome,
        website_id: ctx.website_id,
        website_name: ctx.website_name,
        enabled: ctx.enabled,
        action_count: ctx.action_count,
        mode_label: if ctx.enabled {
            "interaction mode"
        } else {
            "draft (disabled)"
        }
        .to_string(),
        sequence_json: ctx.sequence_json,
        errors: Vec::new(),
        limits: interaction_limits(&state).await,
    }))
}

#[derive(Deserialize)]
pub struct InteractionsForm {
    configuration_json: String,
    enabled: Option<String>,
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    csrf_token: String,
}

async fn interactions_save(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    _session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<InteractionsForm>,
) -> Result<Response, AppError> {
    let Some(ctx) = load_interaction_context(&state, id).await? else {
        return Ok(templates::error_page(
            StatusCode::NOT_FOUND,
            "404",
            "Website not found.",
        ));
    };
    let enabled = matches!(
        form.enabled.as_deref(),
        Some("on") | Some("1") | Some("true")
    );
    let is_htmx = wants_htmx(&headers);

    // Server-side revalidation of everything. The textarea is never trusted.
    let parsed = crate::interactions::actions::parse_sequence_json(form.configuration_json.trim());
    let errors: Vec<String> = match &parsed {
        Err(e) => vec![format!("invalid JSON: {e}")],
        Ok(seq) => {
            let base_origin = url::Url::parse(&ctx.website_url).ok();
            let max_actions = crate::config::typed_i64(&state.db, "max_actions_per_sequence")
                .await
                .unwrap_or(50) as usize;
            let max_click_wait_ms =
                crate::config::typed_i64(&state.db, "interaction_click_wait_max_ms")
                    .await
                    .unwrap_or(10_000) as u64;
            let max_scroll_ops = crate::config::typed_i64(&state.db, "interaction_scroll_max_ops")
                .await
                .unwrap_or(20) as u32;
            let cap_ms = crate::config::typed_i64(&state.db, "max_session_seconds_cap")
                .await
                .unwrap_or(300)
                .clamp(1, i64::MAX / 1000) as u64
                * 1000;
            let limits = crate::interactions::validate::InteractionLimits::new(
                max_actions,
                max_click_wait_ms,
                max_scroll_ops,
                cap_ms,
            );
            match crate::interactions::validate::validate_sequence(
                seq,
                &limits,
                base_origin.as_ref(),
            ) {
                Ok(()) => Vec::new(),
                Err(violations) => violations.iter().map(ToString::to_string).collect(),
            }
        }
    };

    if !errors.is_empty() {
        if is_htmx {
            let mut body = render_fmt(&InteractionErrorsFragment { oob: true, errors })
                .unwrap_or_else(|_| toast("err", "Validation failed; see above.".to_string()));
            body.push_str(&toast(
                "err",
                "Sequence rejected — see validation errors.".to_string(),
            ));
            return Ok(Html(body).into_response());
        }
        let summary = errors.join("\n");
        return Ok(templates::error_page(
            StatusCode::BAD_REQUEST,
            "400",
            &summary,
        ));
    }

    let sequence = parsed.expect("validated above");
    let now = time::OffsetDateTime::now_utc();
    state
        .db
        .upsert_interaction_sequence(&crate::db::InteractionSequence {
            id: 0,
            website_id: id,
            enabled,
            configuration_json: crate::interactions::actions::to_json(&sequence)
                .map_err(|e| AppError::Internal(format!("sequence serialize: {e}")))?,
            created_at: now,
            updated_at: now,
        })
        .await?;

    if is_htmx {
        let mut body = render_fmt(&InteractionErrorsFragment {
            oob: true,
            errors: Vec::new(),
        })
        .unwrap_or_default();
        body.push_str(&toast("ok", "Interaction sequence saved.".to_string()));
        Ok(Html(body).into_response())
    } else {
        Ok(Redirect::to(&format!("/websites/{id}/interactions")).into_response())
    }
}

async fn interactions_clear(
    Path(id): Path<i64>,
    State(state): State<SharedState>,
    _session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    // Website existence gate — avoid silently "clearing" a nonexistent id.
    if state.db.get_website(id).await?.is_none() {
        return Ok(templates::error_page(
            StatusCode::NOT_FOUND,
            "404",
            "Website not found.",
        ));
    }
    state.db.delete_interaction_sequence(id).await?;
    if wants_htmx(&headers) {
        let mut body = render_fmt(&InteractionTextareaFragment {
            oob: true,
            sequence_json: EMPTY_SEQUENCE_JSON.to_string(),
        })
        .unwrap_or_default();
        body.push_str(&toast(
            "ok",
            "Sequence cleared. Basic mode active.".to_string(),
        ));
        Ok(Html(body).into_response())
    } else {
        Ok(Redirect::to(&format!("/websites/{id}/interactions")).into_response())
    }
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

const HISTORY_PAGE_SIZE: i64 = 20;

#[derive(Deserialize)]
pub struct HistoryQuery {
    website_id: Option<i64>,
    outcome: Option<String>,
    page: Option<i64>,
}

fn parse_outcome_param(raw: Option<&str>) -> Option<Outcome> {
    match raw? {
        "success" => Some(Outcome::Success),
        "timeout" => Some(Outcome::Timeout),
        "navigation_error" => Some(Outcome::NavigationError),
        "browser_crash" => Some(Outcome::BrowserCrash),
        "interaction_error" => Some(Outcome::InteractionError),
        _ => None,
    }
}

fn history_filter_query(website_id: Option<i64>, outcome: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(id) = website_id {
        parts.push(format!("website_id={id}"));
    }
    if let Some(o) = outcome
        && !o.is_empty()
    {
        parts.push(format!("outcome={o}"));
    }
    parts.join("&")
}

fn history_row_view(entry: HistoryEntry) -> HistoryRowView {
    let v = entry.visit;
    HistoryRowView {
        started_label: ts(&v.started_at),
        website_name: entry.website_name,
        profile_name: entry.profile_name.unwrap_or_else(|| "—".to_string()),
        duration_label: templates::duration_ms_label(v.duration_ms),
        outcome: v.outcome.as_str().to_string(),
        outcome_class: outcome_class(v.outcome),
        http_status: v
            .http_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "—".to_string()),
        error: v
            .error_message
            .as_deref()
            .map(|e| templates::truncate(e, 120))
            .unwrap_or_default(),
    }
}

struct HistorySelection {
    website_id: Option<i64>,
    outcome: Option<Outcome>,
    selected_outcome: String,
    page: i64,
    filter_query: String,
    total: i64,
    total_pages: i64,
}

async fn history_selection(
    state: &AppState,
    query: &HistoryQuery,
) -> Result<HistorySelection, AppError> {
    let website_id = query.website_id.filter(|id| *id > 0);
    let outcome = parse_outcome_param(query.outcome.as_deref());
    let selected_outcome = outcome.map(|o| o.as_str().to_string()).unwrap_or_default();
    let total = state.db.count_history(website_id, outcome).await?;
    let total_pages = (total + HISTORY_PAGE_SIZE - 1) / HISTORY_PAGE_SIZE;
    let page = query.page.unwrap_or(1).clamp(1, total_pages.max(1));
    Ok(HistorySelection {
        website_id,
        outcome,
        selected_outcome,
        page,
        filter_query: history_filter_query(
            website_id,
            query.outcome.as_deref().filter(|o| !o.is_empty()),
        ),
        total,
        total_pages,
    })
}

async fn history_entries(
    state: &AppState,
    sel: &HistorySelection,
) -> Result<Vec<HistoryRowView>, AppError> {
    let offset = (sel.page - 1) * HISTORY_PAGE_SIZE;
    Ok(state
        .db
        .history_page(sel.website_id, sel.outcome, offset, HISTORY_PAGE_SIZE)
        .await?
        .into_iter()
        .map(history_row_view)
        .collect())
}

async fn history_page(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    Query(query): Query<HistoryQuery>,
) -> Result<Response, AppError> {
    let sel = history_selection(&state, &query).await?;
    let entries = history_entries(&state, &sel).await?;

    let chrome = build_chrome(&state, "History", "history", &session);
    let websites: Vec<WebsiteOptionView> = state
        .db
        .list_websites_with_state()
        .await?
        .into_iter()
        .map(|e| WebsiteOptionView {
            id: e.website.id,
            name: e.website.name,
        })
        .collect();
    html(templates::render_ok(&HistoryPage {
        chrome,
        websites,
        outcomes: &OUTCOME_OPTIONS,
        selected_website: sel.website_id.unwrap_or(0),
        selected_outcome: sel.selected_outcome,
        total: sel.total,
        page: sel.page,
        total_pages: sel.total_pages,
        filter_query: sel.filter_query,
        entries,
    }))
}

async fn history_rows_fragment(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
    Query(query): Query<HistoryQuery>,
) -> Result<Response, AppError> {
    let _ = session;
    let sel = history_selection(&state, &query).await?;
    let entries = history_entries(&state, &sel).await?;
    html(templates::render_ok(&HistoryRowsFragment {
        entries,
        page: sel.page,
        total_pages: sel.total_pages,
        filter_query: sel.filter_query,
        oob: false,
    }))
}

// ---------------------------------------------------------------------------
// Backup / restore
// ---------------------------------------------------------------------------

fn utc_stamp() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::macros::format_description!(
            "[year][month][day]-[hour][minute][second]"
        ))
        .unwrap_or_else(|_| "unknown".to_string())
}

async fn backup_create(
    State(state): State<SharedState>,
    _session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    std::fs::create_dir_all(&state.backup_dir)
        .map_err(|e| AppError::Internal(format!("create backup dir: {e}")))?;
    let filename = format!("uptimepanda-{}.db", utc_stamp());
    let path = state.backup_dir.join(&filename);
    state.db.backup_to(&path).await?;
    tracing::info!(path = %path.display(), "database backup created");

    if wants_htmx(&headers) {
        Ok(Html(toast(
            "ok",
            format!("Backup written to backups/{filename} on the server."),
        ))
        .into_response())
    } else {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("backup written: {}\n", path.display()),
        )
            .into_response())
    }
}

#[derive(Template)]
#[template(path = "restore_done.html")]
struct RestoreDonePage {
    bak_name: String,
}

async fn backup_restore(
    State(state): State<SharedState>,
    _session: Extension<SessionInfo>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    // CSRF via X-CSRF-Token header (raw upload carries no form body).
    if body.is_empty() {
        return Ok((StatusCode::BAD_REQUEST, "empty upload").into_response());
    }

    std::fs::create_dir_all(&state.backup_dir)
        .map_err(|e| AppError::Internal(format!("create backup dir: {e}")))?;
    let tmp = state
        .backup_dir
        .join(format!("restore-upload-{}.part", utc_stamp()));
    std::fs::write(&tmp, &body).map_err(|e| AppError::Internal(format!("write upload: {e}")))?;

    // Validate before anything is moved: SQLite magic + integrity_check.
    if let Err(e) = crate::db::backup::validate_backup(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        // DbError::InvalidBackup's Display already carries the prefix.
        let msg = format!("{e}");
        tracing::warn!(%msg, "restore rejected");
        return Ok((
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            msg,
        )
            .into_response());
    }

    // Mark the uploaded database as restore-pending (read by the operator on
    // next boot) WITHOUT touching the live database.
    let tmp_for_mark = tmp.clone();
    let mark_result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let conn = rusqlite::Connection::open_with_flags(
            &tmp_for_mark,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .map_err(|e| format!("open backup for restore_pending: {e}"))?;
        conn.execute(
            "INSERT INTO application_settings (setting_key, setting_value, updated_at)
             VALUES ('restore_pending', '1', strftime('%Y-%m-%dT%H:%M:%fZ','now'))
             ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = '1',
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            [],
        )
        .map_err(|e| {
            format!(
                "backup does not contain a writable application_settings table (incompatible backup?): {e}"
            )
        })?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(format!("restore_pending task: {e}")))?;

    if let Err(msg) = mark_result {
        let _ = std::fs::remove_file(&tmp);
        return Ok((
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            msg,
        )
            .into_response());
    }

    // Swap the live database aside and move the upload into place.
    let stamp = utc_stamp();
    let bak = state.database_path.with_file_name(format!(
        "{}.bak-{}",
        state
            .database_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("uptimepanda.db"),
        stamp
    ));
    if state.database_path.exists()
        && let Err(e) = std::fs::rename(&state.database_path, &bak)
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(AppError::Internal(format!("rename live db aside: {e}")));
    }
    for suffix in ["-wal", "-shm"] {
        let mut name = state.database_path.as_os_str().to_owned();
        name.push(suffix);
        let side = PathBuf::from(&name);
        if side.exists() {
            let _ = std::fs::rename(
                &side,
                bak.with_file_name(format!(
                    "{}{}",
                    bak.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("uptimepanda.db.bak"),
                    suffix
                )),
            );
        }
    }
    std::fs::rename(&tmp, &state.database_path)
        .map_err(|e| AppError::Internal(format!("activate restored db: {e}")))?;

    let bak_name = bak
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| bak.display().to_string());
    tracing::warn!(bak = %bak.display(), "database restored from upload; restart required");

    if wants_htmx(&headers) {
        Ok(Html(format!(
            "<strong>Restore complete.</strong> Restart the process to activate the restored database. The previous database was kept as <code>{}</code>.",
            escape_basic(&bak_name)
        ))
        .into_response())
    } else {
        html(templates::render_ok(&RestoreDonePage { bak_name }))
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

async fn settings_page(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
) -> Result<Response, AppError> {
    let chrome = build_chrome(&state, "Settings", "settings", &session);
    let views = crate::config::effective_settings(&state.db).await?;
    let settings = views
        .into_iter()
        .map(|v| {
            let bounds = if v.is_bool {
                "true|false".to_string()
            } else if v.key == "active_window_default" {
                "'<N>h' (1–168)".to_string()
            } else if v.key == "log_level" {
                "trace|debug|info|warn|error".to_string()
            } else {
                match (v.min, v.max) {
                    (Some(min), Some(max)) => format!("{min}–{max}"),
                    _ => String::new(),
                }
            };
            SettingRowView {
                key: v.key.to_string(),
                value: v.value,
                default: v.default.to_string(),
                bounds,
                help: v.help.to_string(),
                inputmode: if v.is_bool { "text" } else { "numeric" },
            }
        })
        .collect();
    html(templates::render_ok(&SettingsPage { chrome, settings }))
}

#[derive(Deserialize)]
pub struct SettingForm {
    key: String,
    value: String,
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    /// Consumed by the `require_auth` middleware (see CsrfOnlyForm).
    #[allow(dead_code)]
    csrf_token: String,
}

async fn settings_update(
    State(state): State<SharedState>,
    _session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<SettingForm>,
) -> Result<Response, AppError> {
    let key = form.key.trim();
    // set_setting validates the key against the seed table and the bounds,
    // including the interval/session pair invariants.
    match crate::config::set_setting(&state.db, key, form.value.trim()).await {
        Ok(()) => {
            let msg = format!("Set {key} = {}", form.value.trim());
            if wants_htmx(&headers) {
                Ok(Html(toast("ok", msg)).into_response())
            } else {
                Ok(Redirect::to("/settings").into_response())
            }
        }
        Err(msg) => {
            let full = format!("{key}: {msg}");
            if wants_htmx(&headers) {
                Ok(Html(toast("err", full)).into_response())
            } else {
                Ok(templates::error_page(StatusCode::BAD_REQUEST, "400", &full))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Route-table tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::Db;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    const TEST_PASSWORD: &str = "correct-horse-battery";
    const TEST_ENCRYPTION_KEY: &str = "0123456789abcdef0123";

    fn test_config(dir: &std::path::Path) -> Config {
        Config::resolve(&|k: &str| match k {
            "APP_PASSWORD" => Some(TEST_PASSWORD.to_string()),
            "ENCRYPTION_KEY" => Some(TEST_ENCRYPTION_KEY.to_string()),
            "DATABASE_PATH" => Some(dir.join("uptimepanda.db").to_string_lossy().into_owned()),
            "BACKUP_DIR" => Some(dir.join("backups").to_string_lossy().into_owned()),
            _ => None,
        })
        .expect("test config resolves")
    }

    async fn in_memory_state(dir: &std::path::Path) -> SharedState {
        let config = test_config(dir);
        let db = Db::in_memory().await.expect("open in-memory db");
        crate::config::seed_settings(&db)
            .await
            .expect("seed settings");
        Arc::new(AppState::new(db, None, None, &config, "2026.11.09.1-alpha"))
    }

    async fn file_db_state(dir: &std::path::Path) -> SharedState {
        let config = test_config(dir);
        let db = Db::open(&config.database_path).await.expect("open file db");
        crate::config::seed_settings(&db)
            .await
            .expect("seed settings");
        Arc::new(AppState::new(db, None, None, &config, "2026.11.09.1-alpha"))
    }

    use std::sync::Arc;

    fn app(state: SharedState) -> Router {
        build_router(state)
    }

    async fn request(
        app: Router,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Body,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut builder = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder.body(body).expect("request builds");
        let response = app.oneshot(req).await.expect("router responds");
        let status = response.status();
        let res_headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("body reads")
            .to_vec();
        (status, res_headers, bytes)
    }

    fn form_urlencoded_value(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    async fn login_cookie(app: &Router) -> String {
        let headers = [("content-type", "application/x-www-form-urlencoded")];
        let (status, hdrs, _body) = request(
            app.clone(),
            "POST",
            "/login",
            &headers,
            Body::from(format!("password={TEST_PASSWORD}")),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "login redirects");
        let set_cookie = hdrs
            .get(header::SET_COOKIE)
            .expect("session cookie set")
            .to_str()
            .expect("cookie is utf-8")
            .to_string();
        set_cookie
            .split(';')
            .next()
            .expect("cookie pair")
            .to_string()
    }

    async fn csrf_for(app: &Router, cookie: &str) -> String {
        // The CSRF token is derivable client-side from the session cookie;
        // for tests, read it from the rendered settings page instead.
        let (status, _h, body) = request(
            app.clone(),
            "GET",
            "/settings",
            &[("cookie", cookie)],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8(body).expect("settings page utf-8");
        let marker = "name=\"csrf-token\" content=\"";
        let start = text.find(marker).expect("csrf meta present") + marker.len();
        let end = text[start..].find('"').expect("csrf meta terminated");
        text[start..start + end].to_string()
    }

    // --- public routes ---

    #[tokio::test]
    async fn health_is_open_and_browser_free() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, _h, body) = request(app(state), "GET", "/health", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("health json");
        assert_eq!(json["status"], "ok");
        assert!(json["version"].as_str().is_some_and(|v| !v.is_empty()));
    }

    #[tokio::test]
    async fn post_health_is_405() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, _h, _b) = request(app(state), "POST", "/health", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn public_styles_css_served_with_content_type() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, headers, body) =
            request(app(state), "GET", "/public/styles.css", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/css; charset=utf-8")
        );
        assert!(body.windows(8).any(|w| w == b"--accent"), "serves real css");
    }

    #[tokio::test]
    async fn public_traversal_blocked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        for path in [
            "/public/../Cargo.toml",
            "/public/%2e%2e/%2e%2e/Cargo.toml",
            "/public/..%2fCargo.toml",
        ] {
            let (status, _h, _b) =
                request(app(state.clone()), "GET", path, &[], Body::empty()).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "traversal blocked for {path}"
            );
        }
    }

    #[tokio::test]
    async fn public_font_woff2() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, headers, _b) = request(
            app(state),
            "GET",
            "/public/fonts/jetbrains-mono-400.woff2",
            &[],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("font/woff2")
        );
    }

    // --- auth shell ---

    #[tokio::test]
    async fn unauthed_routes_redirect_to_login() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        for path in [
            "/",
            "/websites",
            "/profiles",
            "/history",
            "/system",
            "/settings",
            "/api/system",
            "/fragments/overview",
            "/fragments/system",
            "/fragments/history-rows",
            "/websites/1/interactions",
        ] {
            let (status, headers, _b) =
                request(app(state.clone()), "GET", path, &[], Body::empty()).await;
            assert_eq!(status, StatusCode::SEE_OTHER, "GET {path} redirects");
            assert_eq!(
                headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
                Some("/login"),
                "GET {path} redirects to /login"
            );
        }
    }

    #[tokio::test]
    async fn login_get_renders() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, _h, body) = request(app(state), "GET", "/login", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("Dashboard password"), "login form renders");
    }

    #[tokio::test]
    async fn login_wrong_then_right_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;

        let (status, _h, body) = request(
            app(state.clone()),
            "POST",
            "/login",
            &[("content-type", "application/x-www-form-urlencoded")],
            Body::from("password=wrong-password"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&body).contains("Invalid credentials"));

        let (status, headers, _b) = request(
            app(state.clone()),
            "POST",
            "/login",
            &[("content-type", "application/x-www-form-urlencoded")],
            Body::from(format!("password={TEST_PASSWORD}")),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
            Some("/")
        );
        let cookie = headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("cookie")
            .to_string();
        assert!(cookie.contains("uptime_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));

        let authed = cookie.split(';').next().expect("cookie pair").to_string();
        let (status, _h, body) = request(
            app(state),
            "GET",
            "/",
            &[("cookie", authed.as_str())],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8(body).unwrap().contains("Overview"));
    }

    // --- CSRF + mutations ---

    #[tokio::test]
    async fn csrf_missing_on_website_create_is_403() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            "/websites",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from("name=x&url=https%3A%2F%2Fexample.com%2F"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn website_create_rejects_static_bad_urls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;
        for bad in [
            "javascript:alert(1)",
            "http://127.0.0.1/",
            "ftp://example.com/",
        ] {
            let body = format!(
                "name=x&url={}&monitoring_mode=basic&min_interval_seconds=480&max_interval_seconds=780&min_session_seconds=15&max_session_seconds=60&csrf_token={}",
                form_urlencoded_value(bad),
                csrf
            );
            let (status, _h, body_bytes) = request(
                app.clone(),
                "POST",
                "/websites",
                &[
                    ("cookie", cookie.as_str()),
                    ("content-type", "application/x-www-form-urlencoded"),
                ],
                Body::from(body),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "rejects {bad}");
            assert!(
                String::from_utf8_lossy(&body_bytes).contains("URL rejected"),
                "message explains rejection: {bad}"
            );
        }
    }

    #[tokio::test]
    async fn profile_create_and_csrf() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;

        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            "/profiles",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from(format!(
                "name=p&description=&ua_preset=&user_agent=&csrf_token={csrf}"
            )),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            "/profiles",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from("name=p2"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn settings_patch_flow() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;
        let patch_headers = [
            ("cookie", cookie.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
        ];
        let patch = |body: &str| {
            request(
                app.clone(),
                "PATCH",
                "/settings",
                &patch_headers,
                Body::from(body.to_string()),
            )
        };
        let (status, _h, _b) = patch("key=memory_restart_mb&value=150&csrf_token=WRONG").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _h, _b) = patch(&format!("key=no_such_key&value=1&csrf_token={csrf}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _h, _b) =
            patch(&format!("key=memory_restart_mb&value=50&csrf_token={csrf}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _h, _b) = patch(&format!(
            "key=memory_restart_mb&value=150&csrf_token={csrf}"
        ))
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn fragments_and_pages_require_auth() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        for path in [
            "/",
            "/websites",
            "/profiles",
            "/history",
            "/system",
            "/settings",
            "/fragments/overview",
            "/fragments/system",
            "/fragments/history-rows",
            "/api/system",
        ] {
            let (status, _h, body) = request(
                app.clone(),
                "GET",
                path,
                &[("cookie", cookie.as_str())],
                Body::empty(),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "GET {path}");
            assert!(!body.is_empty(), "GET {path} returns content");
        }
    }

    #[tokio::test]
    async fn interactions_editor_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state.clone());
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;

        // Seed a website directly (web-layer creation requires DNS-reachable URLs).
        let now = time::OffsetDateTime::now_utc();
        let site_id = state
            .db
            .insert_website(&crate::db::Website {
                id: 0,
                name: "Example".to_string(),
                url: "https://example.com/".to_string(),
                enabled: true,
                profile_id: None,
                monitoring_mode: MonitoringMode::Basic,
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
            })
            .await
            .expect("insert site");

        let (status, _h, body) = request(
            app.clone(),
            "GET",
            &format!("/websites/{site_id}/interactions"),
            &[("cookie", cookie.as_str())],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8(body).unwrap().contains("Sequence JSON"));

        // Invalid JSON → 400
        let body_raw = format!(
            "configuration_json={}&csrf_token={csrf}",
            form_urlencoded_value("{not json")
        );
        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            &format!("/websites/{site_id}/interactions"),
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from(body_raw),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Denylisted click selector → 400 (mentions the rule)
        let deny = r#"{"actions":[{"type":"click","selector":"button.checkout-now","wait_after_ms":500}]}"#;
        let body_raw = format!(
            "configuration_json={}&csrf_token={csrf}",
            form_urlencoded_value(deny)
        );
        let (status, _h, bytes) = request(
            app.clone(),
            "POST",
            &format!("/websites/{site_id}/interactions"),
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from(body_raw),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            String::from_utf8_lossy(&bytes)
                .to_lowercase()
                .contains("checkout")
        );

        // Valid sequence → 303
        let valid = r#"{"actions":[{"type":"wait_duration","ms":1000},{"type":"end_session"}],"on_error":"abort"}"#;
        let body_raw = format!(
            "configuration_json={}&enabled=on&csrf_token={csrf}",
            form_urlencoded_value(valid)
        );
        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            &format!("/websites/{site_id}/interactions"),
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from(body_raw),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        // The row is persisted and validates on read-back.
        let saved = state
            .db
            .get_interaction_sequence(site_id)
            .await
            .expect("read back")
            .expect("row exists");
        assert!(saved.enabled);
        assert!(saved.configuration_json.contains("wait_duration"));
    }

    #[tokio::test]
    async fn backup_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = file_db_state(dir.path()).await;
        let app = app(state.clone());
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;

        // POST /backup creates a file in BACKUP_DIR.
        let (status, _h, body) = request(
            app.clone(),
            "POST",
            "/backup",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from(format!("csrf_token={csrf}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&body).contains("backup written"));
        let backups: Vec<_> = std::fs::read_dir(dir.path().join("backups"))
            .expect("backups dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(backups.len(), 1, "one backup file created");
        let backup_bytes = std::fs::read(backups[0].path()).expect("read backup");

        // Garbage upload → 400.
        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            "/backup/restore",
            &[
                ("cookie", cookie.as_str()),
                ("x-csrf-token", csrf.as_str()),
                ("content-type", "application/octet-stream"),
            ],
            Body::from(vec![1u8, 2, 3, 4, 5, 6, 7, 8]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Valid upload → 200; the previous DB is kept as .bak-*.
        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            "/backup/restore",
            &[
                ("cookie", cookie.as_str()),
                ("x-csrf-token", csrf.as_str()),
                ("content-type", "application/octet-stream"),
            ],
            Body::from(backup_bytes),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("dir")
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            entries
                .iter()
                .any(|e| e.file_name().to_string_lossy().contains(".bak-")),
            "previous database kept as .bak-*"
        );
        assert!(dir.path().join("uptimepanda.db").exists());
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, _h, body) = request(app(state), "GET", "/nope", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(String::from_utf8(body).unwrap().contains("404"));
    }

    #[tokio::test]
    async fn missing_profile_delete_is_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;
        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            "/profiles/424242/delete",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from(format!("csrf_token={csrf}")),
        )
        .await;
        // htmx-less: 303 redirect (row already absent counts as handled).
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::NOT_FOUND);
    }

    // --- auth helpers (pure) ---

    #[test]
    fn session_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600;
        let cookie = crate::web::auth::sign_session(&key, expiry);
        assert_eq!(
            crate::web::auth::verify_session(&key, &cookie),
            Some(expiry)
        );
        // Tampered signature rejected.
        let mut bad = cookie.clone();
        let idx = bad.len() - 1;
        bad.replace_range(idx.., if bad.ends_with('a') { "b" } else { "a" });
        assert_eq!(crate::web::auth::verify_session(&key, &bad), None);
        // Expired session rejected.
        let old = crate::web::auth::sign_session(&key, expiry - 7200);
        assert_eq!(crate::web::auth::verify_session(&key, &old), None);
        // Garbage rejected.
        assert_eq!(crate::web::auth::verify_session(&key, "!!!"), None);
    }

    #[test]
    fn csrf_token_stable_and_constant_time_check() {
        let key = [9u8; 32];
        let t1 = crate::web::csrf::csrf_token(&key);
        let t2 = crate::web::csrf::csrf_token(&key);
        let t3 = crate::web::csrf::csrf_token(&[1u8; 32]);
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
        assert!(crate::web::csrf::tokens_equal(&t1, &t2));
        assert!(!crate::web::csrf::tokens_equal(&t1, &t3));
        assert!(!crate::web::csrf::tokens_equal(&t1, "zz"));
        assert!(crate::web::csrf::verify(&key, &t1));
    }

    #[test]
    fn login_throttler_locks_out_after_five() {
        use crate::web::auth::*;
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 9, 8, 7));
        for _ in 0..5 {
            assert!(lockout_remaining(ip).is_none(), "not locked before 5 fails");
            record_failure(ip);
        }
        assert!(lockout_remaining(ip).is_some(), "locked after 5 fails");
        clear_failures(ip);
        assert!(lockout_remaining(ip).is_none(), "cleared");
    }

    #[test]
    fn password_constant_time_compare() {
        assert!(crate::web::auth::constant_time_eq(
            "s3cret-password",
            "s3cret-password"
        ));
        assert!(!crate::web::auth::constant_time_eq(
            "s3cret-password",
            "s3cret-passwore"
        ));
        assert!(!crate::web::auth::constant_time_eq(
            "s3cret-password",
            "short"
        ));
    }

    #[test]
    fn host_path_strips_query_and_fragment() {
        // Route through the same helper used for public URLs.
        let hp = templates::host_path_lossy("https://sub.example.com:8443/path?token=abc#frag");
        assert_eq!(hp, "https://sub.example.com:8443/path");
        assert!(!hp.contains("token"));
    }

    #[test]
    fn form_urlencoded_value_encodes() {
        assert_eq!(form_urlencoded_value("a b&c=d"), "a%20b%26c%3Dd");
    }
    // --- SEG-13: security headers, renewal, trust-proxy tests ---

    fn assert_security_headers(headers: &HeaderMap, hsts: bool, no_store: bool) {
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        assert_eq!(get("x-frame-options").as_deref(), Some("DENY"));
        assert_eq!(get("x-content-type-options").as_deref(), Some("nosniff"));
        assert_eq!(get("referrer-policy").as_deref(), Some("no-referrer"));
        let csp = get("content-security-policy").expect("CSP present");
        assert!(csp.contains("default-src 'self'"), "{csp}");
        assert!(csp.contains("script-src 'self'"), "{csp}");
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        assert!(!csp.contains("unsafe-eval"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(csp.contains("base-uri 'none'"), "{csp}");
        assert!(csp.contains("form-action 'self'"), "{csp}");
        assert!(csp.contains("img-src 'self' data:"), "{csp}");
        assert!(csp.contains("font-src 'self'"), "{csp}");
        assert!(csp.contains("connect-src 'self'"), "{csp}");
        let hsts_value = get("strict-transport-security");
        if hsts {
            assert_eq!(
                hsts_value.as_deref(),
                Some("max-age=31536000; includeSubDomains")
            );
        } else {
            assert!(hsts_value.is_none(), "HSTS must not leak onto plain HTTP");
        }
        let cache = get("cache-control");
        if no_store {
            assert_eq!(cache.as_deref(), Some("no-store"));
        }
    }

    #[tokio::test]
    async fn security_headers_on_health_get() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, headers, _b) = request(app(state), "GET", "/health", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert_security_headers(&headers, false, true);
    }

    #[tokio::test]
    async fn security_headers_on_root_redirect_when_unauthenticated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, headers, _b) = request(app(state), "GET", "/", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_security_headers(&headers, false, true);
    }

    #[tokio::test]
    async fn security_headers_on_404_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, headers, _b) =
            request(app(state), "GET", "/no-such-page", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_security_headers(&headers, false, true);
    }

    #[tokio::test]
    async fn security_headers_on_authed_page_and_static_asset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        // Authed HTML page: no-store.
        let (status, headers, _b) = request(
            app.clone(),
            "GET",
            "/",
            &[("cookie", cookie.as_str())],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_security_headers(&headers, false, true);
        // Static asset: keeps its own cache policy, still gets the base set.
        let (status, headers, _b) =
            request(app, "GET", "/public/styles.css", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        let cache = headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(cache.contains("max-age=3600"), "{cache}");
        assert!(!cache.contains("no-store"), "{cache}");
        assert_security_headers(&headers, false, false);
    }

    #[tokio::test]
    async fn hsts_only_when_forwarded_proto_https() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let (_s, headers, _b) = request(
            app.clone(),
            "GET",
            "/health",
            &[("x-forwarded-proto", "https")],
            Body::empty(),
        )
        .await;
        assert_security_headers(&headers, true, true);
        // Case-insensitive per RFC 7230 §3.2.6 + the middleware's fold.
        let (_s, headers, _b) = request(
            app.clone(),
            "GET",
            "/health",
            &[("x-forwarded-proto", "HTTPS")],
            Body::empty(),
        )
        .await;
        assert_security_headers(&headers, true, true);
        // Explicit http → never HSTS.
        let (_s, headers, _b) = request(
            app,
            "GET",
            "/health",
            &[("x-forwarded-proto", "http")],
            Body::empty(),
        )
        .await;
        assert_security_headers(&headers, false, true);
    }

    #[tokio::test]
    async fn login_sets_secure_cookie_only_behind_https_proxy() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Plain HTTP (no proxy header): cookie must NOT be Secure, so
        // plain-HTTP deployments keep working.
        let state = in_memory_state(dir.path()).await;
        let (status, headers, _b) = request(
            app(state),
            "POST",
            "/login",
            &[("content-type", "application/x-www-form-urlencoded")],
            Body::from(format!("password={TEST_PASSWORD}")),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let cookie = headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("set-cookie")
            .to_string();
        assert!(!cookie.contains("Secure"), "{cookie}");

        // HTTPS at the proxy: cookie gets Secure.
        let state = in_memory_state(dir.path()).await;
        let (status, headers, _b) = request(
            app(state),
            "POST",
            "/login",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("x-forwarded-proto", "https"),
            ],
            Body::from(format!("password={TEST_PASSWORD}")),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let cookie = headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("set-cookie")
            .to_string();
        assert!(cookie.contains("; Secure"), "{cookie}");
    }

    #[tokio::test]
    async fn sliding_renewal_reissues_expiring_session_cookie() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let key = state.session_key;
        let app = app(state);

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // Session with 2h of TTL left (< 6h threshold) → renewal expected.
        let old_value = crate::web::auth::sign_session(&key, now + 2 * 3600);
        let (status, headers, _b) = request(
            app.clone(),
            "GET",
            "/",
            &[("cookie", format!("uptime_session={old_value}").as_str())],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let renewed = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("uptime_session="))
            .expect("renewed session cookie appended")
            .to_string();
        let pair = renewed.split(';').next().expect("cookie pair");
        let value = pair.split('=').nth(1).expect("cookie value");
        let expiry =
            crate::web::auth::verify_session(&key, value).expect("renewed cookie verifies");
        let remaining = expiry - time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(
            (12 * 3600 - 30..=12 * 3600).contains(&remaining),
            "renewed cookie should carry a fresh 12h TTL, got {remaining}s"
        );

        // Fresh session (> 6h left) → no renewal, no Set-Cookie.
        let fresh_value = crate::web::auth::sign_session(&key, now + 11 * 3600);
        let (status, headers, _b) = request(
            app,
            "GET",
            "/",
            &[("cookie", format!("uptime_session={fresh_value}").as_str())],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let any_session_cookie = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.starts_with("uptime_session="));
        assert!(!any_session_cookie, "fresh session must not be renewed");
    }

    #[tokio::test]
    async fn sliding_renewal_preserves_secure_behind_https_proxy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let key = state.session_key;
        let app = app(state);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let old_value = crate::web::auth::sign_session(&key, now + 3600);
        let (status, headers, _b) = request(
            app,
            "GET",
            "/",
            &[
                ("cookie", format!("uptime_session={old_value}").as_str()),
                ("x-forwarded-proto", "https"),
            ],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let renewed = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("uptime_session="))
            .expect("renewed cookie")
            .to_string();
        assert!(renewed.contains("; Secure"), "{renewed}");
    }

    #[tokio::test]
    async fn csrf_rejects_equal_length_wrong_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;
        // Same length, valid hex, wrong value (constant-time compare path).
        let wrong: String = csrf
            .chars()
            .map(|c| if c == '0' { '1' } else { '0' })
            .collect();
        assert_eq!(csrf.len(), wrong.len());
        let (status, _h, _b) = request(
            app,
            "PATCH",
            "/settings",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from(format!(
                "key=memory_restart_mb&value=150&csrf_token={wrong}"
            )),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn app_js_is_served_as_javascript() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let (status, headers, body) =
            request(app(state), "GET", "/public/app.js", &[], Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        let ct = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(ct.starts_with("text/javascript"), "{ct}");
        let text = String::from_utf8(body).expect("app.js utf-8");
        assert!(text.contains("window.appToast"));
        assert!(text.contains("htmx:config:request"));
    }
}
