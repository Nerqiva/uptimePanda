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
        .route(
            "/settings/restore-defaults",
            post(settings_restore_defaults),
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

async fn collect_system_stats(state: &AppState) -> Result<SystemStatsView, AppError> {
    let browser = browser_summary(state);
    let snap = crate::resources::ResourceSnapshot::collect(
        &state.db,
        state.manager.as_deref(),
        state.scheduler.as_ref(),
    )
    .await;
    let tight_budget = crate::resources::tight_budget(snap.mem_total_mb, snap.mem_available_mb);
    let db_warn_mb = crate::config::typed_i64(&state.db, "db_size_warn_mb")
        .await
        .unwrap_or(64);
    let db_over_warn = snap.db_size_mb > db_warn_mb as f64;
    let queue_len = snap.queue_length;
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
        db_size_mb: format!("{:.1}", snap.db_size_mb),
        mem_available_mb: if snap.mem_available_mb > 0 {
            snap.mem_available_mb.to_string()
        } else {
            "—".to_string()
        },
        app_rss_mb: snap.app_rss_mb.to_string(),
        tight_budget,
        db_over_warn,
        db_warn_mb,
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
                "health_warn" | "crashed" | "crash_loop" | "respawn_failed" | "db_size_warn"
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
    let snap = crate::resources::ResourceSnapshot::collect(
        &state.db,
        state.manager.as_deref(),
        state.scheduler.as_ref(),
    )
    .await;
    let tight_budget = crate::resources::tight_budget(snap.mem_total_mb, snap.mem_available_mb);
    let (
        browser_running,
        lightpanda_rss_mb,
        lightpanda_cpu_pct,
        browser_pid,
        browser_uptime_s,
        browser_restarts_total,
    ) = match &snap.lightpanda {
        Some(s) => (
            s.running,
            s.rss_mb,
            s.cpu_pct,
            s.pid.unwrap_or(0) as u64,
            s.uptime_s,
            s.restarts_total,
        ),
        None => (false, 0.0, 0.0, 0, 0, 0),
    };
    // SEG-15: every numeric value is a JSON number (0 = unavailable); the
    // browser-absent case is reported by `browser_running: false` and zeros.
    let payload = serde_json::json!({
        "app_version": state.version.trim(),
        "version": state.version.trim(),
        "browser_running": browser_running,
        "lightpanda_rss_mb": lightpanda_rss_mb,
        "lightpanda_cpu_pct": lightpanda_cpu_pct,
        "browser_pid": browser_pid,
        "browser_uptime_s": browser_uptime_s,
        "browser_restarts_total": browser_restarts_total,
        "queue_length": snap.queue_length,
        "db_size_mb": snap.db_size_mb,
        "mem_available_mb": snap.mem_available_mb,
        "mem_total_mb": snap.mem_total_mb,
        "app_rss_mb": snap.app_rss_mb,
        "tight_budget": tight_budget,
        "uptime_s": state.boot_instant.elapsed().as_secs(),
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
    // SEG-14: prefill the Add-website form from the default_* settings,
    // live-read on every render (edits on the Settings page apply to the
    // next page load).
    let default_min_interval_seconds =
        crate::config::typed_i64(&state.db, "default_min_interval_seconds")
            .await
            .unwrap_or(480);
    let default_max_interval_seconds =
        crate::config::typed_i64(&state.db, "default_max_interval_seconds")
            .await
            .unwrap_or(780);
    let default_min_session_seconds =
        crate::config::typed_i64(&state.db, "default_min_session_seconds")
            .await
            .unwrap_or(15);
    let default_max_session_seconds =
        crate::config::typed_i64(&state.db, "default_max_session_seconds")
            .await
            .unwrap_or(60);
    html(templates::render_ok(&WebsitesPage {
        chrome,
        entries,
        profiles,
        form_error: String::new(),
        default_min_interval_seconds,
        default_max_interval_seconds,
        default_min_session_seconds,
        default_max_session_seconds,
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

/// Display bounds for one row; shared by the page renderer and the
/// single-row / restore-all fragments.
fn setting_bounds_label(v: &crate::config::SettingView) -> String {
    if v.is_bool {
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
    }
}

/// Keys that only take effect at the next boot; rows carrying one of these
/// get the subtle "restart required" chip. RSS/poll/browser keys are NOT
/// here — the manager and health loop re-read them live.
const RESTART_REQUIRED_KEYS: &[&str] = &["log_level", "sqlite_maintenance_on_boot"];
/// Keys shown read-only (pinned to the single canonical value).
const READ_ONLY_KEYS: &[&str] = &["concurrent_visits"];
const LOG_LEVEL_OPTIONS: &[&str] = &["trace", "debug", "info", "warn", "error"];

/// (title, blurb, anchor, keys) — display order is the contract with the
/// SEG-14 spec. Every SETTING_DEFAULTS key appears in exactly one group
/// (guarded by `setting_groups_cover_seed_table` in the test module).
const SETTING_GROUPS: &[(&str, &str, &str, &[&str])] = &[
    (
        "Browser & memory",
        "Process-level limits and cadence for the Lightpanda worker. RSS thresholds and the poll interval are re-read live on every health tick — edits apply on the next pass.",
        "browser-memory",
        &[
            "memory_warn_mb",
            "memory_restart_mb",
            "browser_restart_timeout_s",
            "browser_respawn_delay_s",
            "concurrent_visits",
            "rss_poll_interval_s",
        ],
    ),
    (
        "Navigation & visits",
        "Per-visit navigation and session-budget bounds. The default_min/max_* pairs prefill the Add-website form on the next page load; ua_presets_enabled gates the compatibility UA override, checked per visit.",
        "navigation-visits",
        &[
            "nav_timeout_s",
            "visit_timeout_s",
            "max_session_seconds_cap",
            "default_min_interval_seconds",
            "default_max_interval_seconds",
            "default_min_session_seconds",
            "default_max_session_seconds",
            "ua_presets_enabled",
        ],
    ),
    (
        "Scheduler & interactions",
        "Queueing and interaction-sequence bounds. The queue bound is live-checked on every manual enqueue (scheduled refills flow from the DB source of truth and are not rejected).",
        "scheduler-interactions",
        &[
            "active_window_default",
            "max_queue_length",
            "max_actions_per_sequence",
            "interaction_scroll_max_ops",
            "interaction_click_wait_max_ms",
        ],
    ),
    (
        "History & database",
        "Retention and storage guards. history_retention_days is enforced by the retention pass (on boot, then every 24h). db_size_warn_mb is enforced there too: an over-threshold database logs a warning and records a db_size_warn browser_events row, and the System page shows a badge.",
        "history-database",
        &[
            "history_retention_days",
            "sqlite_maintenance_on_boot",
            "db_size_warn_mb",
        ],
    ),
    (
        "Logging",
        "Boot-time tracing filter. The value is stored now; the running process keeps its boot-time filter — restart required.",
        "logging",
        &["log_level"],
    ),
];

fn setting_row_view(v: crate::config::SettingView, csrf: &str, oob: bool) -> SettingRowView {
    let read_only = READ_ONLY_KEYS.contains(&v.key);
    let needs_restart = RESTART_REQUIRED_KEYS.contains(&v.key);
    let input_kind: &'static str = if read_only {
        "fixed"
    } else if v.is_bool {
        "bool"
    } else if v.key == "log_level" {
        "select"
    } else if v.min.is_some() && v.max.is_some() {
        "number"
    } else {
        "text"
    };
    let inputmode: &'static str = if v.is_bool || v.key == "log_level" {
        "text"
    } else if v.min.is_some() {
        "numeric"
    } else {
        "text"
    };
    let bounds = setting_bounds_label(&v);
    let default_badge = v.value == v.default;
    let min_attr = v.min.map(|m| m.to_string()).unwrap_or_default();
    let max_attr = v.max.map(|m| m.to_string()).unwrap_or_default();
    let select_options = if v.key == "log_level" {
        LOG_LEVEL_OPTIONS
            .iter()
            .map(|value| SelectOptionView {
                value,
                selected: *value == v.value,
            })
            .collect()
    } else {
        Vec::new()
    };
    SettingRowView {
        key: v.key.to_string(),
        default_badge,
        value: v.value,
        default: v.default.to_string(),
        bounds,
        help: v.help.to_string(),
        input_kind,
        min_attr,
        max_attr,
        needs_restart,
        read_only,
        oob,
        csrf: csrf.to_string(),
        select_options,
        inputmode,
    }
}

fn setting_row_html(view: crate::config::SettingView, csrf: &str, oob: bool) -> String {
    let row = setting_row_view(view, csrf, oob);
    SettingRowFragment { s: &row }
        .render()
        .unwrap_or_else(|_| String::new())
}

/// Flatten views into SETTING_GROUPS order; unknown leftovers go last.
fn ordered_views(views: Vec<crate::config::SettingView>) -> Vec<crate::config::SettingView> {
    let mut by_key: HashMap<&'static str, crate::config::SettingView> =
        views.into_iter().map(|v| (v.key, v)).collect();
    let mut ordered = Vec::with_capacity(by_key.len());
    for (_title, _blurb, _anchor, keys) in SETTING_GROUPS {
        for key in *keys {
            if let Some(v) = by_key.remove(key) {
                ordered.push(v);
            }
        }
    }
    let mut leftover: Vec<_> = by_key.drain().collect();
    leftover.sort_by(|a, b| a.0.cmp(b.0));
    if !leftover.is_empty() {
        tracing::error!(keys = ?leftover.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            "SETTING_GROUPS is missing seed keys");
        ordered.extend(leftover.into_iter().map(|(_, v)| v));
    }
    ordered
}

async fn grouped_settings(state: &AppState) -> Result<SettingGroupsOutcome, AppError> {
    let views = crate::config::effective_settings(&state.db).await?;
    let total_keys = views.len();
    let default_keys = views.iter().filter(|v| v.value == v.default).count();
    let csrf = crate::web::csrf::csrf_token(&state.session_key);
    let mut by_key: HashMap<&'static str, crate::config::SettingView> =
        views.into_iter().map(|v| (v.key, v)).collect();
    let mut groups = Vec::with_capacity(SETTING_GROUPS.len() + 1);
    for (title, blurb, anchor, keys) in SETTING_GROUPS {
        let mut rows = Vec::with_capacity(keys.len());
        for key in *keys {
            if let Some(v) = by_key.remove(key) {
                rows.push(setting_row_view(v, &csrf, false));
            }
        }
        groups.push(SettingGroupView {
            title,
            blurb,
            anchor,
            rows,
        });
    }
    if !by_key.is_empty() {
        // A seed key missing from every group must never be silently
        // hidden — render it under "Other" and scream in the logs.
        let mut leftover: Vec<_> = by_key.drain().collect();
        leftover.sort_by(|a, b| a.0.cmp(b.0));
        tracing::error!(keys = ?leftover.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            "SETTING_GROUPS is missing keys; rendered under Other");
        groups.push(SettingGroupView {
            title: "Other",
            blurb: "Seed-table keys missing from the grouping table — this is a bug.",
            anchor: "other",
            rows: leftover
                .into_iter()
                .map(|(_, v)| setting_row_view(v, &csrf, false))
                .collect(),
        });
    }
    Ok(SettingGroupsOutcome {
        groups,
        total_keys,
        default_keys,
    })
}

struct SettingGroupsOutcome {
    groups: Vec<SettingGroupView>,
    total_keys: usize,
    default_keys: usize,
}

async fn settings_page(
    State(state): State<SharedState>,
    session: Extension<SessionInfo>,
) -> Result<Response, AppError> {
    let chrome = build_chrome(&state, "Settings", "settings", &session);
    let outcome = grouped_settings(&state).await?;
    html(templates::render_ok(&SettingsPage {
        chrome,
        groups: outcome.groups,
        total_keys: outcome.total_keys,
        default_keys: outcome.default_keys,
    }))
}

#[derive(Deserialize)]
pub struct SettingForm {
    key: String,
    /// Checkbox rows submit nothing when unchecked; text/number rows always send it.
    value: Option<String>,
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

/// Re-render the row fragment for `key` post-write (or post-rejection,
/// which shows the unchanged DB value). Returns `None` for unknown keys —
/// crafted forms cannot target a row that does not exist.
async fn rerender_row(state: &AppState, key: &str) -> Option<String> {
    let csrf = crate::web::csrf::csrf_token(&state.session_key);
    match crate::config::view_setting(&state.db, key).await {
        Ok(Some(view)) => Some(setting_row_html(view, &csrf, false)),
        _ => None,
    }
}

async fn settings_update(
    State(state): State<SharedState>,
    _session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(form): Form<SettingForm>,
) -> Result<Response, AppError> {
    let key = form.key.trim().to_string();
    let is_bool = crate::config::is_bool_key(&key) == Some(true);
    // set_setting validates the key against the seed table and the bounds,
    // including the interval/session pair invariants — not weakened here.
    let raw_value = match (form.value.as_deref().map(str::trim), is_bool) {
        (Some(v), _) => v.to_string(),
        // Unchecked checkbox submits no `value` — that *is* the boolean false.
        (None, true) => "false".to_string(),
        (None, false) => String::new(), // rejected by the validator below
    };
    match crate::config::set_setting(&state.db, &key, &raw_value).await {
        Ok(()) => {
            let msg = format!("Set {key} = {raw_value}");
            if wants_htmx(&headers) {
                let mut body = rerender_row(&state, &key).await.unwrap_or_default();
                body.push_str(&toast("ok", msg));
                Ok(Html(body).into_response())
            } else {
                Ok(Redirect::to("/settings").into_response())
            }
        }
        Err(msg) => {
            let full = format!("{key}: {msg}");
            if wants_htmx(&headers) {
                let mut body = rerender_row(&state, &key).await.unwrap_or_default();
                body.push_str(&toast("err", full));
                Ok(Html(body).into_response())
            } else {
                Ok(templates::error_page(StatusCode::BAD_REQUEST, "400", &full))
            }
        }
    }
}

/// Restore every seeded key to its SEG-04 default in a single transaction;
/// defaults are canonical so validation is bypassed by design.
async fn settings_restore_defaults(
    State(state): State<SharedState>,
    _session: Extension<SessionInfo>,
    headers: HeaderMap,
    Form(_form): Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    match crate::config::restore_all_defaults(&state.db).await {
        Ok(written) => {
            tracing::info!(keys = written, "settings restored to defaults");
            let msg = "All settings restored to 512MB/0.15 vCPU defaults".to_string();
            if wants_htmx(&headers) {
                // Full settings-grid refresh out-of-band + toast (SEG-11
                // pattern): every row swaps itself by id.
                let views = crate::config::effective_settings(&state.db).await?;
                let ordered = ordered_views(views);
                let csrf = crate::web::csrf::csrf_token(&state.session_key);
                let rows: Vec<SettingRowView> = ordered
                    .into_iter()
                    .map(|v| setting_row_view(v, &csrf, true))
                    .collect();
                let mut body = templates::render_ok(&SettingsRestoreFragment { rows })?.0;
                body.push_str(&toast("ok", msg));
                Ok(Html(body).into_response())
            } else {
                Ok(Redirect::to("/settings").into_response())
            }
        }
        Err(msg) => {
            let full = format!("restore defaults failed: {msg}");
            tracing::error!(error = %full, "settings restore failed");
            if wants_htmx(&headers) {
                Ok(Html(toast("err", full)).into_response())
            } else {
                Ok(templates::error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "500",
                    &full,
                ))
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

    #[tokio::test]
    async fn api_system_json_has_expected_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        let (status, _h, body) = request(
            app,
            "GET",
            "/api/system",
            &[("cookie", cookie.as_str())],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("system json");
        for key in [
            "app_version",
            "version",
            "browser_running",
            "lightpanda_rss_mb",
            "lightpanda_cpu_pct",
            "browser_pid",
            "browser_uptime_s",
            "browser_restarts_total",
            "queue_length",
            "db_size_mb",
            "mem_available_mb",
            "mem_total_mb",
            "app_rss_mb",
            "tight_budget",
            "uptime_s",
        ] {
            assert!(json.get(key).is_some(), "missing key {key} in {json}");
        }
        assert!(json["version"].is_string());
        assert!(json["app_version"].is_string());
        assert_eq!(json["version"], json["app_version"]);
        assert!(json["browser_running"].is_boolean());
        assert!(json["tight_budget"].is_boolean());
        for key in [
            "lightpanda_rss_mb",
            "lightpanda_cpu_pct",
            "browser_pid",
            "browser_uptime_s",
            "browser_restarts_total",
            "queue_length",
            "db_size_mb",
            "mem_available_mb",
            "mem_total_mb",
            "app_rss_mb",
            "uptime_s",
        ] {
            assert!(json[key].is_number(), "{key} must be a JSON number: {json}");
        }
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

    // --- SEG-14: grouped settings page + restore defaults ---

    #[test]
    fn setting_groups_cover_seed_table_exactly_once() {
        let mut grouped: Vec<&str> = SETTING_GROUPS
            .iter()
            .flat_map(|(_t, _b, _a, keys)| keys.iter().copied())
            .collect();
        let grouped_len = grouped.len();
        grouped.sort();
        grouped.dedup();
        assert_eq!(
            grouped.len(),
            grouped_len,
            "duplicate key in SETTING_GROUPS"
        );
        assert_eq!(grouped.len(), 23, "every seed key must be grouped");
        for def in crate::config::SETTING_DEFAULTS {
            assert!(
                grouped.contains(&def.key),
                "seed key {} is not in any group",
                def.key
            );
        }
        // Restart chips exactly for the two boot-only keys.
        assert_eq!(
            RESTART_REQUIRED_KEYS,
            &["log_level", "sqlite_maintenance_on_boot"]
        );
    }

    async fn settings_get_body(app: &Router, cookie: &str) -> String {
        let (status, _h, body) = request(
            app.clone(),
            "GET",
            "/settings",
            &[("cookie", cookie)],
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        String::from_utf8(body).expect("settings page utf-8")
    }

    #[tokio::test]
    async fn settings_page_renders_groups_in_order_and_all_23_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state);
        let cookie = login_cookie(&app).await;
        let body = settings_get_body(&app, &cookie).await;
        // askama escapes '&' as &#38; — check the escaped header text.
        let positions = [
            body.find("Browser &#38; memory"),
            body.find("Navigation &#38; visits"),
            body.find("Scheduler &#38; interactions"),
            body.find("History &#38; database"),
            body.find("Logging"),
        ];
        let mut last = 0usize;
        for (i, pos) in positions.iter().enumerate() {
            let pos = pos.unwrap_or_else(|| panic!("group {i} header missing from page"));
            assert!(pos >= last, "group {i} rendered out of order");
            last = pos;
        }
        for def in crate::config::SETTING_DEFAULTS {
            assert!(
                body.contains(&format!("id=\"setting-row-{}\"", def.key)),
                "row for {} missing",
                def.key
            );
        }
        // Restart chips + fixed row annotations.
        assert!(body.contains("restart required"), "restart chip rendered");
        assert!(
            body.contains("1 by design"),
            "concurrent_visits pinned annotation rendered"
        );
        assert!(
            body.contains("action=\"/settings/restore-defaults\""),
            "restore defaults form rendered"
        );
        // concurrent_visits is read-only: no editable value input for it.
        assert!(
            !body.contains("aria-label=\"concurrent_visits\""),
            "concurrent_visits must not render an editor"
        );
    }

    #[tokio::test]
    async fn settings_default_badge_tracks_value_vs_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state.clone());
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;

        let body = settings_get_body(&app, &cookie).await;
        let row = |body: &str, key: &str| {
            let start = body
                .find(&format!("id=\"setting-row-{key}\""))
                .expect("row");
            let end = body[start + 1..]
                .find("id=\"setting-row-")
                .map(|n| start + 1 + n)
                .unwrap_or(body.len());
            body[start..end].to_string()
        };
        assert!(
            row(&body, "memory_warn_mb").contains("pill default-badge"),
            "default-valued row carries the default badge"
        );

        let (status, _h, _b) = request(
            app.clone(),
            "PATCH",
            "/settings",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from(format!("key=memory_warn_mb&value=161&csrf_token={csrf}")),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let body = settings_get_body(&app, &cookie).await;
        let row = row(&body, "memory_warn_mb");
        assert!(
            !row.contains("pill default-badge"),
            "mutated row loses the default badge"
        );
        assert!(row.contains("modified"), "mutated row shows modified pill");
    }

    #[tokio::test]
    async fn settings_htmx_patch_returns_row_fragment_and_toast() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state.clone());
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;

        let htmx = [
            ("cookie", cookie.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
            ("hx-request", "true"),
        ];
        let (status, _h, body) = request(
            app.clone(),
            "PATCH",
            "/settings",
            &htmx,
            Body::from(format!("key=memory_restart_mb&value=150&csrf_token={csrf}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8(body).expect("fragment utf-8");
        assert!(
            text.contains("id=\"setting-row-memory_restart_mb\""),
            "response re-renders the row fragment: {text}"
        );
        assert!(text.contains(">150<"), "row shows the new value: {text}");
        assert!(
            text.contains("hx-swap-oob=\"beforeend:#toast-region\""),
            "toast is OOB: {text}"
        );
        assert!(text.contains("Set memory_restart_mb = 150"), "{text}");

        // Validator message verbatim in the error toast; row re-rendered
        // unchanged.
        let (status, _h, body) = request(
            app.clone(),
            "PATCH",
            "/settings",
            &htmx,
            Body::from(format!("key=memory_restart_mb&value=50&csrf_token={csrf}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8(body).expect("fragment utf-8");
        assert!(
            text.contains("memory_restart_mb must be &#62;= 96"),
            "{text}"
        );
        assert!(text.contains("got 50"), "{text}");
        assert!(
            text.contains("id=\"setting-row-memory_restart_mb\""),
            "error path re-renders the row: {text}"
        );
        assert!(
            text.contains(">150<"),
            "rejected write keeps prior value: {text}"
        );
    }

    #[tokio::test]
    async fn settings_bool_toggle_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state.clone());
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;
        let form_headers = [
            ("cookie", cookie.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
        ];
        // Explicit false.
        let (status, _h, _b) = request(
            app.clone(),
            "PATCH",
            "/settings",
            &form_headers,
            Body::from(format!(
                "key=sqlite_maintenance_on_boot&value=false&csrf_token={csrf}"
            )),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            state
                .db
                .get_application_setting("sqlite_maintenance_on_boot")
                .await
                .expect("read")
                .as_deref(),
            Some("false")
        );
        // Unchecked checkbox semantics: submission with NO value field == false.
        let (status, _h, _b) = request(
            app.clone(),
            "PATCH",
            "/settings",
            &form_headers,
            Body::from(format!("key=sqlite_maintenance_on_boot&csrf_token={csrf}")),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            state
                .db
                .get_application_setting("sqlite_maintenance_on_boot")
                .await
                .expect("read")
                .as_deref(),
            Some("false")
        );
        // Back to true.
        let (status, _h, _b) = request(
            app.clone(),
            "PATCH",
            "/settings",
            &form_headers,
            Body::from(format!(
                "key=sqlite_maintenance_on_boot&value=true&csrf_token={csrf}"
            )),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            state
                .db
                .get_application_setting("sqlite_maintenance_on_boot")
                .await
                .expect("read")
                .as_deref(),
            Some("true")
        );
    }

    #[tokio::test]
    async fn settings_patch_cross_pair_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state.clone());
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;
        // min stays 480 while max is dragged to 60 → min > max → 400.
        let (status, _h, body) = request(
            app.clone(),
            "PATCH",
            "/settings",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Body::from(format!(
                "key=default_max_interval_seconds&value=60&csrf_token={csrf}"
            )),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let text = String::from_utf8(body).expect("error page utf-8");
        assert!(text.contains("default_min_interval_seconds"), "{text}");
        assert!(text.contains("480"), "{text}");
        // Unchanged.
        assert_eq!(
            state
                .db
                .get_application_setting("default_max_interval_seconds")
                .await
                .expect("read")
                .as_deref(),
            Some("780")
        );
    }

    #[tokio::test]
    async fn settings_restore_defaults_resets_mutated_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = in_memory_state(dir.path()).await;
        let app = app(state.clone());
        let cookie = login_cookie(&app).await;
        let csrf = csrf_for(&app, &cookie).await;
        let form_headers = [
            ("cookie", cookie.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
        ];

        // Mutate two keys.
        for (key, value) in [("memory_restart_mb", "150"), ("log_level", "debug")] {
            let (status, _h, _b) = request(
                app.clone(),
                "PATCH",
                "/settings",
                &form_headers,
                Body::from(format!("key={key}&value={value}&csrf_token={csrf}")),
            )
            .await;
            assert_eq!(status, StatusCode::SEE_OTHER);
        }

        // Plain (non-htmx) restore → 303.
        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            "/settings/restore-defaults",
            &form_headers,
            Body::from(format!("csrf_token={csrf}")),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            state
                .db
                .get_application_setting("memory_restart_mb")
                .await
                .expect("read")
                .as_deref(),
            Some("200")
        );
        assert_eq!(
            state
                .db
                .get_application_setting("log_level")
                .await
                .expect("read")
                .as_deref(),
            Some("info")
        );

        // Mutate again, restore via htmx → 200 + OOB rows + toast.
        for (key, value) in [("memory_restart_mb", "150")] {
            let (status, _h, _b) = request(
                app.clone(),
                "PATCH",
                "/settings",
                &form_headers,
                Body::from(format!("key={key}&value={value}&csrf_token={csrf}")),
            )
            .await;
            assert_eq!(status, StatusCode::SEE_OTHER);
        }
        let (status, _h, body) = request(
            app.clone(),
            "POST",
            "/settings/restore-defaults",
            &[
                ("cookie", cookie.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
                ("hx-request", "true"),
            ],
            Body::from(format!("csrf_token={csrf}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8(body).expect("restore fragment utf-8");
        assert!(
            text.contains("All settings restored to 512MB/0.15 vCPU defaults"),
            "{text}"
        );
        assert!(
            text.contains("id=\"setting-row-memory_restart_mb\""),
            "{text}"
        );
        assert!(
            text.matches("hx-swap-oob=\"outerHTML\"").count() >= 23,
            "restore response refreshes every row out-of-band: {text}"
        );
        assert_eq!(
            state
                .db
                .get_application_setting("memory_restart_mb")
                .await
                .expect("read")
                .as_deref(),
            Some("200"),
            "htmx restore also persists defaults"
        );

        // CSRF is enforced on the restore endpoint.
        let (status, _h, _b) = request(
            app.clone(),
            "POST",
            "/settings/restore-defaults",
            &form_headers,
            Body::from("csrf_token=WRONG"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // concurrent_visits stays 1 (canonical default), and the DB now
        // holds defaults for every seeded key.
        let rows = state.db.all_application_settings().await.expect("rows");
        assert_eq!(rows.len(), 23);
        for (key, value) in rows {
            let def = crate::config::SETTING_DEFAULTS
                .iter()
                .find(|d| d.key == key)
                .expect("seeded key");
            assert_eq!(value, def.value, "row {key} restored to default");
        }
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
