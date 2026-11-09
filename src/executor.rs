//! Visit executor — the end-to-end execution cycle for one monitoring job
//! (SEG-10).
//!
//! One `execute()` call performs exactly one visit:
//!
//!  0. **pre-flight memory guard** — when `MemAvailable` (`/proc/meminfo`)
//!     is below [`crate::resources::RESOURCE_GUARD_MIN_AVAILABLE_MB`] the
//!     visit is refused *before* the gate is taken: no `visit_history` row
//!     is written, no browser work starts. The caller maps the refusal to a
//!     retryable `timeout` scheduler completion (the scheduler owns backoff);
//!  1. loads the website (unknown id → `NavigationError` outcome, nothing
//!     recorded — `visit_history.website_id` is a foreign key);
//!  2. loads the browser profile when `websites.profile_id` is set. A profile
//!     that is missing or disabled aborts the visit with `InteractionError`;
//!     with `profile_id` NULL the visit runs profile-less (no UA override,
//!     no jar restore/capture — jar hygiene clearing still happens);
//!  3. acquires the manager's `visit_gate` for the **entire** visit — before
//!     `ensure_running()` — so a recycle can never SIGTERM the browser
//!     mid-visit. Released on every return path because the guard is bound
//!     in `execute`'s scope; (with one exception: a pre-flight memory-guard
//!     refusal returns `Err` *before* the gate is taken — nothing else is
//!     touched);
//!  4. ensures Lightpanda is running (`ensure_running`, ≤30 s). Failure →
//!     `BrowserCrash` outcome, recorded; no retry here (the scheduler owns
//!     the retry matrix);
//!  5. validates the configured URL with [`crate::security`] (http/https,
//!     public addresses only, DNS-resolved and checked). Failure →
//!     `NavigationError`;
//!  6. opens a **fresh CDP connection per visit** and one target
//!     (`about:blank`), applies the profile's UA override (verified no-op on
//!     Lightpanda 1.0.3, sent for forward compatibility), wipes the
//!     context-global cookie jar (Lightpanda has exactly one) and restores
//!     the profile's encrypted jar — before any navigation;
//!  7. navigates and waits for `loadEventFired` (`nav_timeout_s`). Captures
//!     `http_status` from the first buffered `Network.responseReceived` with
//!     `type == "Document"`, and `final_url` from `location.href`. The final
//!     URL is re-validated (redirect defence) — a violation aborts the visit
//!     with `NavigationError`;
//!  8. chooses the session duration uniformly in
//!     `[min_session_seconds, max_session_seconds]`, hard-capped once per
//!     visit by `max_session_seconds_cap`;
//!  9. runs the interaction sequence (parsed from `configuration_json`,
//!     fail-fast validated against settings-derived limits, same-origin
//!     `navigate` actions only) — or, with no sequence configured/enabled,
//!     the basic navigate → hold → close cycle. Sequence failures abort with
//!     `InteractionError` (or skip-and-continue with `on_error: "continue"`).
//!     Running out of the visit's total budget (`D`, the selected session
//!     duration) with actions still pending ends the visit as
//!     `InteractionError` ("session budget exceeded"); `end_session` stops
//!     interactions early *without* being an error;
//!  10. holds the page open for the remainder of the session window (this is
//!      the keep-alive half of uptimePanda);
//!  11. captures the live cookie jar (profile visits), persists it via
//!      [`ProfileSession::persist_after_visit`] and wipes the
//!      context-global jar — **before** the target is closed, always, on
//!      every exit path;
//!  12. closes the target — always, on every exit path;
//!  13. records the `visit_history` row (duration, status, `final_url`
//!      stripped to `scheme://host[:port]/path`, outcome, redacted error
//!      ≤ 400 chars, browser pid, post-visit browser RSS in bytes) and sets
//!      `websites.last_visit_at`. `scheduler_state` is advanced by the caller
//!      (the job loop in `main.rs`) via
//!      [`crate::scheduler::SchedulerHandle::handle_completion`], exactly
//!      once per job.
//!
//! URLs are only ever logged as `scheme://host[:port]/path` — query strings
//! may carry credentials. `error_message` is redacted through
//! [`security::redact_message`] before logging or recording.

use std::sync::Arc;
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::{debug, error, info, info_span, warn};
use url::Url;

use crate::browser::cdp::{CdpError, CdpEvent, CdpHandle, CookieInput, PageSession};
use crate::browser::manager::BrowserManager;
use crate::browser::sessions::{ProfileSession, USER_AGENT_OVERRIDE_LABEL};
use crate::config::{self, Config};
use crate::db::{
    Db, InteractionSequence as InteractionSequenceRow, Outcome, VisitHistoryRow, Website,
};
use crate::interactions::{
    Action, InteractionLimits, InteractionSequence, OnError, ScrollDirection, parse_sequence_json,
    validate_sequence,
};
use crate::security;

/// How a visit was requested. Mirrors [`crate::scheduler::Trigger`]; kept
/// separate so the executor does not depend on scheduler types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionTrigger {
    Scheduled,
    Manual,
}

/// Why a visit never started.
///
/// Distinct from `Outcome`: a guard refusal is **not** a visit and never
/// produces a `visit_history` row. The caller maps this onto a retryable
/// scheduler completion (see the job loop in `main.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorError {
    /// `MemAvailable` is below
    /// [`crate::resources::RESOURCE_GUARD_MIN_AVAILABLE_MB`]. Transient —
    /// the scheduler retries with backoff.
    ResourceGuard,
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutorError::ResourceGuard => write!(
                f,
                "insufficient available memory (MemAvailable < {} MB)",
                crate::resources::RESOURCE_GUARD_MIN_AVAILABLE_MB
            ),
        }
    }
}

impl std::error::Error for ExecutorError {}

/// Outcome of one executed visit. The caller (the job loop in `main.rs`)
/// maps this onto
/// [`crate::scheduler::SchedulerHandle::handle_completion`] exactly once —
/// see [`completion_outcome`].
#[derive(Debug, Clone)]
pub struct VisitOutcome {
    pub outcome: Outcome,
    /// Whole-visit wall-clock duration.
    pub duration: Duration,
    pub http_status: Option<i64>,
    /// `scheme://host[:port]/path` of the final URL (query stripped).
    pub final_url: Option<String>,
    /// Browser RSS in bytes, sampled post-visit; `None` if unavailable.
    pub memory_usage: Option<i64>,
}

/// The executor: one per process. Share via `Arc`.
pub struct Executor {
    db: Db,
    manager: Arc<BrowserManager>,
    encryption_key: String,
    /// Reserved for SEG-11/15/16 (visit caps, flags). Kept per the SEG-10
    /// contract; the DB-backed settings are the live control plane.
    #[allow(dead_code)]
    config: Arc<Config>,
}

/// Map the executor's outcome onto the outcome the scheduler consumes.
///
/// Both sides use [`crate::db::models::Outcome`] today; this function is the
/// single choke point so a future split stays a one-line change. Retry
/// semantics (retryable = timeout|navigation_error) are the scheduler's
/// business and unchanged by this mapping.
pub fn completion_outcome(outcome: Outcome) -> Outcome {
    outcome
}

const PER_ACTION_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_ACTION_TIMEOUT_MS: u64 = 10_000;
const WAIT_JS_POLL: Duration = Duration::from_millis(150);

// ---------------------------------------------------------------------------
// Pure, unit-testable helpers
// ---------------------------------------------------------------------------

/// Pick the session duration (seconds) for one visit: uniformly drawn from
/// `[min_s, max_s]`, then hard-capped at `cap_s` (the
/// `max_session_seconds_cap` setting). The cap wins even over the range's
/// lower bound — it is a hard ceiling, not a hint.
///
/// `min_s > max_s` (should be impossible; the DB enforces a CHECK
/// constraint) collapses to `min_s`. Negative inputs clamp at 0.
pub(crate) fn pick_session_seconds(min_s: i64, max_s: i64, cap_s: i64) -> i64 {
    let cap = cap_s.max(0);
    let lo = min_s.max(0);
    let hi = max_s.max(lo);
    let chosen = if lo == hi {
        lo
    } else {
        rand::random_range(lo..=hi)
    };
    chosen.min(cap)
}

/// Apply ±`jitter_pct`% relative jitter to `ms` (uniform), never returning
/// less than 0. `jitter_pct` clamps to `[0, 100]`; `draw` is the injected
/// uniform in `[0, 1)`.
pub(crate) fn jittered_wait_ms_with(ms: u64, jitter_pct: f64, draw: f64) -> u64 {
    let j = jitter_pct.clamp(0.0, 100.0) / 100.0;
    let offset = (draw - 0.5) * 2.0 * j;
    (ms as f64 * (1.0 + offset)).round().max(0.0) as u64
}

fn jittered_wait_ms(ms: u64, jitter_pct: f64) -> u64 {
    jittered_wait_ms_with(ms, jitter_pct, rand::random::<f64>())
}

/// Vary a scroll distance by ±`spread` (0.30 = ±30%), preserving the sign
/// and never collapsing a non-zero input to zero.
pub(crate) fn vary_distance(d: i64, spread: f64) -> i64 {
    if d == 0 {
        return 0;
    }
    let sign = d.signum();
    let mag = d.unsigned_abs() as f64;
    let factor = 1.0 + (rand::random::<f64>() - 0.5) * 2.0 * spread.clamp(0.0, 1.0);
    sign * (mag * factor).round().max(1.0) as i64
}

/// JS truthiness for `wait_js` conditions evaluated via `Runtime.evaluate`
/// (`returnByValue`): `false`/`0`/`""`/`null` are falsy; everything else —
/// including all objects and arrays, even empty ones — is truthy.
pub(crate) fn js_truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => true,
    }
}

// ---------------------------------------------------------------------------
// Internal flow types
// ---------------------------------------------------------------------------

enum NavResult {
    Loaded,
    Timeout,
    Failed(String),
}

enum SeqExit {
    Completed,
    EndSession,
    Aborted(String),
    BudgetExceeded,
    SecurityAbort(String),
}

enum ActionFlow {
    Continue,
    EndSession,
    RedirectBlocked,
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

impl Executor {
    pub fn new(
        db: Db,
        manager: Arc<BrowserManager>,
        encryption_key: String,
        config: Arc<Config>,
    ) -> Self {
        Self {
            db,
            manager,
            encryption_key,
            config,
        }
    }

    /// Execute one visit. Never panics on the normal path.
    ///
    /// Returns `Err(ExecutorError::ResourceGuard)` when `MemAvailable` is
    /// below the pre-flight floor — before the gate is taken, before any
    /// browser work, before `visit_history` is touched. Every other failure
    /// mode is a recorded `Outcome` (unknown-website, which FK-prevents a
    /// row, excepted).
    pub async fn execute(
        &self,
        website_id: i64,
        trigger: ExecutionTrigger,
    ) -> Result<VisitOutcome, ExecutorError> {
        // 0) Pre-flight memory guard — BEFORE the gate, before any work.
        //    A refusal leaves no trace in `visit_history` by design; the
        //    caller maps it to a retryable timeout completion.
        if let Some(avail) = crate::resources::mem_available_mb()
            && crate::resources::should_refuse(avail)
        {
            tracing::warn!(avail_mb = avail, "visit refused: memory guard");
            return Err(ExecutorError::ResourceGuard);
        }

        // Hold the visit gate for the ENTIRE visit — from before
        // ensure_running until the target is closed. Released on every
        // return path because the guard is bound in this function scope.
        let gate = self.manager.visit_gate();
        let _gate = gate.lock().await;

        let span = info_span!("visit", website_id, trigger = ?trigger);
        let _enter = span.enter();
        Ok(self.execute_inner(website_id, trigger).await)
    }

    async fn execute_inner(&self, website_id: i64, trigger: ExecutionTrigger) -> VisitOutcome {
        let started_at = OffsetDateTime::now_utc();
        let t0 = Instant::now();

        info!(trigger = ?trigger, "visit started");

        // 1) Load the website. Unknown id: record nothing (FK), map to
        //    NavigationError for the scheduler completion.
        let website = match self.db.get_website(website_id).await {
            Ok(Some(w)) => w,
            Ok(None) => {
                error!("visit requested for unknown website");
                return VisitOutcome {
                    outcome: Outcome::NavigationError,
                    duration: t0.elapsed(),
                    http_status: None,
                    final_url: None,
                    memory_usage: None,
                };
            }
            Err(e) => {
                error!(error = %security::redact_message(&e.to_string(), 200), "failed to load website");
                return VisitOutcome {
                    outcome: Outcome::NavigationError,
                    duration: t0.elapsed(),
                    http_status: None,
                    final_url: None,
                    memory_usage: None,
                };
            }
        };

        // 2) Load the profile when configured. A set-but-unloadable profile
        //    aborts with InteractionError (not retryable).
        let profile = match website.profile_id {
            Some(pid) => match ProfileSession::load_profile(self.db.clone(), pid).await {
                Ok(p) => {
                    debug!(profile_id = pid, "profile loaded");
                    Some(p)
                }
                Err(e) => {
                    let msg = security::redact_message(
                        &format!("profile load failed: {e}"),
                        security::MAX_ERROR_MESSAGE_LEN,
                    );
                    error!(error = %msg, "profile failed to load; aborting visit");
                    return self
                        .record_and_finish(
                            &website,
                            started_at,
                            t0,
                            Outcome::InteractionError,
                            Some(msg),
                            None,
                            None,
                            None,
                        )
                        .await;
                }
            },
            None => None,
        };

        // 3) Browser must be up (the gate is already ours).
        let port = match self.manager.ensure_running().await {
            Ok(p) => p,
            Err(e) => {
                let msg = security::redact_message(
                    &format!("browser unavailable: {e}"),
                    security::MAX_ERROR_MESSAGE_LEN,
                );
                error!(error = %msg, "browser did not become available");
                return self
                    .record_and_finish(
                        &website,
                        started_at,
                        t0,
                        Outcome::BrowserCrash,
                        Some(msg),
                        None,
                        None,
                        None,
                    )
                    .await;
            }
        };
        let browser_pid = self.manager.pid().await.map(|p| p as i64);

        // 4) Validate the configured URL (SSRF guard).
        let target_url = match security::validate_target(&website.url).await {
            Ok(u) => u,
            Err(reason) => {
                let msg = security::redact_message(&reason, security::MAX_ERROR_MESSAGE_LEN);
                warn!(reason = %msg, "target URL rejected by safety policy");
                return self
                    .record_and_finish(
                        &website,
                        started_at,
                        t0,
                        Outcome::NavigationError,
                        Some(msg),
                        None,
                        None,
                        browser_pid,
                    )
                    .await;
            }
        };
        let base_origin = target_url.clone();
        info!(host = %security::host_path(&target_url), "target validated");

        // 5) Fresh CDP connection + fresh target for this visit only.
        let cdp_url = format!("ws://127.0.0.1:{port}/");
        let cdp = match crate::browser::cdp::connect(&cdp_url).await {
            Ok(c) => c,
            Err(e) => {
                let msg = security::redact_message(
                    &format!("cdp connect failed: {e}"),
                    security::MAX_ERROR_MESSAGE_LEN,
                );
                error!(error = %msg, "failed to open CDP connection");
                return self
                    .record_and_finish(
                        &website,
                        started_at,
                        t0,
                        Outcome::BrowserCrash,
                        Some(msg),
                        None,
                        None,
                        browser_pid,
                    )
                    .await;
            }
        };
        let handle = cdp.into_handle();

        // ua_presets_enabled=false suppresses every UA override for this
        // visit (live read; default true). The profile's own UA is used
        // exactly as stored otherwise.
        let ua_enabled = config::typed_bool(&self.db, "ua_presets_enabled")
            .await
            .unwrap_or(true);
        let ua = if ua_enabled {
            profile
                .as_ref()
                .and_then(|p| p.user_agent().map(str::to_string))
        } else {
            None
        };
        if ua.is_some() {
            debug!(%USER_AGENT_OVERRIDE_LABEL, "sending ua override (engine may ignore)");
        }
        let page = match handle.open_page("about:blank", ua.as_deref()).await {
            Ok(p) => p,
            Err(e) => {
                let msg = security::redact_message(
                    &format!("open_page failed: {e}"),
                    security::MAX_ERROR_MESSAGE_LEN,
                );
                error!(error = %msg, "failed to open page target");
                return self
                    .record_and_finish(
                        &website,
                        started_at,
                        t0,
                        Outcome::NavigationError,
                        Some(msg),
                        None,
                        None,
                        browser_pid,
                    )
                    .await;
            }
        };
        let target_id = page.target_id().to_string();
        let session_id = page.session_id().to_string();
        // Subscribe to the event stream *before* navigation so the Document
        // responseReceived is never missed.
        let mut events = page.subscribe();

        // Cookie hygiene: wipe the context-global jar, then restore the
        // profile's jar. Best-effort hygiene; never fails the visit over a
        // clear failure (a warn is emitted).
        if let Err(e) = page.clear_cookies().await {
            warn!(error = %security::redact_message(&e.to_string(), 200), "failed to clear browser cookie jar");
        }

        if let Some(profile) = &profile {
            match profile
                .to_cookie_inputs(&self.encryption_key, OffsetDateTime::now_utc())
                .await
            {
                Ok(inputs) => {
                    if !inputs.is_empty() {
                        debug!(count = inputs.len(), "restoring cookie jar");
                        if let Err(e) = page.set_cookies(&inputs).await {
                            let msg = security::redact_message(
                                &format!("cookie restore failed: {e}"),
                                security::MAX_ERROR_MESSAGE_LEN,
                            );
                            error!(error = %msg, "failed to restore cookie jar");
                            return self
                                .teardown_and_record(
                                    &handle,
                                    &page,
                                    &target_id,
                                    None, // navigation never happened; do not persist a partial jar
                                    &website,
                                    started_at,
                                    t0,
                                    Outcome::InteractionError,
                                    Some(msg),
                                    None,
                                    None,
                                    browser_pid,
                                )
                                .await;
                        }
                    }
                }
                Err(e) => {
                    let msg = security::redact_message(
                        &format!("cookie jar decrypt failed: {e}"),
                        security::MAX_ERROR_MESSAGE_LEN,
                    );
                    error!(error = %msg, "failed to decrypt cookie jar");
                    return self
                        .teardown_and_record(
                            &handle,
                            &page,
                            &target_id,
                            None,
                            &website,
                            started_at,
                            t0,
                            Outcome::InteractionError,
                            Some(msg),
                            None,
                            None,
                            browser_pid,
                        )
                        .await;
                }
            }
        }

        // 6) Navigate and await load (hard timeout).
        let nav_timeout_s = setting_i64(&self.db, "nav_timeout_s", 15, 1, 300).await;
        let nav_timeout = Duration::from_secs(nav_timeout_s as u64);
        let nav_result = navigate_and_wait(&page, target_url.as_str(), nav_timeout).await;

        // Every branch from here on falls through to jar capture + close +
        // record — no early returns below this line.
        let mut outcome = Outcome::Success;
        let mut error_message: Option<String> = None;
        let mut http_status: Option<i64> = None;
        let mut final_url_raw: Option<String> = None;
        let mut early_termination = false;
        let mut end_session = false;

        match nav_result {
            NavResult::Loaded => {
                // 7) Drain buffered events for the Document response.
                http_status = drain_document_status(&mut events, &session_id);
                final_url_raw = evaluate_href(&page).await;
                info!(http_status, "navigation finished");
            }
            NavResult::Timeout => {
                warn!(nav_timeout_s, "navigation timed out");
                outcome = Outcome::Timeout;
                error_message = Some("navigation timed out".to_string());
                early_termination = true;
            }
            NavResult::Failed(msg) => {
                warn!(error = %msg, "navigation failed");
                outcome = Outcome::NavigationError;
                error_message = Some(msg);
                early_termination = true;
            }
        }

        // Redirect defence: the final URL must pass the same policy.
        //
        // Residual DNS-rebinding risk (documented, accepted): the pre-visit
        // check resolved the host to public addresses at t0; a hostile
        // authoritative server could answer differently at t1. This
        // post-navigation recheck of the *final* URL is the mitigation — an
        // attacker who flips DNS to an internal address gains nothing,
        // because the landed URL is rejected here and the visit aborts with
        // `navigation_error` before any content is recorded or interacted
        // with. TTL-0 rebinding between the two checks remains theoretically
        // possible and is accepted for v1; see SECURITY.md.
        if !early_termination
            && let Some(href) = final_url_raw.as_deref()
            && security::validate_redirect_target(href).await.is_err()
        {
            warn!("final URL violates the URL safety policy; aborting visit");
            outcome = Outcome::NavigationError;
            error_message = Some("redirect target violates URL safety policy".to_string());
            early_termination = true;
        }

        // 8) Session duration: uniform in [min, max], hard-capped once for
        //    the whole visit by max_session_seconds_cap.
        let session_cap_s = setting_i64(&self.db, "max_session_seconds_cap", 300, 0, 3600).await;
        let session_s = pick_session_seconds(
            website.min_session_seconds,
            website.max_session_seconds,
            session_cap_s,
        );
        let visit_deadline = t0 + Duration::from_secs(session_s.max(0) as u64);

        // 9) Interaction sequence, if configured and enabled (and the
        //    navigation did not fail early).
        if !early_termination {
            match self.db.get_interaction_sequence(website.id).await {
                Ok(Some(row)) if row.enabled => {
                    match prepare_sequence(&row, &self.db, session_cap_s, Some(&base_origin)).await
                    {
                        Ok(Some((seq, limits))) => {
                            debug!(
                                actions = seq.actions.len(),
                                on_error = ?seq.on_error,
                                "running interaction sequence"
                            );
                            let exit = run_sequence(&page, &seq, &limits, visit_deadline).await;
                            // The final URL may have moved (a navigate action).
                            if let Some(href) = evaluate_href(&page).await {
                                final_url_raw = Some(href);
                            }
                            match exit {
                                SeqExit::Completed => {}
                                SeqExit::EndSession => end_session = true,
                                SeqExit::Aborted(msg) => {
                                    outcome = Outcome::InteractionError;
                                    error_message = Some(msg);
                                    early_termination = true;
                                }
                                SeqExit::BudgetExceeded => {
                                    outcome = Outcome::InteractionError;
                                    error_message = Some("session budget exceeded".to_string());
                                    early_termination = true;
                                }
                                SeqExit::SecurityAbort(msg) => {
                                    outcome = Outcome::NavigationError;
                                    error_message = Some(msg);
                                    early_termination = true;
                                }
                            }
                        }
                        Ok(None) => { /* empty sequence — basic mode */ }
                        Err(msg) => {
                            outcome = Outcome::InteractionError;
                            error_message = Some(msg);
                            early_termination = true;
                        }
                    }
                }
                Ok(Some(_)) | Ok(None) => { /* disabled / absent — basic mode */ }
                Err(e) => {
                    error!(error = %security::redact_message(&e.to_string(), 200),
                        "failed to load interaction sequence; aborting visit");
                    outcome = Outcome::InteractionError;
                    error_message = Some("failed to load interaction sequence".to_string());
                    early_termination = true;
                }
            }
        }

        // 10) Hold the page open for the remainder of the session window.
        if !early_termination
            && !end_session
            && let Some(remaining) = visit_deadline.checked_duration_since(Instant::now())
            && remaining > Duration::ZERO
        {
            debug!(remaining_s = remaining.as_secs(), "holding session");
            tokio::time::sleep(remaining).await;
        }

        // 11–13) Capture jar → close target → record. Every path lands here.
        self.teardown_and_record(
            &handle,
            &page,
            &target_id,
            profile.as_ref(),
            &website,
            started_at,
            t0,
            outcome,
            error_message,
            http_status,
            final_url_raw.as_deref().map(security::host_path_lossy),
            browser_pid,
        )
        .await
    }

    /// Capture the live jar (profile visits only), persist it encrypted,
    /// wipe the context-global jar, close the target, then record the
    /// visit. The jar capture, jar wipe and target close always happen —
    /// on every exit path.
    #[allow(clippy::too_many_arguments)]
    async fn teardown_and_record(
        &self,
        handle: &CdpHandle,
        page: &PageSession,
        target_id: &str,
        profile: Option<&ProfileSession>,
        website: &Website,
        started_at: OffsetDateTime,
        t0: Instant,
        outcome: Outcome,
        error_message: Option<String>,
        http_status: Option<i64>,
        final_url: Option<String>,
        browser_pid: Option<i64>,
    ) -> VisitOutcome {
        if let Some(profile) = profile {
            Self::persist_live_jar(profile, page, &self.encryption_key).await;
        }
        // Hygiene: wipe the context-global jar for the next visitor.
        if let Err(e) = page.clear_cookies().await {
            debug!(error = %security::redact_message(&e.to_string(), 200), "failed to clear browser cookie jar");
        }
        if let Err(e) = handle.close_target(target_id).await {
            warn!(error = %security::redact_message(&e.to_string(), 200), "failed to close page target");
        }
        self.record_and_finish(
            website,
            started_at,
            t0,
            outcome,
            error_message,
            http_status,
            final_url,
            browser_pid,
        )
        .await
    }

    /// Read the live jar from the browser and replace the stored
    /// (encrypted) jar wholesale. Best-effort: failures are logged, never
    /// propagated — the visit's outcome reflects navigation, not storage.
    async fn persist_live_jar(profile: &ProfileSession, page: &PageSession, encryption_key: &str) {
        let live = match page.get_cookies().await {
            Ok(cookies) => cookies,
            Err(e) => {
                warn!(error = %security::redact_message(&e.to_string(), 200), "failed to read live cookie jar");
                return;
            }
        };
        let inputs: Vec<CookieInput> = live
            .into_iter()
            .map(|c| CookieInput {
                name: c.name,
                value: c.value,
                url: None,
                domain: c.domain,
                path: c.path,
                // CDP uses a negative expiry (-1) for session cookies; the
                // CookieInput/persist contract uses 0.0 for "session cookie".
                // Normalize so session cookies are not swept as "expired".
                expires: if c.expires < 0.0 { 0.0 } else { c.expires },
                http_only: c.http_only,
                secure: c.secure,
                same_site: c.same_site,
            })
            .collect();
        match profile
            .persist_after_visit(encryption_key, OffsetDateTime::now_utc(), inputs)
            .await
        {
            Ok(stats) => debug!(
                jars = stats.jars_written,
                cookies = stats.cookies_written,
                expired_dropped = stats.expired_dropped,
                domainless_dropped = stats.domainless_dropped,
                "cookie jar persisted"
            ),
            Err(e) => {
                warn!(error = %security::redact_message(&format!("persist after visit: {e}"), 200),
                    "failed to persist cookie jar")
            }
        }
    }

    /// Record the visit in `visit_history`, set `websites.last_visit_at`,
    /// and return the outcome for the caller to feed the scheduler.
    #[allow(clippy::too_many_arguments)] // outcome bundle, kept flat for call-site clarity
    async fn record_and_finish(
        &self,
        website: &Website,
        started_at: OffsetDateTime,
        t0: Instant,
        outcome: Outcome,
        error_message: Option<String>,
        http_status: Option<i64>,
        final_url: Option<String>,
        browser_pid: Option<i64>,
    ) -> VisitOutcome {
        let duration = t0.elapsed();
        let memory_usage = self.sample_browser_rss_bytes();
        let error_message =
            error_message.map(|m| security::redact_message(&m, security::MAX_ERROR_MESSAGE_LEN));
        let row = VisitHistoryRow {
            id: 0,
            website_id: website.id,
            profile_id: website.profile_id,
            started_at,
            completed_at: Some(OffsetDateTime::now_utc()),
            duration_ms: Some(duration.as_millis() as i64),
            http_status,
            final_url: final_url.clone(),
            outcome,
            error_message,
            browser_pid,
            memory_usage,
        };
        if let Err(e) = self.db.record_visit(&row).await {
            error!(error = %security::redact_message(&e.to_string(), 200), "failed to record visit_history row");
        }
        if let Err(e) = self
            .db
            .touch_website_last_visit(website.id, OffsetDateTime::now_utc())
            .await
        {
            error!(error = %security::redact_message(&e.to_string(), 200), "failed to set websites.last_visit_at");
        }
        VisitOutcome {
            outcome,
            duration,
            http_status,
            final_url,
            memory_usage,
        }
    }

    /// Post-visit browser RSS in bytes, from the manager's health stats.
    /// `None` when the browser is not running or has never been sampled.
    fn sample_browser_rss_bytes(&self) -> Option<i64> {
        let stats = self.manager.stats();
        (stats.rss_mb > 0.0).then_some((stats.rss_mb * 1024.0 * 1024.0) as i64)
    }
}

// ---------------------------------------------------------------------------
// Free functions — navigation, events, sequences
// ---------------------------------------------------------------------------

async fn setting_i64(db: &Db, key: &str, default: i64, min: i64, max: i64) -> i64 {
    config::typed_i64(db, key)
        .await
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

async fn navigate_and_wait(page: &PageSession, url: &str, timeout: Duration) -> NavResult {
    if let Err(e) = page.navigate(url).await {
        return NavResult::Failed(security::redact_message(
            &format!("navigate command failed: {e}"),
            300,
        ));
    }
    match page.wait_load(timeout).await {
        Ok(()) => NavResult::Loaded,
        Err(CdpError::Timeout) => NavResult::Timeout,
        Err(e) => NavResult::Failed(security::redact_message(
            &format!("navigation failed: {e}"),
            300,
        )),
    }
}

/// Keep the first `type == "Document"` responseReceived for *this* session,
/// draining whatever the bounded subscriber channel already buffered.
fn drain_document_status(rx: &mut mpsc::Receiver<CdpEvent>, session_id: &str) -> Option<i64> {
    loop {
        match rx.try_recv() {
            Ok(ev) => {
                if ev.session_id.as_deref() == Some(session_id)
                    && ev.response_type() == Some("Document")
                    && let Some(status) = ev.response_status()
                {
                    return Some(status);
                }
            }
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                return None;
            }
        }
    }
}

async fn evaluate_href(page: &PageSession) -> Option<String> {
    match page.evaluate("location.href").await {
        Ok(v) => v.as_str().map(str::to_string),
        Err(e) => {
            debug!(error = %security::redact_message(&e.to_string(), 200), "location.href evaluate failed");
            None
        }
    }
}

/// Parse and fail-fast-validate a stored sequence. Returns `Ok(None)` for
/// an empty (basic-mode) sequence, `Err(first_error_message)` for a
/// validation/parse failure — the caller records the FIRST message only.
async fn prepare_sequence(
    row: &InteractionSequenceRow,
    db: &Db,
    session_cap_s: i64,
    base_origin: Option<&Url>,
) -> Result<Option<(InteractionSequence, InteractionLimits)>, String> {
    let seq = parse_sequence_json(&row.configuration_json).map_err(|e| {
        security::redact_message(&format!("interaction sequence is invalid: {e}"), 300)
    })?;
    if seq.actions.is_empty() {
        return Ok(None);
    }
    let limits = build_interaction_limits(db, session_cap_s).await;
    validate_sequence(&seq, &limits, base_origin).map_err(|errors| {
        let first = errors
            .first()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "interaction sequence invalid".to_string());
        security::redact_message(&first, 300)
    })?;
    Ok(Some((seq, limits)))
}

async fn build_interaction_limits(db: &Db, session_cap_s: i64) -> InteractionLimits {
    let max_actions = setting_i64(db, "max_actions_per_sequence", 50, 1, 10_000).await as usize;
    let click_wait = setting_i64(db, "interaction_click_wait_max_ms", 10_000, 0, i64::MAX / 2)
        .await
        .max(0) as u64;
    let scroll_ops = setting_i64(db, "interaction_scroll_max_ops", 20, 1, 10_000).await as u32;
    let total_ms = (session_cap_s.max(0) as u64).saturating_mul(1000);
    InteractionLimits::new(max_actions, click_wait, scroll_ops, total_ms)
}

async fn run_sequence(
    page: &PageSession,
    seq: &InteractionSequence,
    limits: &InteractionLimits,
    deadline: Instant,
) -> SeqExit {
    // The conservative time budget was enforced at validation time; the
    // `deadline` (the visit's selected session duration) enforces the real
    // one at run time.
    let _ = limits;
    for (i, action) in seq.actions.iter().enumerate() {
        if Instant::now() >= deadline {
            warn!(action = i, "session budget exceeded before action");
            return SeqExit::BudgetExceeded;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let per_action = remaining.min(PER_ACTION_TIMEOUT);
        match tokio::time::timeout(per_action, execute_action(page, action, deadline)).await {
            Ok(Ok(ActionFlow::Continue)) => {}
            Ok(Ok(ActionFlow::EndSession)) => {
                debug!("end_session action reached");
                return SeqExit::EndSession;
            }
            Ok(Ok(ActionFlow::RedirectBlocked)) => {
                return SeqExit::SecurityAbort(
                    "redirect target violates URL safety policy".to_string(),
                );
            }
            Ok(Err(msg)) => {
                error!(action = i, error = %msg, "interaction action failed");
                match seq.on_error {
                    OnError::Abort => return SeqExit::Aborted(msg),
                    OnError::Continue => {
                        debug!(action = i, "on_error=continue; skipping action");
                    }
                }
            }
            Err(_elapsed) => {
                let msg = format!("action {i}: timed out");
                error!(action = i, "interaction action timed out");
                match seq.on_error {
                    OnError::Abort => return SeqExit::Aborted(msg),
                    OnError::Continue => {
                        debug!(action = i, "on_error=continue; skipping action");
                    }
                }
            }
        }
    }
    SeqExit::Completed
}

async fn execute_action(
    page: &PageSession,
    action: &Action,
    deadline: Instant,
) -> Result<ActionFlow, String> {
    match action {
        Action::Navigate { url } => {
            // Same-origin was enforced at validation; this re-applies the
            // full SSRF policy defensively (incl. DNS).
            let parsed = security::validate_target(url)
                .await
                .map_err(|e| security::redact_message(&e, 200))?;
            page.navigate(parsed.as_str())
                .await
                .map_err(|e| security::redact_message(&format!("navigate failed: {e}"), 300))?;
            let timeout = DEFAULT_ACTION_TIMEOUT_MS.min(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64,
            );
            page.wait_load(Duration::from_millis(timeout))
                .await
                .map_err(|e| security::redact_message(&format!("wait_load failed: {e}"), 300))?;
            // Redirect re-check for the post-navigate URL.
            if let Some(href) = evaluate_href(page).await
                && security::validate_redirect_target(&href).await.is_err()
            {
                warn!("sequence navigate landed on a blocked address");
                return Ok(ActionFlow::RedirectBlocked);
            }
            Ok(ActionFlow::Continue)
        }
        Action::WaitDuration { ms, jitter_pct } => {
            let wait = jittered_wait_ms(*ms, jitter_pct.unwrap_or(20.0));
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(Duration::from_millis(wait).min(remaining)).await;
            Ok(ActionFlow::Continue)
        }
        Action::WaitSelector {
            selector,
            timeout_ms,
        } => {
            let timeout = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_ACTION_TIMEOUT_MS));
            let timeout = timeout.min(deadline.saturating_duration_since(Instant::now()));
            match page.wait_for_selector(selector, timeout).await {
                Ok(true) => Ok(ActionFlow::Continue),
                Ok(false) => Err("selector wait timed out".to_string()),
                Err(e) => Err(security::redact_message(
                    &format!("wait_selector failed: {e}"),
                    300,
                )),
            }
        }
        Action::WaitJs {
            condition,
            timeout_ms,
        } => {
            let timeout = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_ACTION_TIMEOUT_MS));
            let remaining = deadline.saturating_duration_since(Instant::now());
            let budget = timeout.min(remaining);
            let js_deadline = Instant::now() + budget;
            loop {
                match page.evaluate(condition).await {
                    Ok(v) if js_truthy(&v) => return Ok(ActionFlow::Continue),
                    // Falsy or JS exception (page may still be loading): keep polling.
                    Ok(_) | Err(CdpError::Protocol { .. } | CdpError::Timeout) => {}
                    Err(e) => {
                        return Err(security::redact_message(
                            &format!("wait_js failed: {e}"),
                            300,
                        ));
                    }
                }
                if Instant::now() >= js_deadline {
                    return Err("wait_js condition not met".to_string());
                }
                tokio::time::sleep(WAIT_JS_POLL).await;
            }
        }
        Action::Scroll {
            direction,
            distance_px,
            operations,
            delay_ms,
        } => {
            for op in 0..*operations {
                if Instant::now() >= deadline {
                    break; // budget check; outer loop records BudgetExceeded
                }
                let d = vary_distance(*distance_px, 0.30);
                let (dy, dx) = match direction {
                    ScrollDirection::Vertical => (d as f64, 0.0),
                    ScrollDirection::Horizontal => (0.0, d as f64),
                };
                page.scroll_by(dy, dx, 1, *delay_ms)
                    .await
                    .map_err(|e| security::redact_message(&format!("scroll failed: {e}"), 300))?;
                if op + 1 < *operations {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    tokio::time::sleep(Duration::from_millis(*delay_ms).min(remaining)).await;
                }
            }
            Ok(ActionFlow::Continue)
        }
        Action::Click {
            selector,
            wait_after_ms,
        } => match page.click_element(selector).await {
            Ok(true) => {
                if let Some(ms) = wait_after_ms {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    tokio::time::sleep(Duration::from_millis(*ms).min(remaining)).await;
                }
                Ok(ActionFlow::Continue)
            }
            Ok(false) => Err("click selector matched no element".to_string()),
            Err(e) => Err(security::redact_message(&format!("click failed: {e}"), 300)),
        },
        Action::Rotate { choices } => {
            if choices.is_empty() {
                return Err("rotate has no choices".to_string());
            }
            let idx = rand::random_range(0..choices.len());
            debug!(
                choice_index = idx,
                choice_count = choices.len(),
                "rotate picked choice"
            );
            // Validator guarantees depth 1 (no nested rotate); recursion is
            // still safe if the DB was written out of band.
            Box::pin(execute_action(page, &choices[idx], deadline)).await
        }
        Action::EndSession => Ok(ActionFlow::EndSession),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::BrowserProfile;
    use crate::db::models::MonitoringMode;

    fn sample_website(id: i64, min_session: i64, max_session: i64) -> Website {
        let now = OffsetDateTime::now_utc();
        Website {
            id,
            name: format!("site-{id}"),
            url: format!("https://site-{id}.example.com/"),
            enabled: true,
            profile_id: None,
            monitoring_mode: MonitoringMode::Basic,
            min_interval_seconds: 480,
            max_interval_seconds: 780,
            min_session_seconds: min_session,
            max_session_seconds: max_session,
            last_visit_at: None,
            next_visit_at: None,
            created_at: now,
            updated_at: now,
            active_window_start: None,
            active_window_end: None,
            timezone: None,
        }
    }

    // --- pure helpers ---

    #[test]
    fn session_seconds_fixed_when_min_equals_max() {
        for _ in 0..100 {
            assert_eq!(pick_session_seconds(15, 15, 300), 15);
        }
    }

    #[test]
    fn session_seconds_within_bounds_and_capped() {
        for _ in 0..2_000 {
            let v = pick_session_seconds(5, 60, 300);
            assert!((5..=60).contains(&v), "{v} out of [5, 60]");
            let v = pick_session_seconds(100, 200, 90);
            assert_eq!(v, 90, "hard cap must win even over the lower bound");
            let v = pick_session_seconds(-5, 10, 300);
            assert!((0..=10).contains(&v));
        }
        // min > max (DB corruption) collapses to min, still capped.
        assert_eq!(pick_session_seconds(50, 10, 300), 50);
        assert_eq!(pick_session_seconds(500, 10, 300), 300);
    }

    #[test]
    fn jittered_wait_respects_injected_draw() {
        // 20% jitter on 1000ms → [800, 1200].
        assert_eq!(jittered_wait_ms_with(1000, 20.0, 0.0), 800);
        assert_eq!(jittered_wait_ms_with(1000, 20.0, 0.5), 1000);
        assert!(jittered_wait_ms_with(1000, 20.0, 0.999_999) <= 1200);
        // Zero jitter is exact regardless of the draw.
        assert_eq!(jittered_wait_ms_with(1000, 0.0, 0.0), 1000);
        assert_eq!(jittered_wait_ms_with(1000, 0.0, 0.999_999), 1000);
        // Out-of-range jitter clamps; zero ms never goes negative.
        assert_eq!(jittered_wait_ms_with(1000, 250.0, 0.0), 0);
        assert_eq!(jittered_wait_ms_with(0, 100.0, 0.0), 0);
    }

    #[test]
    fn varied_distance_stays_near_input_and_preserves_sign() {
        for _ in 0..1_000 {
            let v = vary_distance(1000, 0.30);
            assert!((700..=1300).contains(&v), "{v}");
            let neg = vary_distance(-1000, 0.30);
            assert!((-1300..=-700).contains(&neg), "{neg}");
            assert_eq!(vary_distance(0, 0.30), 0);
            assert_ne!(vary_distance(1, 0.30), 0);
        }
    }

    #[test]
    fn js_truthy_matrix() {
        use serde_json::json;
        assert!(!js_truthy(&serde_json::Value::Null));
        assert!(!js_truthy(&json!(false)));
        assert!(js_truthy(&json!(true)));
        assert!(!js_truthy(&json!(0)));
        assert!(!js_truthy(&json!(0.0)));
        assert!(js_truthy(&json!(1)));
        assert!(js_truthy(&json!(-0.5)));
        assert!(!js_truthy(&json!("")));
        assert!(js_truthy(&json!("x")));
        assert!(js_truthy(&json!({})));
        assert!(js_truthy(&json!([])));
        assert!(js_truthy(&json!({"a": 1})));
    }

    #[test]
    fn completion_outcome_is_identity_today() {
        for o in [
            Outcome::Success,
            Outcome::Timeout,
            Outcome::NavigationError,
            Outcome::BrowserCrash,
            Outcome::InteractionError,
        ] {
            assert_eq!(completion_outcome(o), o);
        }
    }

    // --- live tests (require lightpanda + network) ---

    fn lightpanda_available() -> bool {
        let binary = std::env::var("BROWSER_BINARY").unwrap_or_else(|_| "lightpanda".to_string());
        std::process::Command::new(&binary)
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn test_config(encryption_key: &str) -> Arc<Config> {
        Arc::new(Config {
            database_path: std::path::PathBuf::from("./data/test.db"),
            backup_dir: std::path::PathBuf::from("./data/backups"),
            app_password: "test-password-123".to_string(),
            encryption_key: encryption_key.to_string(),
            port: 8080,
            bind_addr: std::net::IpAddr::from([127, 0, 0, 1]),
            tz: "UTC".to_string(),
            log_level: "error".to_string(),
        })
    }

    async fn insert_site(
        db: &Db,
        url: &str,
        min_s: i64,
        max_s: i64,
        profile_id: Option<i64>,
    ) -> i64 {
        let mut site = sample_website(0, min_s, max_s);
        site.url = url.to_string();
        site.profile_id = profile_id;
        db.insert_website(&site).await.expect("insert website")
    }

    #[ignore = "requires lightpanda + network access to example.com; run with --ignored"]
    #[tokio::test]
    async fn execute_against_example_com_records_visit() {
        if !lightpanda_available() {
            eprintln!("lightpanda not found; skipping live test");
            return;
        }
        let key = "live-test-encryption-key-0001";
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, "https://example.com/", 1, 1, None).await;

        let binary = std::env::var("BROWSER_BINARY").unwrap_or_else(|_| "lightpanda".to_string());
        let manager = Arc::new(BrowserManager::launch(db.clone(), &binary, 19231).await);
        manager.spawn_monitoring();

        let executor = Executor::new(
            db.clone(),
            manager.clone(),
            key.to_string(),
            test_config(key),
        );
        let outcome = executor
            .execute(id, ExecutionTrigger::Scheduled)
            .await
            .expect("memory guard allows the visit");
        eprintln!(
            "live visit outcome: {:?} in {:?}",
            outcome.outcome, outcome.duration
        );

        let visits = db.recent_visits(1, Some(id)).await.expect("recent visits");
        assert_eq!(visits.len(), 1);
        let row = &visits[0];
        assert!(matches!(row.outcome, Outcome::Success | Outcome::Timeout));
        assert_eq!(row.website_id, id);
        assert!(row.duration_ms.unwrap_or(0) >= 0);
        if row.outcome == Outcome::Success {
            assert_eq!(row.http_status, Some(200));
            assert_eq!(
                row.final_url.as_deref(),
                Some("https://example.com/"),
                "final_url must be the query-stripped host+path"
            );
        }

        let site = db
            .get_website(id)
            .await
            .expect("get website")
            .expect("site row");
        assert!(site.last_visit_at.is_some(), "last_visit_at must be set");

        manager.shutdown().await.expect("manager shutdown");
    }

    #[ignore = "requires lightpanda + network access to httpbin.org; run with --ignored"]
    #[tokio::test]
    async fn execute_with_profile_persists_cookie_jar() {
        if !lightpanda_available() {
            eprintln!("lightpanda not found; skipping live test");
            return;
        }
        let key = "live-test-encryption-key-0002";
        let db = Db::in_memory().await.expect("db");

        let profile = BrowserProfile {
            id: 0,
            name: "live-test-profile".to_string(),
            description: "seg-10 live cookie round trip".to_string(),
            user_agent: None,
            enabled: true,
            configuration_json: "{}".to_string(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let profile_id = db.create_profile(&profile).await.expect("create profile");
        // httpbin sets session=abc123 then 302s to /cookies.
        let id = insert_site(
            &db,
            "https://httpbin.org/cookies/set?session=abc123",
            1,
            1,
            Some(profile_id),
        )
        .await;

        let binary = std::env::var("BROWSER_BINARY").unwrap_or_else(|_| "lightpanda".to_string());
        let manager = Arc::new(BrowserManager::launch(db.clone(), &binary, 19233).await);
        manager.spawn_monitoring();

        let executor = Executor::new(
            db.clone(),
            manager.clone(),
            key.to_string(),
            test_config(key),
        );
        let outcome = executor
            .execute(id, ExecutionTrigger::Scheduled)
            .await
            .expect("memory guard allows the visit");
        eprintln!("live profile visit outcome: {:?}", outcome.outcome);

        let jars = db.list_cookie_jars(profile_id).await.expect("list jars");
        if outcome.outcome == Outcome::Success {
            assert!(!jars.is_empty(), "cookie jar must have been persisted");
            let live = ProfileSession::load_profile(db.clone(), profile_id)
                .await
                .expect("reload profile")
                .to_cookie_inputs(key, OffsetDateTime::now_utc())
                .await
                .expect("decrypt jar");
            eprintln!(
                "persisted cookies: {:?}",
                live.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
            assert!(
                live.iter()
                    .any(|c| c.name == "session" && c.value == "abc123")
            );
        } else {
            eprintln!("visit did not succeed; jar assertion skipped (network-dependent)");
        }

        manager.shutdown().await.expect("manager shutdown");
    }

    #[ignore = "requires lightpanda + network access; run with --ignored"]
    #[tokio::test]
    async fn manual_trigger_flows_through_channel_and_completion_upserts() {
        if !lightpanda_available() {
            eprintln!("lightpanda not found; skipping live test");
            return;
        }
        let key = "live-test-encryption-key-0003";
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, "https://example.com/", 1, 1, None).await;
        // Not due for a long time: the manual path must be the only emitter.
        let future = OffsetDateTime::now_utc() + time::Duration::hours(6);
        db.upsert_scheduler_state(&crate::db::SchedulerState {
            website_id: id,
            next_visit_at: Some(future),
            last_execution_at: None,
            retry_count: 0,
            job_status: crate::db::JobStatus::Pending,
            lease_expires_at: None,
        })
        .await
        .expect("insert state");

        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::scheduler::VisitJob>(1);
        let sched = crate::scheduler::Scheduler::new(db.clone(), "UTC").start(tx);
        let ack = sched.enqueue_manual(id).await.expect("enqueue manual");
        assert!(matches!(ack, crate::scheduler::EnqueueAck::Queued { .. }));
        let job = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("job emitted")
            .expect("channel open");
        assert_eq!(job.website_id, id);
        assert_eq!(job.trigger, crate::scheduler::Trigger::Manual);

        let binary = std::env::var("BROWSER_BINARY").unwrap_or_else(|_| "lightpanda".to_string());
        let manager = Arc::new(BrowserManager::launch(db.clone(), &binary, 19235).await);
        manager.spawn_monitoring();
        let executor = Executor::new(
            db.clone(),
            manager.clone(),
            key.to_string(),
            test_config(key),
        );
        let outcome = executor
            .execute(job.website_id, ExecutionTrigger::Manual)
            .await
            .expect("memory guard allows the visit");
        eprintln!("manual visit outcome: {:?}", outcome.outcome);
        sched
            .handle_completion(job.website_id, completion_outcome(outcome.outcome))
            .await
            .expect("handle completion");

        let state = db
            .get_scheduler_state(id)
            .await
            .expect("get state")
            .expect("state row");
        assert_eq!(state.job_status, crate::db::JobStatus::Pending);
        assert_eq!(state.retry_count, 0);
        assert!(state.last_execution_at.is_some());
        // Next visit must be rescheduled into the future.
        assert!(state.next_visit_at.expect("next set") > OffsetDateTime::now_utc());

        manager.shutdown().await.expect("manager shutdown");
    }
}
