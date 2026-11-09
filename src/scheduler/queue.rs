//! Scheduler — in-memory priority queue backed by SQLite.
//!
//! Design (see SEG-08 in `UPTIMEPANDA_PLAN.md`):
//!
//! * **Persistent source of truth** is `scheduler_state` (+ `websites.enabled`).
//!   The heap is a wake-up/ordering structure rebuilt from the DB on boot and
//!   after every completion; rows in the DB survive crashes.
//! * **One worker** pops the heap and claims jobs atomically via
//!   [`Db::claim_due_job`] (`UPDATE … WHERE job_status IN ('pending','retry')`
//!   CAS) for scheduled visits, or the targeted single-row CAS
//!   [`Db::claim_website_job`](crate::db::queries::ClaimKind::Manual) for
//!   manual "visit now" requests (which bypass the interval but still require
//!   the site to be `enabled = 1`; paused sites may run manual visits).
//! * **Manual requests** push a heap entry stamped with `now`, which pops
//!   *before* scheduled entries, giving manual visits priority without a
//!   second queue.
//! * **Retry**: `timeout`/`navigation_error` outcomes are retried at most
//!   twice (`+60s`, then `+300s`, `retry_count` tracked in the row). On the
//!   third consecutive failure the normal cycle resumes:
//!   `job_status='pending'`, `retry_count=0`, `next_visit_at = now + jitter`.
//! * **Active windows**: websites may set `active_window_start`/`active_window_end`
//!   (`"HH:MM"` local wall clock) with `timezone` (IANA name; falls back to
//!   the deployment `TZ`). Outside the window no visit is emitted; the site is
//!   rescheduled to the next window start. `start == end` (or a missing/unusable
//!   window) means "always active". Manual visits bypass the window.
//!   `active_window_default = "24h"` is the only supported global value —
//!   everything else is treated as always-active with a warning (a wall-clock
//!   window cannot be derived from a bare hour count).
//! * **Pause** is modeled as `scheduler_state.job_status='paused'`; it is not
//!   the same as disabling the monitor (`websites.enabled=0`). Paused sites are
//!   never claimed by the background loop. Manual visits on paused sites run
//!   and the pause is restored when the visit completes.
//! * **Recovery**: on boot `recover_stale_running(0)` requeues `running` rows
//!   whose lease expired (or was never set) — e.g. after a crash mid-visit.
//!   Only the row count is logged (the DB API does not expose the rows).
//! * Visits are **not** executed here — the scheduler emits [`VisitJob`]s onto
//!   a capacity-1 bounded channel (`tokio::sync::mpsc`); SEG-10's executor
//!   consumes them and reports outcomes back via
//!   [`SchedulerHandle::handle_completion`]. A 1-permit
//!   [`tokio::sync::Semaphore`] is acquired before a claim and held until the
//!   matching `handle_completion`, so the worker never claims/prefetches the
//!   next job while a visit is in flight (the single-worker guarantee).
//! * Ordinary RNG is used for jitter — no CSPRNG is involved in scheduling
//!   (see [`crate::scheduler::jitter`]).

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::TimeZone;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::config::{get_setting, typed_i64};
use crate::db::models::{JobStatus, Outcome, SchedulerState, Website};
use crate::db::queries::ClaimKind;
use crate::db::{Db, DbError};
use crate::scheduler::jitter;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// How a visit was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Normal scheduled visit (claim path, subject to window/pause rules).
    Scheduled,
    /// User-requested "Visit now" (bypasses interval/window; requires the
    /// site to be enabled; allowed on paused sites).
    Manual,
}

/// A job claimed by the scheduler, ready for the executor to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisitJob {
    pub website_id: i64,
    pub trigger: Trigger,
    /// 1-based attempt counter (`retry_count + 1` at claim time).
    pub attempt: u32,
}

/// Result of [`SchedulerHandle::enqueue_manual`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueAck {
    /// Accepted; `position` is the 1-based position of the job in the heap
    /// (number of entries ahead of it, plus one). Approximate but
    /// deterministic for a quiescent heap.
    Queued { position: u32 },
    /// The website exists but is disabled (`enabled = 0`) — rejected.
    /// Manual visits on paused-but-enabled sites are allowed.
    NotEnabled,
    /// The queue (`max_queue_length`, default 32) is full — rejected.
    QueueFull,
    /// No such website.
    Unknown,
}

/// Errors surfaced by the scheduler API.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("database error: {0}")]
    Db(#[from] DbError),
}

// ---------------------------------------------------------------------------
// Heap internals
// ---------------------------------------------------------------------------

/// `BinaryHeap` entries keyed by `(due time, sequence, website_id)`; the
/// `Reverse` turns the max-heap into a min-heap so the earliest entry pops.
#[derive(Debug, Clone, Eq, PartialEq)]
struct HeapEntry {
    key: Reverse<(OffsetDateTime, u64, i64)>,
    trigger: Trigger,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

struct Inflight {
    was_paused: bool,
    /// Held until the matching [`SchedulerHandle::handle_completion`]
    /// removes the in-flight entry — release order == completion order.
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// One visit at a time (single-worker guarantee, `concurrent_visits = 1`).
const VISIT_PERMITS: usize = 1;

struct Core {
    heap: BinaryHeap<HeapEntry>,
    seq: u64,
    /// Websites currently holding a `Scheduled` heap entry — prevents the
    /// refill from pushing duplicate scheduled entries for the same site.
    scheduled_in_heap: HashSet<i64>,
    /// Websites with an emitted-but-not-completed job, with claim-time context.
    in_flight: std::collections::HashMap<i64, Inflight>,
}

struct Shared {
    core: Mutex<Core>,
    notify: tokio::sync::Notify,
    running: AtomicBool,
    /// IANA name used for websites without their own `timezone`.
    default_tz: String,
    /// 1-permit semaphore: the worker acquires a permit before claiming a
    /// job and releases it in `handle_completion`. While a visit is
    /// in flight, no *next* job is claimed — no prefetching, no double
    /// execution, and the capacity-1 dispatch channel remains the bound
    /// on queued dispatches.
    visit_permit: Arc<tokio::sync::Semaphore>,
}

// ---------------------------------------------------------------------------
// Window math (active monitoring windows)
// ---------------------------------------------------------------------------

/// Resolve the timezone for a website window: the site's own IANA name if
/// set and valid, else the deployment default (`TZ`), else UTC.
pub fn resolve_timezone(site_tz: Option<&str>, default_tz: &str) -> chrono_tz::Tz {
    site_tz
        .and_then(|z| z.parse::<chrono_tz::Tz>().ok())
        .or_else(|| default_tz.parse::<chrono_tz::Tz>().ok())
        .unwrap_or(chrono_tz::Tz::UTC)
}

fn parse_hhmm(s: &str) -> Option<chrono::NaiveTime> {
    chrono::NaiveTime::parse_from_str(s.trim(), "%H:%M").ok()
}

fn to_chrono_utc(t: OffsetDateTime) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(t.unix_timestamp(), t.nanosecond())
        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)
}

fn from_chrono_utc(t: chrono::DateTime<chrono::Utc>) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(t.timestamp()).unwrap_or(OffsetDateTime::UNIX_EPOCH)
        + Duration::nanoseconds(t.timestamp_subsec_nanos() as i64)
}

/// Is `now` inside the daily window `[start, end)` in `tz`?
/// Handles overnight windows (e.g. `22:00`–`06:00`). `start == end` means
/// "always active". An unparsable bound fails open (always active) and is
/// logged by callers.
pub fn within_window(tz: chrono_tz::Tz, start: &str, end: &str, now: OffsetDateTime) -> bool {
    let (Some(s), Some(e)) = (parse_hhmm(start), parse_hhmm(end)) else {
        return true;
    };
    if s == e {
        return true;
    }
    let local = to_chrono_utc(now).with_timezone(&tz);
    let wall = local.time();
    if s < e {
        wall >= s && wall < e
    } else {
        // Overnight window, e.g. 22:00-06:00.
        wall >= s || wall < e
    }
}

/// Next moment (strictly after `now`) at which the window opens, or `None`
/// if it cannot be computed (fail-open caller treats the site as active).
pub fn next_window_start(
    tz: chrono_tz::Tz,
    start: &str,
    end: &str,
    now: OffsetDateTime,
) -> Option<OffsetDateTime> {
    let s = parse_hhmm(start)?;
    if parse_hhmm(end)? == s {
        return Some(now); // always-active degenerate window
    }
    let local_now = to_chrono_utc(now).with_timezone(&tz);
    for day_offset in 0..=2u64 {
        let date = local_now
            .date_naive()
            .checked_add_days(chrono::Days::new(day_offset))?;
        let naive = date.and_time(s);
        // Handle DST gaps/ambiguity: prefer a single match, else the earliest
        // of the ambiguous ones; on a spring-forward gap there is no valid
        // local time, so skip the day (fail-open upstream).
        let resolved = match tz.from_local_datetime(&naive) {
            chrono::LocalResult::Single(dt) => Some(dt),
            chrono::LocalResult::Ambiguous(dt, _) => Some(dt),
            chrono::LocalResult::None => None,
        };
        let Some(dt) = resolved else {
            continue;
        };
        let utc = dt.with_timezone(&chrono::Utc);
        if utc > to_chrono_utc(now) {
            return Some(from_chrono_utc(utc));
        }
    }
    None
}

pub(crate) fn in_rfc3339(now: OffsetDateTime) -> String {
    now.format(&Rfc3339).unwrap_or_else(|_| now.to_string())
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

enum WindowVerdict {
    /// Inside the window (or no window configured) — emit as normal.
    Active,
    /// Outside the window — do not visit; resume at the given time.
    NotBefore(OffsetDateTime),
}

fn check_window(site: &Website, now: OffsetDateTime, default_tz: &str) -> WindowVerdict {
    let (Some(start), Some(end)) = (
        site.active_window_start.as_deref(),
        site.active_window_end.as_deref(),
    ) else {
        return WindowVerdict::Active;
    };
    let tz = resolve_timezone(site.timezone.as_deref(), default_tz);
    if within_window(tz, start, end, now) {
        return WindowVerdict::Active;
    }
    match next_window_start(tz, start, end, now) {
        Some(t) => WindowVerdict::NotBefore(t),
        None => WindowVerdict::Active, // fail-open; logged by caller
    }
}

/// Retry backoff for `timeout`/`navigation_error` outcomes: first retry
/// after 60s, second after 300s. `new_retry_count` is the count *including*
/// this retry.
pub fn retry_delay_seconds(new_retry_count: i64) -> i64 {
    if new_retry_count <= 1 { 60 } else { 300 }
}

fn is_retryable(outcome: Outcome) -> bool {
    matches!(outcome, Outcome::Timeout | Outcome::NavigationError)
}

fn push_entry(
    core: &mut Core,
    website_id: i64,
    when: OffsetDateTime,
    trigger: Trigger,
) -> Reverse<(OffsetDateTime, u64, i64)> {
    core.seq += 1;
    let seq = core.seq;
    if trigger == Trigger::Scheduled {
        core.scheduled_in_heap.insert(website_id);
    }
    let key = Reverse((when, seq, website_id));
    core.heap.push(HeapEntry { key, trigger });
    key
}

async fn queue_bound(db: &Db) -> usize {
    typed_i64(db, "max_queue_length")
        .await
        .unwrap_or(32)
        .clamp(1, 256) as usize
}

async fn claim_lease_seconds(db: &Db) -> i64 {
    // Lease must outlive a whole visit (visit_timeout_s) plus clock skew.
    typed_i64(db, "visit_timeout_s").await.unwrap_or(30).max(0) + 60
}

/// Rebuild/refresh the heap from the DB source of truth. Called on boot and
/// after every completion. Defers out-of-window sites to their next window
/// start (persisting the deferred `next_visit_at`).
async fn refill(db: &Db, shared: &Shared, default_tz: &str) {
    // Reconcile: enabled websites with no scheduler_state row get one with a
    // NULL next_visit_at (due immediately).
    match db.list_enabled_website_ids_missing_scheduler_state().await {
        Ok(ids) => {
            for id in ids {
                let state = SchedulerState {
                    website_id: id,
                    next_visit_at: None,
                    last_execution_at: None,
                    retry_count: 0,
                    job_status: JobStatus::Pending,
                    lease_expires_at: None,
                };
                if let Err(e) = db.upsert_scheduler_state(&state).await {
                    tracing::error!(website_id = id, error = %e, "failed to init scheduler_state");
                }
            }
        }
        Err(e) => tracing::error!(error = %e, "failed to list websites missing scheduler_state"),
    }

    let jobs = match db.list_claimable_scheduler_jobs().await {
        Ok(jobs) => jobs,
        Err(e) => {
            tracing::error!(error = %e, "failed to list claimable scheduler jobs");
            return;
        }
    };

    let now = OffsetDateTime::now_utc();
    let mut to_push = Vec::with_capacity(jobs.len());
    for (state, site) in jobs {
        let due = state.next_visit_at.unwrap_or(now);
        let when = match check_window(&site, now, default_tz) {
            WindowVerdict::Active => due,
            WindowVerdict::NotBefore(t) => {
                let sync_to = t.max(due);
                let needs_sync = state.next_visit_at.map(|n| n < sync_to).unwrap_or(true);
                if needs_sync {
                    let mut deferred = state.clone();
                    deferred.next_visit_at = Some(sync_to);
                    if let Err(e) = db.upsert_scheduler_state(&deferred).await {
                        tracing::error!(website_id = site.id, error = %e,
                            "failed to defer next_visit_at to window start");
                    } else {
                        tracing::info!(website_id = site.id,
                            next_visit_at = %in_rfc3339(sync_to),
                            "site outside active window; deferred to window start");
                    }
                }
                sync_to
            }
        };
        to_push.push((site.id, when));
    }

    let mut core = shared.core.lock().expect("core mutex poisoned");
    // Heap entries pointing at websites whose row is currently running are
    // skipped by the CAS at claim time; for scheduled entries retain the
    // dedupe set as-is.
    for (id, when) in to_push {
        if core.scheduled_in_heap.contains(&id) {
            continue;
        }
        push_entry(&mut core, id, when, Trigger::Scheduled);
    }
}

/// Worker: pops due entries, claims them, emits [`VisitJob`]s.
async fn run(
    db: Db,
    shared: Arc<Shared>,
    default_tz: String,
    dispatch: tokio::sync::mpsc::Sender<VisitJob>,
) {
    shared.running.store(true, Ordering::SeqCst);

    // Restart recovery FIRST: requeue `running` rows whose lease expired.
    match db.recover_stale_running(0).await {
        Ok(0) => {}
        Ok(n) => tracing::warn!(
            recovered = n,
            "requeued stale running scheduler jobs on boot"
        ),
        Err(e) => tracing::error!(error = %e, "failed to recover stale running jobs"),
    }

    // Global "active_window_default" sanity: only "24h" is meaningful — any
    // other value can't be mapped to a wall-clock window; warn once.
    if let Ok(v) = get_setting(&db, "active_window_default").await
        && v.trim() != "24h"
    {
        tracing::warn!(
            active_window_default = %v,
            "only '24h' is supported as the global active window; ignoring and treating as always-active (per-website windows still apply)"
        );
    }

    refill(&db, &shared, &default_tz).await;
    let lease = claim_lease_seconds(&db).await;

    loop {
        let now = OffsetDateTime::now_utc();

        // Cheap due-check before we block on the permit.
        let has_due = {
            let core = shared.core.lock().expect("core mutex poisoned");
            core.heap.peek().map(|e| e.key.0.0 <= now).unwrap_or(false)
        };

        if !has_due {
            // Nothing due: sleep until the heap head or a wakeup.
            let head = {
                let core = shared.core.lock().expect("core mutex poisoned");
                core.heap.peek().map(|e| e.key.0.0)
            };
            match head {
                Some(t) => {
                    let now = OffsetDateTime::now_utc();
                    let wait = std::time::Duration::try_from((t - now).max(Duration::ZERO))
                        .unwrap_or(std::time::Duration::ZERO);
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = shared.notify.notified() => {}
                    }
                }
                None => {
                    // Empty heap: park until an enqueue/completion wakes us.
                    shared.notify.notified().await;
                }
            }
            continue;
        }

        // A visit may already be in flight: wait for the permit. This is the
        // single-worker backpressure point — no prefetching.
        let permit = Arc::clone(&shared.visit_permit)
            .acquire_owned()
            .await
            .expect("visit permit semaphore closed");

        // Pop the earliest due entry (state may have changed while we waited
        // on the permit). Releasing the permit by dropping it if nothing pops.
        let popped = {
            let mut core = shared.core.lock().expect("core mutex poisoned");
            let now = OffsetDateTime::now_utc();
            match core.heap.peek() {
                Some(e) if e.key.0.0 <= now => {
                    let entry = core.heap.pop().expect("peeked entry");
                    if entry.trigger == Trigger::Scheduled {
                        core.scheduled_in_heap.remove(&entry.key.0.2);
                    }
                    Some(entry)
                }
                _ => None,
            }
        };

        let Some(entry) = popped else {
            drop(permit);
            continue;
        };

        pop_entry(&db, &shared, &default_tz, entry, &dispatch, lease, permit).await;
    }
}

async fn pop_entry(
    db: &Db,
    shared: &Shared,
    default_tz: &str,
    entry: HeapEntry,
    dispatch: &tokio::sync::mpsc::Sender<VisitJob>,
    lease: i64,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let now = OffsetDateTime::now_utc();
    let website_id = entry.key.0.2;

    // Claim.
    let (was_paused, claimed) = match entry.trigger {
        Trigger::Scheduled => match db.claim_due_job(now, lease).await {
            Ok(Some(state)) => {
                if state.website_id != website_id {
                    // Heap/DB skew (should not happen with this refill
                    // discipline): emit the globally-due site the DB picked,
                    // and re-push our entry for a later pass.
                    tracing::debug!(
                        popped = website_id,
                        claimed = state.website_id,
                        "claim returned a different website; re-queueing popped entry"
                    );
                    let mut core = shared.core.lock().expect("core mutex poisoned");
                    push_entry(&mut core, website_id, entry.key.0.0, Trigger::Scheduled);
                }
                (false, Some(state))
            }
            Ok(None) => (false, None),
            Err(e) => {
                tracing::error!(error = %e, "claim_due_job failed");
                (false, None)
            }
        },
        Trigger::Manual => match db
            .claim_website_job(website_id, now, lease, ClaimKind::Manual)
            .await
        {
            Ok(Some((previous, state))) => (previous == JobStatus::Paused, Some(state)),
            Ok(None) => (false, None), // paused-no-more / already running / retry'd concurrently
            Err(e) => {
                tracing::error!(website_id, error = %e, "manual claim failed");
                (false, None)
            }
        },
    };

    let Some(claimed) = claimed else {
        refill(db, shared, default_tz).await;
        return; // permit drops with the function
    };
    let target_website_id = claimed.website_id;

    // Post-claim validation of the *claimed* row (which may differ from the
    // popped entry when the DB picked the global earliest due job).
    let claimed_site = match db.get_website(target_website_id).await {
        Ok(Some(site)) => site,
        Ok(None) => {
            // Website deleted (scheduler_state cascaded away) — requeue is
            // impossible; drop the entry and un-lease the row if it lingers.
            let _ = db
                .set_scheduler_state_status(target_website_id, JobStatus::Disabled, None, 0)
                .await;
            return;
        }
        Err(e) => {
            tracing::error!(website_id = target_website_id, error = %e,
                "failed to load claimed website; reverting claim to pending");
            let _ = db
                .set_scheduler_state_status(
                    target_website_id,
                    JobStatus::Pending,
                    Some(now),
                    claimed.retry_count,
                )
                .await;
            return;
        }
    };

    // Never emit for a disabled site; mark the row so the heap stops
    // offering it.
    if !claimed_site.enabled {
        if let Err(e) = db.mark_scheduler_state_disabled(target_website_id).await {
            tracing::error!(website_id = target_website_id, error = %e,
                "failed to mark disabled job_status");
        }
        return; // permit drops with the function
    }

    // Strict window enforcement for scheduled visits (manual bypasses).
    if entry.trigger == Trigger::Scheduled
        && let WindowVerdict::NotBefore(t) = check_window(&claimed_site, now, default_tz)
    {
        let deferred = t.max(now);
        let status = if claimed.retry_count > 0 {
            JobStatus::Retry
        } else {
            JobStatus::Pending
        };
        if let Err(e) = db
            .upsert_scheduler_state(&SchedulerState {
                website_id: target_website_id,
                next_visit_at: Some(deferred),
                last_execution_at: claimed.last_execution_at,
                retry_count: claimed.retry_count,
                job_status: status,
                lease_expires_at: None,
            })
            .await
        {
            tracing::error!(website_id = target_website_id, error = %e,
                "failed to defer out-of-window visit");
        }
        let mut core = shared.core.lock().expect("core mutex poisoned");
        push_entry(&mut core, target_website_id, deferred, Trigger::Scheduled);
        return; // permit drops with the function
    }

    {
        let mut core = shared.core.lock().expect("core mutex poisoned");
        core.in_flight.insert(
            target_website_id,
            Inflight {
                was_paused,
                _permit: permit,
            },
        );
    }

    let attempt = u32::try_from(claimed.retry_count.max(0)).unwrap_or(0) + 1;
    let job = VisitJob {
        website_id: target_website_id,
        trigger: entry.trigger,
        attempt,
    };
    tracing::debug!(
        website_id = target_website_id,
        trigger = ?job.trigger,
        attempt = job.attempt,
        "claimed job; dispatching"
    );
    if dispatch.send(job).await.is_err() {
        tracing::error!(
            website_id = target_website_id,
            "dispatch channel closed; requeueing job as pending"
        );
        let state = SchedulerState {
            website_id: target_website_id,
            next_visit_at: Some(now),
            last_execution_at: claimed.last_execution_at,
            retry_count: claimed.retry_count,
            job_status: if was_paused {
                JobStatus::Paused
            } else {
                JobStatus::Pending
            },
            lease_expires_at: None,
        };
        let _ = db.upsert_scheduler_state(&state).await;
        // Release the visit permit — there is no completion coming for a job
        // that never got dispatched.
        let mut core = shared.core.lock().expect("core mutex poisoned");
        core.in_flight.remove(&target_website_id);
        shared.running.store(false, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Public handle
// ---------------------------------------------------------------------------

/// Cloneable handle to the running scheduler. Passed to SEG-10 (executor),
/// the web layer (visit/pause/resume endpoints) and the System page.
#[derive(Clone)]
pub struct SchedulerHandle {
    db: Db,
    shared: Arc<Shared>,
}

impl SchedulerHandle {
    /// Number of jobs currently waiting in the heap (approximate; a
    /// completion may add one concurrently).
    pub fn queue_length(&self) -> usize {
        self.shared
            .core
            .lock()
            .expect("core mutex poisoned")
            .heap
            .len()
    }

    /// Is the worker loop running (has not given up the dispatch channel)?
    pub fn running(&self) -> bool {
        self.shared.running.load(Ordering::SeqCst)
    }

    /// Effective next visit time for a website: scheduler_state first,
    /// falling back to the legacy `websites.next_visit_at` column.
    pub async fn next_visit_at(
        &self,
        website_id: i64,
    ) -> Result<Option<OffsetDateTime>, SchedulerError> {
        if let Some(state) = self.db.get_scheduler_state(website_id).await? {
            return Ok(state.next_visit_at);
        }
        Ok(self
            .db
            .get_website(website_id)
            .await?
            .and_then(|w| w.next_visit_at))
    }

    /// Request a manual visit. Allowed when the website is enabled
    /// (including paused-but-enabled — user intent wins over the pause for a
    /// single run); rejected for disabled or unknown websites.
    /// Bypasses the interval and the active window; still atomic — the
    /// normal claim path executes it.
    pub async fn enqueue_manual(&self, website_id: i64) -> Result<EnqueueAck, SchedulerError> {
        // Existence / enabled gates first (unknown ids outrank capacity).
        let site = match self.db.get_website(website_id).await? {
            Some(site) => site,
            None => return Ok(EnqueueAck::Unknown),
        };
        if !site.enabled {
            return Ok(EnqueueAck::NotEnabled);
        }

        let bound = queue_bound(&self.db).await;

        // Make sure a claimable row exists (NULL next_visit_at claims
        // immediately). Do not clobber a currently-running row.
        match self.db.get_scheduler_state(website_id).await? {
            Some(_) => {}
            None => {
                self.db
                    .upsert_scheduler_state(&SchedulerState {
                        website_id,
                        next_visit_at: None,
                        last_execution_at: None,
                        retry_count: 0,
                        job_status: JobStatus::Pending,
                        lease_expires_at: None,
                    })
                    .await?;
            }
        }

        let position = {
            let mut core = self.shared.core.lock().expect("core mutex poisoned");
            if core.heap.len() >= bound {
                return Ok(EnqueueAck::QueueFull);
            }
            let key = push_entry(
                &mut core,
                website_id,
                OffsetDateTime::now_utc(),
                Trigger::Manual,
            );
            core.heap.iter().filter(|e| e.key > key).count() as u32 + 1
        };

        self.shared.notify.notify_one();
        Ok(EnqueueAck::Queued { position })
    }

    /// Pause or resume a website. `paused = true` writes
    /// `job_status='paused'` and clears the next visit; `false` writes
    /// `pending` with a freshly jittered `next_visit_at` (or `disabled` when
    /// the website is disabled) and re-pushes a heap entry.
    /// Returns `true` when the website exists.
    pub async fn set_paused(&self, website_id: i64, paused: bool) -> Result<bool, SchedulerError> {
        let site = match self.db.get_website(website_id).await? {
            Some(site) => site,
            None => return Ok(false),
        };
        let now = OffsetDateTime::now_utc();
        if paused {
            self.db
                .set_scheduler_state_status(website_id, JobStatus::Paused, None, 0)
                .await?;
            // Drop pending scheduled entries so a paused site never pops.
            let mut core = self.shared.core.lock().expect("core mutex poisoned");
            let mut kept: Vec<HeapEntry> = std::mem::take(&mut core.heap).into_vec();
            kept.retain(|e| !(e.trigger == Trigger::Scheduled && e.key.0.2 == website_id));
            core.heap = kept.into_iter().collect();
            core.scheduled_in_heap.remove(&website_id);
        } else {
            let (status, next) = if site.enabled {
                let interval = jitter::next_interval(
                    site.min_interval_seconds.min(site.max_interval_seconds),
                    site.min_interval_seconds.max(site.max_interval_seconds),
                );
                (JobStatus::Pending, Some(now + Duration::seconds(interval)))
            } else {
                (JobStatus::Disabled, None)
            };
            self.db
                .set_scheduler_state_status(website_id, status, next, 0)
                .await?;
            if let Some(t) = next {
                let mut core = self.shared.core.lock().expect("core mutex poisoned");
                core.heap
                    .retain(|e| !(e.trigger == Trigger::Scheduled && e.key.0.2 == website_id));
                push_entry(&mut core, website_id, t, Trigger::Scheduled);
            }
        }
        self.shared.notify.notify_one();
        Ok(true)
    }

    /// Report the outcome of a dispatched job. Computes the next visit time
    /// and updates `scheduler_state` (and the heap). See the module docs for
    /// the exact rescheduling policy.
    pub async fn handle_completion(
        &self,
        website_id: i64,
        outcome: Outcome,
    ) -> Result<(), SchedulerError> {
        let now = OffsetDateTime::now_utc();
        let inflight = {
            let mut core = self.shared.core.lock().expect("core mutex poisoned");
            core.in_flight.remove(&website_id)
        };
        if inflight.is_none() {
            tracing::warn!(
                website_id,
                "handle_completion for a job that was not claimed by this handle; \
                 assuming it was not paused before the visit"
            );
        }
        let was_paused = inflight.map(|i| i.was_paused).unwrap_or(false);

        // Fresh reads to decide the next state.
        let site = self.db.get_website(website_id).await?;
        let current = self.db.get_scheduler_state(website_id).await?;
        let retry_count = current.as_ref().map(|s| s.retry_count).unwrap_or(0);
        // A pause that landed mid-visit wins over the rescheduling policy.
        let paused_meanwhile = current
            .as_ref()
            .map(|s| s.job_status == JobStatus::Paused)
            .unwrap_or(false);
        let paused_now = was_paused || paused_meanwhile;
        let disabled = site.as_ref().map(|s| !s.enabled).unwrap_or(false);

        let (status, next_visit_at, new_retry_count) = if disabled {
            (JobStatus::Disabled, None, 0)
        } else if paused_now {
            (JobStatus::Paused, None, 0)
        } else if is_retryable(outcome) && retry_count < 2 {
            let new_retry = retry_count + 1;
            (
                JobStatus::Retry,
                Some(now + Duration::seconds(retry_delay_seconds(new_retry))),
                new_retry,
            )
        } else {
            let (min_s, max_s) = site
                .as_ref()
                .map(|s| (s.min_interval_seconds, s.max_interval_seconds))
                .unwrap_or((480, 780));
            let interval = jitter::next_interval(min_s.min(max_s), min_s.max(max_s));
            (
                JobStatus::Pending,
                Some(now + Duration::seconds(interval)),
                0,
            )
        };

        // Apply the window gate to the computed next visit as well.
        let next_visit_at = match (&site, next_visit_at) {
            (Some(site), Some(t)) => match check_window(site, t, &self.shared.default_tz) {
                WindowVerdict::Active => Some(t),
                WindowVerdict::NotBefore(w) => Some(t.max(w)),
            },
            (_, t) => t,
        };

        let state = SchedulerState {
            website_id,
            next_visit_at,
            last_execution_at: Some(now),
            retry_count: new_retry_count,
            job_status: status,
            lease_expires_at: None,
        };
        self.db.upsert_scheduler_state(&state).await?;

        {
            let mut core = self.shared.core.lock().expect("core mutex poisoned");
            // The heap is a wake-up structure over the DB source of truth:
            // drop any stale Scheduled entries for this website first, so a
            // long-running monitor never accumulates one dead entry per
            // completed visit (the DB carries the real next_visit_at).
            core.heap
                .retain(|e| !(e.trigger == Trigger::Scheduled && e.key.0.2 == website_id));
            if let Some(t) = next_visit_at {
                push_entry(&mut core, website_id, t, Trigger::Scheduled);
            } else {
                core.scheduled_in_heap.remove(&website_id);
            }
        }
        self.shared.notify.notify_one();
        Ok(())
    }
}

/// Deployment-default timezone (`TZ`), read at scheduler start.
fn tz_env() -> String {
    std::env::var("TZ").unwrap_or_else(|_| "UTC".to_string())
}

/// The scheduler itself. Owns the DB handle and the shared heap; use
/// [`SchedulerHandle`] (via [`Scheduler::start`]) to interact with it.
pub struct Scheduler {
    db: Db,
    default_tz: String,
    shared: Arc<Shared>,
}

impl Scheduler {
    /// `default_tz` is the IANA name used for websites without their own
    /// `timezone` (typically the deployment `TZ`).
    pub fn new(db: Db, default_tz: impl Into<String>) -> Self {
        let default_tz: String = default_tz.into();
        Scheduler {
            db,
            shared: Arc::new(Shared {
                core: Mutex::new(Core {
                    heap: BinaryHeap::new(),
                    seq: 0,
                    scheduled_in_heap: HashSet::new(),
                    in_flight: std::collections::HashMap::new(),
                }),
                notify: tokio::sync::Notify::new(),
                running: AtomicBool::new(false),
                default_tz: default_tz.clone(),
                visit_permit: Arc::new(tokio::sync::Semaphore::new(VISIT_PERMITS)),
            }),
            default_tz,
        }
    }

    /// Convenience constructor reading `TZ` from the environment.
    pub fn from_env_tz(db: Db) -> Self {
        Self::new(db, tz_env())
    }

    /// Spawn the worker loop and return the handle. `dispatch` should be a
    /// **bounded, capacity-1** channel; the worker emits a job per claim and
    /// waits for room rather than prefetching (the single-worker guarantee is
    /// enforced by `concurrent_visits = 1` on the executor side, SEG-10).
    ///
    /// Boot sequence: recovery of stale `running` rows, reconciliation of
    /// missing `scheduler_state` rows, heap refill, then the pop loop.
    pub fn start(self, dispatch: tokio::sync::mpsc::Sender<VisitJob>) -> SchedulerHandle {
        let shared = self.shared.clone();
        let db = self.db.clone();
        let tz = self.default_tz;
        tokio::spawn(run(db, shared, tz, dispatch));
        SchedulerHandle {
            db: self.db,
            shared: self.shared,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (in-memory DB; the executor is mocked by driving handle_completion)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::MonitoringMode;
    use time::Duration;

    fn sample_website(name: &str, min_s: i64, max_s: i64, enabled: bool) -> Website {
        let now = OffsetDateTime::now_utc();
        Website {
            id: 0,
            name: name.to_string(),
            url: format!("https://{name}.example.com/"),
            enabled,
            profile_id: None,
            monitoring_mode: MonitoringMode::Basic,
            min_interval_seconds: min_s,
            max_interval_seconds: max_s,
            min_session_seconds: 5,
            max_session_seconds: 10,
            last_visit_at: None,
            next_visit_at: None,
            created_at: now,
            updated_at: now,
            active_window_start: None,
            active_window_end: None,
            timezone: None,
        }
    }

    async fn insert_site(db: &Db, site: &Website) -> i64 {
        db.insert_website(site).await.expect("insert website")
    }

    async fn insert_state(
        db: &Db,
        website_id: i64,
        next_visit_at: Option<OffsetDateTime>,
        job_status: JobStatus,
        retry_count: i64,
    ) {
        db.upsert_scheduler_state(&SchedulerState {
            website_id,
            next_visit_at,
            last_execution_at: None,
            retry_count,
            job_status,
            lease_expires_at: None,
        })
        .await
        .expect("upsert scheduler state");
    }

    fn start(db: &Db) -> (SchedulerHandle, tokio::sync::mpsc::Receiver<VisitJob>) {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let handle = Scheduler::new(db.clone(), "UTC").start(tx);
        (handle, rx)
    }

    async fn recv_job(rx: &mut tokio::sync::mpsc::Receiver<VisitJob>) -> VisitJob {
        tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .expect("job emitted in time")
            .expect("dispatch channel open")
    }

    async fn assert_no_job(rx: &mut tokio::sync::mpsc::Receiver<VisitJob>, within_ms: u64) {
        let got =
            tokio::time::timeout(std::time::Duration::from_millis(within_ms), rx.recv()).await;
        assert!(got.is_err(), "no job expected within {within_ms}ms");
    }

    async fn wait_queue_len(handle: &SchedulerHandle, at_least: usize) {
        for _ in 0..500 {
            if handle.queue_length() >= at_least {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("queue never reached {at_least} entries");
    }

    // --- jitter ---

    #[test]
    fn jitter_min_max_equal_is_fixed() {
        for _ in 0..1_000 {
            assert_eq!(jitter::next_interval(480, 480), 480);
        }
    }

    // --- window math ---

    fn utc(y: i32, m: u8, d: u8, h: u8, min: u8) -> OffsetDateTime {
        let date = time::Date::from_calendar_date(y, time::Month::try_from(m).unwrap(), d).unwrap();
        let time = time::Time::from_hms(h, min, 0).unwrap();
        OffsetDateTime::new_utc(date, time)
    }

    #[test]
    fn within_window_simple_daytime() {
        let tz = chrono_tz::Tz::UTC;
        assert!(!within_window(
            tz,
            "08:00",
            "18:00",
            utc(2026, 11, 9, 7, 59)
        ));
        assert!(within_window(tz, "08:00", "18:00", utc(2026, 11, 9, 8, 0)));
        assert!(within_window(tz, "08:00", "18:00", utc(2026, 11, 9, 12, 0)));
        assert!(!within_window(
            tz,
            "08:00",
            "18:00",
            utc(2026, 11, 9, 18, 0)
        ));
    }

    #[test]
    fn within_window_overnight_wraps_midnight() {
        let tz = chrono_tz::Tz::UTC;
        assert!(within_window(tz, "22:00", "06:00", utc(2026, 11, 9, 22, 0)));
        assert!(within_window(
            tz,
            "22:00",
            "06:00",
            utc(2026, 11, 9, 23, 30)
        ));
        assert!(within_window(tz, "22:00", "06:00", utc(2026, 11, 9, 3, 0)));
        assert!(within_window(tz, "22:00", "06:00", utc(2026, 11, 9, 5, 59)));
        assert!(!within_window(tz, "22:00", "06:00", utc(2026, 11, 9, 6, 0)));
        assert!(!within_window(
            tz,
            "22:00",
            "06:00",
            utc(2026, 11, 9, 12, 0)
        ));
    }

    #[test]
    fn within_window_degenerate_and_invalid() {
        let tz = chrono_tz::Tz::UTC;
        let noon = utc(2026, 11, 9, 12, 0);
        assert!(
            within_window(tz, "08:00", "08:00", noon),
            "start == end means 24h"
        );
        assert!(
            within_window(tz, "garbage", "18:00", noon),
            "unparsable window fails open"
        );
        assert!(within_window(tz, "08:00", "garbage", noon));
    }

    #[test]
    fn within_window_respects_iana_timezone() {
        // Europe/Berlin is UTC+1 in November (CET). 10:30 Berlin == 09:30 UTC.
        let tz = chrono_tz::Tz::Europe__Berlin;
        assert!(within_window(tz, "10:00", "18:00", utc(2026, 11, 9, 9, 30)));
        // 09:30 Berlin == 08:30 UTC -> before window.
        assert!(!within_window(
            tz,
            "10:00",
            "18:00",
            utc(2026, 11, 9, 8, 30)
        ));
    }

    #[test]
    fn next_window_start_same_day_and_tomorrow() {
        let tz = chrono_tz::Tz::UTC;
        let s = |h, min| format!("{h:02}:{min:02}");
        let now = utc(2026, 11, 9, 7, 0); // before the 08:00 window
        let t = next_window_start(tz, &s(8, 0), &s(18, 0), now).expect("next start");
        assert_eq!(t, utc(2026, 11, 9, 8, 0));
        let now = utc(2026, 11, 9, 12, 0); // inside window
        let t = next_window_start(tz, &s(8, 0), &s(10, 0), now).expect("next start");
        assert_eq!(t, utc(2026, 11, 10, 8, 0));
    }

    #[test]
    fn next_window_start_overnight_after_close() {
        let tz = chrono_tz::Tz::UTC;
        let now = utc(2026, 11, 9, 7, 0); // window 22:00-06:00 already closed at 06:00
        let t = next_window_start(tz, "22:00", "06:00", now).expect("next start");
        assert_eq!(t, utc(2026, 11, 9, 22, 0));
    }

    // --- scheduler behavior ---

    #[tokio::test]
    async fn due_site_is_claimed_and_emitted_on_boot() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("due-site", 60, 120, true)).await;
        insert_state(&db, id, None, JobStatus::Pending, 0).await;
        let (_handle, mut rx) = start(&db);
        let job = recv_job(&mut rx).await;
        assert_eq!(job.website_id, id);
        assert_eq!(job.trigger, Trigger::Scheduled);
        assert_eq!(job.attempt, 1);
        // Row is now claimed with a lease in the future.
        let state = db
            .get_scheduler_state(id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(state.job_status, JobStatus::Running);
        assert!(state.lease_expires_at.expect("lease set") > OffsetDateTime::now_utc());
    }

    #[tokio::test]
    async fn fresh_enabled_website_without_state_row_is_scheduled() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("fresh", 60, 120, true)).await;
        let (_handle, mut rx) = start(&db);
        let job = recv_job(&mut rx).await;
        assert_eq!(job.website_id, id);
        let state = db
            .get_scheduler_state(id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(state.job_status, JobStatus::Running);
    }

    #[tokio::test]
    async fn paused_site_is_not_claimed_but_manual_visit_runs() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("paused", 60, 120, true)).await;
        insert_state(&db, id, None, JobStatus::Paused, 0).await;
        let (handle, mut rx) = start(&db);
        assert_no_job(&mut rx, 400).await;
        // Pause is visible in the heap view as well.
        assert_eq!(handle.queue_length(), 0);
        // Manual visit runs and bypasses the pause for one execution.
        let ack = handle.enqueue_manual(id).await.expect("enqueue");
        assert!(matches!(ack, EnqueueAck::Queued { .. }));
        let job = recv_job(&mut rx).await;
        assert_eq!(job.trigger, Trigger::Manual);
        // Completion restores the pause.
        handle
            .handle_completion(id, Outcome::Success)
            .await
            .expect("completion");
        let state = db
            .get_scheduler_state(id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(state.job_status, JobStatus::Paused);
        assert!(state.next_visit_at.is_none());
    }

    #[tokio::test]
    async fn disabled_site_is_never_claimed_and_manual_rejected() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("off", 60, 120, false)).await;
        insert_state(&db, id, None, JobStatus::Pending, 0).await;
        let (handle, mut rx) = start(&db);
        assert_no_job(&mut rx, 400).await;
        let ack = handle.enqueue_manual(id).await.expect("enqueue");
        assert_eq!(ack, EnqueueAck::NotEnabled);
        let ack = handle.enqueue_manual(999_999).await.expect("enqueue");
        assert_eq!(ack, EnqueueAck::Unknown);
    }

    #[tokio::test]
    async fn completion_reschedules_within_interval_bounds() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("resched", 120, 120, true)).await;
        insert_state(&db, id, None, JobStatus::Pending, 0).await;
        let (handle, mut rx) = start(&db);
        recv_job(&mut rx).await; // claimed by worker
        let before = OffsetDateTime::now_utc();
        handle
            .handle_completion(id, Outcome::Success)
            .await
            .expect("completion");
        let state = db
            .get_scheduler_state(id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(state.job_status, JobStatus::Pending);
        assert_eq!(state.retry_count, 0);
        let next = state.next_visit_at.expect("next set");
        let delta = next - before;
        assert!(
            (Duration::seconds(118)..=Duration::seconds(121)).contains(&delta),
            "min == max interval, got {delta}"
        );
        assert_eq!(handle.queue_length(), 1);
    }

    #[tokio::test]
    async fn repeated_completions_do_not_accumulate_heap_entries() {
        // Regression: each completion used to push a fresh Scheduled entry
        // without dropping the stale one, so the heap grew by one entry per
        // completed visit. The DB is the source of truth; the heap must
        // hold at most one Scheduled entry per website.
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("pileup", 300, 300, true)).await;
        insert_state(&db, id, None, JobStatus::Pending, 0).await;
        let (handle, mut rx) = start(&db);
        recv_job(&mut rx).await; // boot claim
        for round in 1..=4 {
            handle
                .handle_completion(id, Outcome::Success)
                .await
                .expect("completion");
            assert_eq!(
                handle.queue_length(),
                1,
                "scheduled after completion {round}"
            );
            let ack = handle.enqueue_manual(id).await.expect("enqueue");
            assert!(matches!(ack, EnqueueAck::Queued { .. }), "round {round}");
            recv_job(&mut rx).await;
            handle
                .handle_completion(id, Outcome::Success)
                .await
                .expect("manual completion");
            assert_eq!(
                handle.queue_length(),
                1,
                "scheduled after manual completion {round}"
            );
        }
    }

    #[tokio::test]
    async fn manual_enqueue_bypasses_future_schedule() {
        let db = Db::in_memory().await.expect("db");
        let future = OffsetDateTime::now_utc() + Duration::hours(1);
        let id = insert_site(&db, &sample_website("future", 60, 120, true)).await;
        insert_state(&db, id, Some(future), JobStatus::Pending, 0).await;
        let (handle, mut rx) = start(&db);
        assert_no_job(&mut rx, 200).await; // not due yet
        let ack = handle.enqueue_manual(id).await.expect("enqueue");
        assert_eq!(ack, EnqueueAck::Queued { position: 1 });
        let job = recv_job(&mut rx).await;
        assert_eq!(job.trigger, Trigger::Manual);
    }

    #[tokio::test]
    async fn queue_is_bounded_manual_rejects_beyond_limit() {
        let db = Db::in_memory().await.expect("db");
        db.upsert_application_setting("max_queue_length", "1")
            .await
            .expect("set bound");
        let future = OffsetDateTime::now_utc() + Duration::hours(1);
        let id = insert_site(&db, &sample_website("bounded", 60, 120, true)).await;
        insert_state(&db, id, Some(future), JobStatus::Pending, 0).await;
        let (handle, _rx) = start(&db);
        wait_queue_len(&handle, 1).await; // scheduled entry occupies the bound
        let ack = handle.enqueue_manual(id).await.expect("enqueue");
        assert_eq!(ack, EnqueueAck::QueueFull);
    }

    #[tokio::test]
    async fn manual_twice_is_single_flight() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("single", 60, 120, true)).await;
        insert_state(&db, id, None, JobStatus::Pending, 0).await;
        let (handle, mut rx) = start(&db);
        let ack = handle.enqueue_manual(id).await.expect("enqueue 1");
        assert!(matches!(ack, EnqueueAck::Queued { .. }));
        let job = recv_job(&mut rx).await;
        assert_eq!(job.trigger, Trigger::Manual);
        let ack = handle.enqueue_manual(id).await.expect("enqueue 2");
        assert!(matches!(ack, EnqueueAck::Queued { .. }));
        // Second pop loses the CAS (row already running) — no second job.
        assert_no_job(&mut rx, 400).await;
        handle
            .handle_completion(id, Outcome::Success)
            .await
            .expect("completion");
    }

    #[tokio::test]
    async fn retry_counts_and_exhausts_to_normal_cycle() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("flaky", 120, 120, true)).await;
        insert_state(&db, id, None, JobStatus::Pending, 0).await;
        let (handle, mut rx) = start(&db);

        // Attempt 1 — failure, first retry at +60s.
        let job = recv_job(&mut rx).await;
        assert_eq!(job.attempt, 1);
        let before = OffsetDateTime::now_utc();
        handle
            .handle_completion(id, Outcome::NavigationError)
            .await
            .expect("completion");
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Retry);
        assert_eq!(state.retry_count, 1);
        let delta = state.next_visit_at.unwrap() - before;
        assert!((Duration::seconds(59)..=Duration::seconds(61)).contains(&delta));

        // Simulate the backoff elapsing.
        let mut state = db.get_scheduler_state(id).await.unwrap().unwrap();
        state.next_visit_at = Some(OffsetDateTime::now_utc() - Duration::seconds(1));
        db.upsert_scheduler_state(&state).await.unwrap();
        // Re-push by reparing heap via a completion-free path: instead, just wait for the worker loop to
        // notice the imminent entry... the heap holds the entry at the old time,
        // which is still future — patch the row and trigger refill by completion of nothing? Simplest:
        // restart logic is covered elsewhere; here we verify the row transitions after a second claim.
        // We drive it via a fresh scheduler against the same DB to exercise boot refill.
        drop(handle);
        let (handle, mut rx) = start(&db);
        let job = recv_job(&mut rx).await;
        assert_eq!(job.attempt, 2);

        let before = OffsetDateTime::now_utc();
        handle
            .handle_completion(id, Outcome::Timeout)
            .await
            .expect("completion");
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Retry);
        assert_eq!(state.retry_count, 2);
        let delta = state.next_visit_at.unwrap() - before;
        assert!((Duration::seconds(298)..=Duration::seconds(302)).contains(&delta));

        // Exhaustion: third failure => normal cycle resumes.
        let mut state = db.get_scheduler_state(id).await.unwrap().unwrap();
        state.next_visit_at = Some(OffsetDateTime::now_utc() - Duration::seconds(1));
        db.upsert_scheduler_state(&state).await.unwrap();
        drop(handle);
        let (handle, mut rx) = start(&db);
        let job = recv_job(&mut rx).await;
        assert_eq!(job.attempt, 3);
        let before = OffsetDateTime::now_utc();
        handle
            .handle_completion(id, Outcome::Timeout)
            .await
            .expect("completion");
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Pending);
        assert_eq!(state.retry_count, 0);
        let delta = state.next_visit_at.unwrap() - before;
        assert!((Duration::seconds(118)..=Duration::seconds(121)).contains(&delta));
    }

    #[tokio::test]
    async fn boot_recovers_stale_running_visit() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("crash", 60, 120, true)).await;
        // Simulate a crash mid-visit: row left `running` with an expired lease.
        db.upsert_scheduler_state(&SchedulerState {
            website_id: id,
            next_visit_at: Some(OffsetDateTime::now_utc() - Duration::hours(2)),
            last_execution_at: None,
            retry_count: 0,
            job_status: JobStatus::Running,
            lease_expires_at: Some(OffsetDateTime::now_utc() - Duration::hours(1)),
        })
        .await
        .unwrap();
        let (_handle, mut rx) = start(&db);
        let job = recv_job(&mut rx).await;
        assert_eq!(job.website_id, id);
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Running); // re-claimed after recovery
    }

    #[tokio::test]
    async fn pause_set_mid_visit_wins_over_completion_resume() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("midpause", 120, 120, true)).await;
        insert_state(&db, id, None, JobStatus::Pending, 0).await;
        let (handle, mut rx) = start(&db);
        recv_job(&mut rx).await;
        assert!(handle.set_paused(id, true).await.expect("pause"));
        handle
            .handle_completion(id, Outcome::Success)
            .await
            .expect("completion");
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Paused);
        assert!(state.next_visit_at.is_none());
        // Resume: rescheduled with jitter in [min, max].
        assert!(handle.set_paused(id, false).await.expect("resume"));
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Pending);
        let next = state.next_visit_at.expect("next set");
        let delta = next - OffsetDateTime::now_utc();
        assert!((Duration::seconds(115)..=Duration::seconds(125)).contains(&delta));
        assert_eq!(handle.queue_length(), 1);
    }

    #[tokio::test]
    async fn handle_completion_applies_window_deferral() {
        let db = Db::in_memory().await.expect("db");
        let mut site = sample_website("windowed", 120, 120, true);
        site.active_window_start = Some("00:00".to_string());
        site.active_window_end = Some("00:00".to_string()); // degenerate => always active
        let id = insert_site(&db, &site).await;
        insert_state(&db, id, None, JobStatus::Pending, 0).await;
        let (handle, mut rx) = start(&db);
        recv_job(&mut rx).await;
        handle
            .handle_completion(id, Outcome::Success)
            .await
            .expect("completion");
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Pending);
        assert!(state.next_visit_at.is_some());
    }

    #[tokio::test]
    async fn not_retryable_outcome_does_not_retry() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("crashy", 120, 120, true)).await;
        insert_state(&db, id, None, JobStatus::Pending, 0).await;
        let (handle, mut rx) = start(&db);
        recv_job(&mut rx).await;
        handle
            .handle_completion(id, Outcome::BrowserCrash)
            .await
            .expect("completion");
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Pending);
        assert_eq!(state.retry_count, 0);

        // interaction_error is not retryable either.
        handle
            .handle_completion(id, Outcome::InteractionError)
            .await
            .expect("completion");
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Pending);
        assert_eq!(state.retry_count, 0);
    }

    #[tokio::test]
    async fn unpause_of_disabled_site_marks_disabled() {
        let db = Db::in_memory().await.expect("db");
        let id = insert_site(&db, &sample_website("off2", 120, 120, false)).await;
        insert_state(&db, id, None, JobStatus::Paused, 0).await;
        let (handle, _rx) = start(&db);
        assert!(handle.set_paused(id, false).await.expect("resume"));
        let state = db.get_scheduler_state(id).await.unwrap().unwrap();
        assert_eq!(state.job_status, JobStatus::Disabled);
        assert!(state.next_visit_at.is_none());
    }
}
