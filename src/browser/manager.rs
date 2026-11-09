#![allow(dead_code)]
// Consumed by SEG-08 (scheduler), SEG-10 (executor), SEG-15/16 (system page).
// Until then only the unit tests exercise most of this API.

//! Lightpanda process manager — persistent browser process with controlled
//! recycling.
//!
//! ## Recycle policy (locked)
//! Recycle **only** when RSS exceeds `memory_restart_mb` (default 200 MB) or
//! the process exited unexpectedly (crash). No max-uptime limit, no
//! visit-count limit. Recycle sequence:
//!
//! 1. acquire [`visit_gate`](BrowserManager::visit_gate) with a timeout of
//!    `visit_timeout_s + 30` (oldest in-flight visit wins that race) — an
//!    over-long visit is killed anyway and recorded as a failed visit by the
//!    executor,
//! 2. SIGTERM to the browser child → wait up to `browser_restart_timeout_s`
//!    (default 15) → SIGKILL fallback,
//! 3. `browser_respawn_delay_s` pause,
//! 4. respawn on the next free port (bounded scan of 10 ports), wait for
//!    `/json/version` (HTTP 200) + one real CDP connect,
//! 5. `browser_events` rows: `restarting` (before the kill) and
//!    `restarted` (after the respawn), plus `crash_loop` when the
//!    crash-loop protection trips.
//!
//! ## Visit-gate contract (SEG-10 MUST honor)
//! Any task that navigates the shared browser (the executor) **must** hold
//! `manager.visit_gate().lock().await` for the entire duration of the visit
//! (from `ensure_running` to target close). While a visit holds the gate,
//! `recycle()` waits for it (capped at `visit_timeout_s + 30`s); after the
//! cap it kills the browser anyway. If a visit does *not* hold the gate, the
//! browser may be SIGTERM'd mid-visit: the CDP connection dies, the visit
//! fails with `Disconnected`, and the job is requeued by SEG-08/10.
//!
//! ## Crash-loop protection
//! Recycles with reason `Crash` or `Memory` are counted in a 60 s sliding
//! window ([`RecycleWindow`]). At 5 recycles inside the window the manager
//! transitions to `Down { reason: "crash-loop" }` and does **not** respawn.
//! Manual (`force_restart`, `reason = manual`) and shutdown recycles do not
//! count toward the window. Recovery from `Down` is manual:
//! `manager.force_restart()` (the System page "Restart browser" button in
//! SEG-16 calls this).
//!
//! ## Design notes
//! * CDP connections are **not** kept by the manager. Every visit opens a
//!   fresh connection; this avoids cross-task session bleed and keeps the
//!   connection-per-worker model. The only persistent state is the process,
//!   port, pid and health metadata.
//! * `recycle()` is re-entrancy-guarded (`recycle_in_progress`); concurrent
//!   callers get [`BrowserError::AlreadyRecycling`].
//! * All `/proc/<pid>/*` reads happen on tokio's blocking fs; parse failures
//!   are logged at debug and the sample is skipped. A vanished process is
//!   detected via `try_wait` instead.
//! * Time uses `time::OffsetDateTime` (the codebase-wide timestamp type); the
//!   plan's `DateTime<Utc>` sketch is mapped to the same concept.
//! * RSS ⇄ MB conversions use `kB / 1024.0` (i.e. MiB), consistent with how
//!   the settings and the Phase 0 measurements quote browser memory.
//! * `%cpu` is expressed as a fraction of **one core** (`100` = one saturated
//!   core): `Δticks / sysconf(CLK_TCK) / Δwall × 100` with `CLK_TCK = 100`
//!   (the constant on Linux/x86_64; not exposed to safe Rust without libc).
//! * The readiness probe uses a raw HTTP/1.0 `GET /json/version` over
//!   `tokio::net::TcpStream` (no HTTP client dependency). After HTTP 200 it
//!   performs exactly one `ws://127.0.0.1:<port>/` CDP connect to prove the
//!   websocket path end to end; that connection is intentionally never closed
//!   by us — its reader task ends when the child exits (at most 1 of
//!   Lightpanda's 16 `max_browser_connections` per spawn).
//! * Stdout/stderr of the child are inherited. Lightpanda's own log lines are
//!   useful on container stdout and pipe-buffer deadlock is impossible when
//!   nothing is piped.

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::db::Db;

/// Default CDP port for Lightpanda.
pub const DEFAULT_BASE_PORT: u16 = 9222;
/// The ONLY host the Lightpanda CDP server is allowed to bind. Loopback,
/// hard-coded, never read from the environment or CLI: `BROWSER_BINARY`
/// swaps the binary, `LIGHTPANDA_CDP_PORT` swaps the port, and there is
/// deliberately no host override path. Asserted at startup (see main.rs)
/// and by the unit tests in this module.
pub(crate) const CDP_HOST: &str = "127.0.0.1";

/// Exact argument vector for `<binary> serve ...` — the loopback binding
/// factored out so it is unit-testable in isolation.
pub(crate) fn serve_args(port: u16) -> Vec<String> {
    vec![
        "serve".to_string(),
        "--host".to_string(),
        CDP_HOST.to_string(),
        "--port".to_string(),
        port.to_string(),
        "--log-level".to_string(),
        "info".to_string(),
    ]
}

/// Startup self-check (called from main.rs before any spawn): the CDP
/// server must be pinned to the loopback interface.
pub fn cdp_binds_loopback() -> bool {
    let args = serve_args(DEFAULT_BASE_PORT);
    args.windows(2)
        .any(|w| w[0] == "--host" && w[1] == CDP_HOST)
        && CDP_HOST == "127.0.0.1"
        && CDP_HOST
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback())
}
/// Port scan window: `base ..= base + PORT_SCAN` (i.e. up to 11 candidates).
const PORT_SCAN: u16 = 10;
/// How long to wait for `/json/version` after spawn.
const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// Readiness poll cadence.
const READY_POLL: Duration = Duration::from_millis(100);
/// Cap for the `visit_gate` wait inside `recycle()`: `visit_timeout_s + 30`.
const GATE_WAIT_SLACK_S: i64 = 30;
/// Minimum interval between two `health_warn` events.
const HEALTH_WARN_MIN_INTERVAL: Duration = Duration::from_secs(300);
/// Sliding window for crash-loop detection.
const RECYCLE_WINDOW: Duration = Duration::from_secs(60);
/// Recycles inside [`RECYCLE_WINDOW`] that trip the crash-loop protection.
const CRASH_LOOP_MAX_RECYCLES: usize = 5;
/// Cap on the stored recycle timestamps (allocation bound).
const RECYCLE_HISTORY_CAP: usize = 8;
/// `sysconf(_SC_CLK_TCK)` on Linux/x86_64; used for CPU% conversion.
const CLK_TCK: f64 = 100.0;

/// Why a recycle was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecycleReason {
    /// RSS exceeded `memory_restart_mb`.
    Memory,
    /// The child exited unexpectedly.
    Crash,
    /// Explicit (System page "Restart browser", `force_restart`).
    Manual,
    /// Application shutdown.
    Shutdown,
}

impl RecycleReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Crash => "crash",
            Self::Manual => "manual",
            Self::Shutdown => "shutdown",
        }
    }
}

impl fmt::Display for RecycleReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of the browser process.
#[derive(Debug, Clone)]
pub enum BrowserState {
    Running,
    Restarting,
    /// Manually or automatically left down. Carries a reason; recovery is
    /// `force_restart()`.
    Down {
        reason: String,
    },
    Stopping,
}

/// Process-manager error.
#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("browser is unavailable: {0}")]
    BrowserUnavailable(String),

    #[error("a browser recycle is already in progress")]
    AlreadyRecycling,

    #[error("crash-loop protection tripped after repeated fast recycles; browser left down")]
    CrashLoop,

    #[error("browser did not become ready in time")]
    NotReady,

    #[error("no free CDP port found in the scan window")]
    NoPortAvailable,

    #[error("browser is stopping")]
    ShuttingDown,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Db(#[from] crate::db::DbError),
}

/// Snapshot of browser health, refreshed every poll interval. Consumed by
/// `/api/system` (SEG-15/16). Reading is cheap and never blocks the health
/// loop (a dedicated short-lived mutex).
#[derive(Debug, Clone)]
pub struct BrowserStats {
    pub running: bool,
    pub pid: Option<u32>,
    pub port: u16,
    /// Resident set size in MB (kB / 1024).
    pub rss_mb: f64,
    /// % of one core since the previous sample (100 = one saturated core).
    pub cpu_pct: f64,
    pub uptime_s: u64,
    pub restarts_total: u64,
    /// The `memory_restart_mb` threshold in effect at the last sample.
    pub mem_threshold_mb: i64,
}

impl Default for BrowserStats {
    fn default() -> Self {
        Self {
            running: false,
            pid: None,
            port: 0,
            rss_mb: 0.0,
            cpu_pct: 0.0,
            uptime_s: 0,
            restarts_total: 0,
            mem_threshold_mb: 200,
        }
    }
}

/// One `/proc/<pid>/stat` CPU sample.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CpuSample {
    /// utime + stime in clock ticks.
    pub(crate) ticks: u64,
    pub(crate) at: Instant,
}

/// Previous /proc sample kept across polls for delta computation.
struct ManagerInner {
    child: Option<Child>,
    cdp_port: u16,
    pid: Option<u32>,
    started_at: OffsetDateTime,
    restarts_total: u64,
    state: BrowserState,
    recycle_in_progress: bool,
    prev_cpu: Option<CpuSample>,
    last_health_warn: Option<Instant>,
    recycle_history: Vec<Instant>,
}

/// Cloneable work surface for the manager and the health task. Everything is
/// behind `Arc` internally, so cloning is a handful of refcount bumps.
#[derive(Clone)]
struct Core {
    inner: Arc<Mutex<ManagerInner>>,
    db: Db,
    stats: Arc<StdMutex<BrowserStats>>,
    visit_gate: Arc<Mutex<()>>,
    /// Serializes the spawn+ready-wait path so concurrent `ensure_running` /
    /// `recycle` callers can never end up with two browsers, one orphaned.
    spawn_lock: Arc<Mutex<()>>,
    binary: String,
    base_port: u16,
}

/// Persistent Lightpanda process manager. See module docs for the full
/// contract.
pub struct BrowserManager {
    core: Core,
    health_task: StdMutex<Option<JoinHandle<()>>>,
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested)
// ---------------------------------------------------------------------------

/// Parse `VmRSS` from `/proc/<pid>/status` content. Returns kB.
pub(crate) fn parse_vm_rss_kb(status: &str) -> Option<u64> {
    for line in status.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb_str = rest.trim().strip_suffix("kB")?.trim();
            return kb_str.parse::<u64>().ok();
        }
    }
    None
}

/// Parse utime + stime (clock ticks) from `/proc/<pid>/stat` content.
///
/// Field 2 (`comm`) may contain spaces and parentheses, so the parse starts
/// after the **last** `)`; the remaining tokens are fields 3.. with field
/// indices 1-based, i.e. utime (field 14) is index 11 and stime is index 12.
pub(crate) fn parse_stat_cpu_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 1..)?.trim();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

/// CPU% of one core between two samples. First sample (no `prev`) → 0.0.
pub(crate) fn cpu_pct_between(prev: Option<&CpuSample>, ticks: u64, now: Instant) -> f64 {
    match prev {
        None => 0.0,
        Some(p) => {
            let delta_ticks = ticks.saturating_sub(p.ticks) as f64;
            let secs = now.saturating_duration_since(p.at).as_secs_f64();
            if secs <= f64::EPSILON {
                return 0.0;
            }
            (delta_ticks / CLK_TCK) / secs * 100.0
        }
    }
}

/// Pure warn decision for `memory_warn_mb`.
pub(crate) fn should_warn(rss_mb: f64, warn_mb: i64) -> bool {
    warn_mb >= 0 && rss_mb > warn_mb as f64
}

/// Pure recycle decision for `memory_restart_mb`.
pub(crate) fn should_restart(rss_mb: f64, restart_mb: i64) -> bool {
    restart_mb >= 0 && rss_mb > restart_mb as f64
}

/// Rate limiter for `health_warn`: true when no sample recorded yet, or at
/// least `min_interval` elapsed since the last one.
pub(crate) fn warn_due(last: Option<Instant>, now: Instant, min_interval: Duration) -> bool {
    match last {
        None => true,
        Some(t) => now.saturating_duration_since(t) >= min_interval,
    }
}

/// Sliding-window crash-loop counter. Pushes `now`, prunes older entries and
/// reports whether the window now holds at least `max_in_window` recycles.
pub(crate) fn recycle_window_push(
    times: &mut Vec<Instant>,
    now: Instant,
    window: Duration,
    max_in_window: usize,
) -> bool {
    times.retain(|t| now.saturating_duration_since(*t) < window);
    times.push(now);
    if times.len() > RECYCLE_HISTORY_CAP {
        times.drain(..times.len() - RECYCLE_HISTORY_CAP);
    }
    times.len() >= max_in_window
}

// ---------------------------------------------------------------------------
// Process spawn helpers
// ---------------------------------------------------------------------------

/// First bindable port in `from..=scan_end`, or `None`. This is a pure
/// “is someone home?” check; the spawn-exit path in [`spawn_browser`] is the
/// backstop for the inevitable race between this check and the spawn.
async fn first_free_port_in(from: u16, scan_end: u16) -> Option<u16> {
    for port in from..=scan_end {
        if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.is_ok() {
            return Some(port);
        }
    }
    None
}

/// Minimal raw-HTTP probe: `GET /json/version`, expect HTTP 200. No HTTP
/// client dependency (reqwest is not and must not become one).
async fn probe_json_version(port: u16) -> bool {
    let probe = async {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.ok()?;
        stream.set_nodelay(true).ok()?;
        stream
            .write_all(
                b"GET /json/version HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .ok()?;
        let mut buf = Vec::with_capacity(512);
        // Lightpanda answers this endpoint with a small body; 4 KiB is plenty.
        AsyncReadExt::take(&mut stream, 4096)
            .read_to_end(&mut buf)
            .await
            .ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    };
    match tokio::time::timeout(Duration::from_millis(700), probe).await {
        Ok(Some(response)) => response.starts_with("HTTP/1.") && response.contains(" 200"),
        _ => false,
    }
}

/// Why a readiness wait failed.
#[derive(Debug)]
enum WaitReadyError {
    /// The child exited before the deadline (bind conflict or instant crash).
    ExitedEarly,
    /// The deadline passed with the child still alive.
    TimedOut,
}

/// Poll `/json/version` until HTTP 200, then verify with one real CDP
/// connection. Returns the child once verified.
async fn wait_ready(child: &mut Child, port: u16, timeout: Duration) -> Result<(), WaitReadyError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(_status)) = child.try_wait() {
            return Err(WaitReadyError::ExitedEarly);
        }
        if probe_json_version(port).await {
            // Single real connect as end-to-end verification. The connection
            // stays open until the child exits; we hold no handle.
            let url = format!("ws://127.0.0.1:{port}/");
            match crate::browser::cdp::connect(&url).await {
                Ok(_cdp) => return Ok(()),
                Err(e) => {
                    debug!(error = %e, port, "ready: http 200 but cdp connect failed; retrying")
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(WaitReadyError::TimedOut);
        }
        tokio::time::sleep(READY_POLL).await;
    }
}

/// Spawn the browser on the first free port at or after `base_port`.
///
/// Strategy: pre-check each candidate with a bind probe to skip busy ports,
/// then spawn; if the child exits during the readiness wait (bind conflict
/// race, or instant crash), try the next port. A total `READY_TIMEOUT`
/// expiry is **not** retried (the binary works on other ports, it is simply
/// not ready — retrying would burn time, not fix anything).
///
/// Returns `(child, port, pid)`.
async fn spawn_browser(base_port: u16, binary: &str) -> Result<(Child, u16, u32), BrowserError> {
    let scan_end = base_port.saturating_add(PORT_SCAN);
    let mut port = first_free_port_in(base_port, scan_end)
        .await
        .ok_or(BrowserError::NoPortAvailable)?;

    loop {
        let mut cmd = Command::new(binary);
        cmd.args(serve_args(port))
            .env("LIGHTPANDA_DISABLE_TELEMETRY", "true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());
        // tokio `Child` reaps on `wait()` / `try_wait()`; no `kill_on_drop` —
        // shutdown sequences do explicit signalling.

        let mut child = cmd.spawn()?;
        match wait_ready(&mut child, port, READY_TIMEOUT).await {
            Ok(()) => {
                let pid = child.id().unwrap_or(0);
                return Ok((child, port, pid));
            }
            Err(WaitReadyError::ExitedEarly) => {
                warn!(
                    port,
                    binary, "browser exited before becoming ready; trying next port"
                );
                match first_free_port_in(port.saturating_add(1), scan_end).await {
                    Some(next) => {
                        port = next;
                        continue;
                    }
                    None => {
                        return Err(BrowserError::BrowserUnavailable(
                            "browser exited before ready on every candidate port \
                             (binary missing/crashing or all ports busy)"
                                .to_string(),
                        ));
                    }
                }
            }
            Err(WaitReadyError::TimedOut) => {
                warn!(
                    port,
                    "browser did not become ready within {READY_TIMEOUT:?}; killing"
                );
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(BrowserError::NotReady);
            }
        }
    }
}

/// Read `/proc/<pid>/status` + `/proc/<pid>/stat`. Returns `(rss_mb, cpu_ticks)`.
async fn sample_proc(pid: u32) -> Option<(f64, u64)> {
    let status = tokio::fs::read_to_string(format!("/proc/{pid}/status"))
        .await
        .ok()?;
    let stat = tokio::fs::read_to_string(format!("/proc/{pid}/stat"))
        .await
        .ok()?;
    let rss_kb = parse_vm_rss_kb(&status)?;
    let ticks = parse_stat_cpu_ticks(&stat)?;
    Some((rss_kb as f64 / 1024.0, ticks))
}

// ---------------------------------------------------------------------------
// Core: spawn/store, stats, recycle
// ---------------------------------------------------------------------------

/// What a spawn is for — decides the event written afterwards.
#[derive(Debug, Clone, Copy)]
enum SpawnPurpose {
    /// Initial spawn (boot / first `ensure_running`). Not a recycle.
    Boot,
    /// Respawn after a recycle. Counts toward `restarts_total`.
    Respawn,
}

impl Core {
    fn restarts_total_now(&self) -> u64 {
        // Best-effort; used for event detail strings only.
        self.inner.try_lock().map(|g| g.restarts_total).unwrap_or(0)
    }

    fn write_stats(&self, sample: BrowserStats) {
        let mut slot = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        *slot = sample;
    }

    fn snapshot_stats(
        &self,
        running: bool,
        inner: &ManagerInner,
        rss_mb: f64,
        cpu_pct: f64,
        mem_threshold_mb: i64,
    ) -> BrowserStats {
        BrowserStats {
            running,
            pid: inner.pid,
            port: inner.cdp_port,
            rss_mb,
            cpu_pct,
            uptime_s: (OffsetDateTime::now_utc() - inner.started_at)
                .whole_seconds()
                .max(0) as u64,
            restarts_total: inner.restarts_total,
            mem_threshold_mb,
        }
    }

    /// Spawn + store + event. Serialized by `spawn_lock` — callers
    /// (`ensure_running` / `recycle`) hold it across the spawn.
    async fn spawn_and_store(&self, purpose: SpawnPurpose) -> Result<u16, BrowserError> {
        let (child, port, pid) = spawn_browser(self.base_port, &self.binary).await?;
        let (rss_mb, cpu_ticks) = sample_proc(pid).await.unwrap_or((0.0, 0));
        let rss_bytes = (rss_mb * 1024.0 * 1024.0) as i64;
        let mem_threshold = crate::config::typed_i64(&self.db, "memory_restart_mb")
            .await
            .unwrap_or(200);
        let now = OffsetDateTime::now_utc();

        let mut inner = self.inner.lock().await;
        inner.child = Some(child);
        inner.cdp_port = port;
        inner.pid = Some(pid);
        inner.started_at = now;
        inner.prev_cpu = Some(CpuSample {
            ticks: cpu_ticks,
            at: Instant::now(),
        });
        inner.state = BrowserState::Running;
        if matches!(purpose, SpawnPurpose::Respawn) {
            inner.restarts_total += 1;
        }
        let restarts_total = inner.restarts_total;
        let sample = self.snapshot_stats(true, &inner, rss_mb, 0.0, mem_threshold);
        drop(inner);
        self.write_stats(sample);

        match purpose {
            SpawnPurpose::Boot => {
                info!(pid, port, "lightpanda spawned");
                if let Err(e) = self
                    .db
                    .insert_browser_event(
                        "started",
                        Some(rss_bytes),
                        Some(&format!("pid={pid} port={port}")),
                    )
                    .await
                {
                    warn!(error = %e, "failed to record browser_events(started)");
                }
            }
            SpawnPurpose::Respawn => {
                info!(pid, port, restarts_total, "lightpanda respawned");
            }
        }
        Ok(port)
    }

    /// Graceful stop: SIGTERM → wait `browser_restart_timeout_s` → SIGKILL →
    /// wait. The child is taken out of `inner` by the caller path.
    async fn terminate_child(&self, child: Child) {
        let mut child = child;
        let pid = child.id().unwrap_or(0);
        let pid_i32 = pid as i32;

        // SAFETY: `pid` is the direct child we spawned this session (or the
        // child we just took out of `inner`). `kill(pid, SIGTERM)` carries no
        // pointers and cannot corrupt memory; it merely asks the browser to
        // shut down, which Phase 0 verified it honors in <100 ms. A pid that
        // is no longer ours yields ESRCH/EPERM — logged, not fatal.
        let ret = unsafe { libc::kill(pid_i32, libc::SIGTERM) };
        if ret != 0 {
            warn!(pid, error = %std::io::Error::last_os_error(), "SIGTERM to browser failed");
        }

        let restart_timeout = crate::config::typed_i64(&self.db, "browser_restart_timeout_s")
            .await
            .unwrap_or(15)
            .clamp(1, 120) as u64;
        match tokio::time::timeout(Duration::from_secs(restart_timeout), child.wait()).await {
            Ok(Ok(status)) => info!(pid, %status, "browser exited after SIGTERM"),
            Ok(Err(e)) => warn!(pid, error = %e, "error waiting for browser exit"),
            Err(_) => {
                warn!(
                    pid,
                    restart_timeout, "browser did not exit after SIGTERM; sending SIGKILL"
                );
                // tokio `Child::start_kill` sends SIGKILL on unix; `wait` reaps.
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
    }

    /// Core recycle. `force` skips the Down/`CrashLoop` guards (used by
    /// `force_restart`). All recycles pass through the sliding-window counter;
    /// only `Memory`/`Crash` ones are *limited* by it.
    async fn recycle(&self, reason: RecycleReason, force: bool) -> Result<(), BrowserError> {
        // Phase 1 — guards + state transition under one short lock.
        let old_pid;
        {
            let mut inner = self.inner.lock().await;
            if inner.recycle_in_progress {
                return Err(BrowserError::AlreadyRecycling);
            }
            match &inner.state {
                BrowserState::Stopping => return Err(BrowserError::ShuttingDown),
                BrowserState::Down { reason } if !force => {
                    return Err(BrowserError::BrowserUnavailable(reason.clone()));
                }
                BrowserState::Restarting => return Err(BrowserError::AlreadyRecycling),
                _ => {}
            }
            if matches!(reason, RecycleReason::Memory | RecycleReason::Crash) && !force {
                let now = Instant::now();
                let tripped = recycle_window_push(
                    &mut inner.recycle_history,
                    now,
                    RECYCLE_WINDOW,
                    CRASH_LOOP_MAX_RECYCLES,
                );
                if tripped {
                    inner.state = BrowserState::Down {
                        reason: "crash-loop".to_string(),
                    };
                    drop(inner);
                    error!(
                        "crash-loop: >= {CRASH_LOOP_MAX_RECYCLES} recycles in {}s; browser left down. \
                         Manual recovery: System page Restart browser (force_restart)",
                        RECYCLE_WINDOW.as_secs()
                    );
                    if let Err(e) = self
                        .db
                        .insert_browser_event(
                            "crash_loop",
                            None,
                            Some(&format!(
                                "window_s={} max={}",
                                RECYCLE_WINDOW.as_secs(),
                                CRASH_LOOP_MAX_RECYCLES
                            )),
                        )
                        .await
                    {
                        warn!(error = %e, "failed to record browser_events(crash_loop)");
                    }
                    return Err(BrowserError::CrashLoop);
                }
            }
            inner.recycle_in_progress = true;
            inner.state = BrowserState::Restarting;
            old_pid = inner.pid;
        }

        let old_rss = self.stats.lock().unwrap_or_else(|e| e.into_inner()).rss_mb;
        info!(%reason, old_pid, old_rss_mb = format!("{old_rss:.1}"), "recycling browser");
        if let Err(e) = self
            .db
            .insert_browser_event(
                "restarting",
                Some((old_rss * 1024.0 * 1024.0) as i64),
                Some(&format!("reason={reason} old_pid={old_pid:?}")),
            )
            .await
        {
            warn!(error = %e, "failed to record browser_events(restarting)");
        }

        // Phase 2 — wait for an in-flight visit (capped). Runs without the
        // inner lock; a still-running visit keeps holding the gate.
        let visit_timeout = crate::config::typed_i64(&self.db, "visit_timeout_s")
            .await
            .unwrap_or(30)
            .clamp(1, 300);
        let gate_wait = Duration::from_secs((visit_timeout + GATE_WAIT_SLACK_S).max(1) as u64);
        // Owned permit: released when `_gate` drops (end of the function).
        let gate_result = tokio::time::timeout(gate_wait, self.visit_gate.lock()).await;
        let _gate = gate_result.ok();
        if _gate.is_none() {
            warn!(
                "in-flight visit exceeded {gate_wait:?}; killing the browser anyway (visit fails with Disconnected)"
            );
        }

        // Phases 3–5 run under the spawn lock: `ensure_running` re-checks
        // state under it too, so it can never boot-spawn a duplicate while a
        // recycle is between "old child taken" and "new child stored".
        let _spawn = self.spawn_lock.lock().await;

        // Phase 3 — graceful stop of the old child.
        let child = { self.inner.lock().await.child.take() };
        if let Some(child) = child {
            self.terminate_child(child).await;
        }

        // If a shutdown was requested while the recycle was in flight, this
        // is a plain stop: skip delay + respawn entirely.
        {
            let mut inner = self.inner.lock().await;
            if matches!(inner.state, BrowserState::Stopping) {
                inner.recycle_in_progress = false;
                inner.child = None;
                inner.pid = None;
                return Ok(());
            }
        }

        // Phase 4 — respawn delay.
        let delay = crate::config::typed_i64(&self.db, "browser_respawn_delay_s")
            .await
            .unwrap_or(5)
            .clamp(0, 30) as u64;
        if delay > 0 {
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }

        // Phase 5 — respawn.
        match self.spawn_and_store(SpawnPurpose::Respawn).await {
            Ok(port) => {
                let new_pid = self.inner.lock().await.pid;
                let restarts = self.restarts_total_now();
                if let Err(e) = self
                    .db
                    .insert_browser_event(
                        "restarted",
                        None,
                        Some(&format!(
                            "reason={reason} old_pid={old_pid:?} new_pid={new_pid:?} port={port} restarts_total={restarts}"
                        )),
                    )
                    .await
                {
                    warn!(error = %e, "failed to record browser_events(restarted)");
                }
                self.inner.lock().await.recycle_in_progress = false;
                Ok(())
            }
            Err(e) => {
                error!(error = %e, "respawn failed; browser left down");
                let mut inner = self.inner.lock().await;
                inner.child = None;
                inner.pid = None;
                inner.recycle_in_progress = false;
                inner.state = BrowserState::Down {
                    reason: format!("respawn failed: {e}"),
                };
                drop(inner);
                if let Err(db_err) = self
                    .db
                    .insert_browser_event(
                        "respawn_failed",
                        None,
                        Some(&format!("reason={reason} error={e}")),
                    )
                    .await
                {
                    warn!(error = %db_err, "failed to record browser_events(respawn_failed)");
                }
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Health loop
// ---------------------------------------------------------------------------

async fn health_tick(core: &Core) {
    // Live-read thresholds; tolerate DB errors with built-in defaults.
    let warn_mb = crate::config::typed_i64(&core.db, "memory_warn_mb")
        .await
        .unwrap_or(160);
    let restart_mb = crate::config::typed_i64(&core.db, "memory_restart_mb")
        .await
        .unwrap_or(200);

    // 1) State/exit check under one short lock.
    let crashed: Option<(Option<u32>, std::process::ExitStatus)> = {
        let mut inner = core.inner.lock().await;
        if !matches!(inner.state, BrowserState::Running) {
            return; // Restarting / Down / Stopping — nothing to sample this tick.
        }
        match inner.child.as_mut() {
            None => None, // Pre-boot; spawn_monitoring/ensure_running will spawn.
            Some(child) => match child.try_wait() {
                Ok(None) => None,
                Ok(Some(status)) => {
                    let pid = inner.pid;
                    // Take the child so terminate paths see a clean slot.
                    inner.child.take();
                    inner.pid = None;
                    Some((pid, status))
                }
                Err(e) => {
                    debug!(error = %e, "try_wait failed; skipping sample");
                    None
                }
            },
        }
    };

    if let Some((pid, status)) = crashed {
        let detail = match status.code() {
            Some(code) => format!("pid={pid:?} exit_code={code}"),
            None => format!("pid={pid:?} terminated_by_signal"),
        };
        error!(%detail, "lightpanda exited unexpectedly");
        if let Err(e) = core
            .db
            .insert_browser_event("crashed", None, Some(&detail))
            .await
        {
            warn!(error = %e, "failed to record browser_events(crashed)");
        }
        // Persist last-known stats as down before recycling.
        let sample = {
            let inner = core.inner.lock().await;
            core.snapshot_stats(false, &inner, 0.0, 0.0, restart_mb)
        };
        core.write_stats(sample);
        if let Err(e) = core.recycle(RecycleReason::Crash, false).await {
            error!(error = %e, "recycle after crash failed");
        }
        return;
    }

    // 2) /proc sample (no inner lock held across the reads).
    let pid = { core.inner.lock().await.pid };
    let (rss_mb, cpu_pct) = match pid {
        Some(pid) => match sample_proc(pid).await {
            Some((rss_mb, ticks)) => {
                let now = Instant::now();
                let mut inner = core.inner.lock().await;
                let prev = inner.prev_cpu;
                let cpu_pct = cpu_pct_between(prev.as_ref(), ticks, now);
                inner.prev_cpu = Some(CpuSample { ticks, at: now });
                drop(inner);
                (rss_mb, cpu_pct)
            }
            None => {
                debug!(pid, "/proc read failed; skipping sample");
                return;
            }
        },
        None => return, // Nothing to sample yet.
    };

    // 3) Threshold decisions + stats publish.
    let now = Instant::now();
    let mut warn_now = false;
    let mut recycle_reason = None;
    {
        let inner = core.inner.lock().await;
        if should_warn(rss_mb, warn_mb) {
            warn_now = warn_due(inner.last_health_warn, now, HEALTH_WARN_MIN_INTERVAL);
        }
        if should_restart(rss_mb, restart_mb) {
            recycle_reason = Some(RecycleReason::Memory);
        }
        let uptime_s = (OffsetDateTime::now_utc() - inner.started_at)
            .whole_seconds()
            .max(0) as u64;
        let sample = BrowserStats {
            running: inner.child.is_some(),
            pid: inner.pid,
            port: inner.cdp_port,
            rss_mb,
            cpu_pct,
            uptime_s,
            restarts_total: inner.restarts_total,
            mem_threshold_mb: restart_mb,
        };
        drop(inner);
        if warn_now {
            core.inner.lock().await.last_health_warn = Some(now);
        }
        core.write_stats(sample);
    }

    if warn_now {
        warn!(rss_mb, warn_mb, "browser RSS above warning threshold");
        if let Err(e) = core
            .db
            .insert_browser_event(
                "health_warn",
                Some((rss_mb * 1024.0 * 1024.0) as i64),
                Some(&format!("rss_mb={rss_mb:.1} warn_mb={warn_mb}")),
            )
            .await
        {
            warn!(error = %e, "failed to record browser_events(health_warn)");
        }
    }

    if let Some(reason) = recycle_reason {
        warn!(
            rss_mb,
            restart_mb, "browser RSS above restart threshold; recycling"
        );
        if let Err(e) = core.recycle(reason, false).await {
            error!(error = %e, "memory-triggered recycle failed");
        }
    }
}

async fn health_loop(core: Core) {
    // Boot spawn: surface failures here, then keep the loop alive regardless.
    // The loop re-checks state every tick; `ensure_running` is the
    // concurrency-safe entry point, reused to avoid two spawn paths.
    if let Err(e) = ensure_running_core(&core).await {
        error!(error = %e, "initial browser spawn failed; browser is down until force_restart()");
        let mut inner = core.inner.lock().await;
        if matches!(inner.state, BrowserState::Running) {
            inner.state = BrowserState::Down {
                reason: format!("initial spawn failed: {e}"),
            };
        }
    }
    loop {
        let poll_s = crate::config::typed_i64(&core.db, "rss_poll_interval_s")
            .await
            .unwrap_or(5)
            .clamp(1, 60) as u64;
        tokio::time::sleep(Duration::from_secs(poll_s)).await;
        health_tick(&core).await;
    }
}

/// Shared implementation of `ensure_running` for both the task and the
/// public API. See [`BrowserManager::ensure_running`].
async fn ensure_running_core(core: &Core) -> Result<u16, BrowserError> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // Cheap inspect first: avoid the spawn lock when not needed.
        enum Next {
            Done(u16),
            Spawn,
            Wait,
            Err(BrowserError),
        }
        let next = {
            let inner = core.inner.lock().await;
            match &inner.state {
                BrowserState::Running if inner.child.is_some() => Next::Done(inner.cdp_port),
                BrowserState::Running => Next::Spawn,
                BrowserState::Restarting => Next::Wait,
                BrowserState::Down { reason } => {
                    Next::Err(BrowserError::BrowserUnavailable(reason.clone()))
                }
                BrowserState::Stopping => Next::Err(BrowserError::ShuttingDown),
            }
        };
        match next {
            Next::Done(port) => return Ok(port),
            Next::Err(e) => return Err(e),
            Next::Spawn => {
                let _spawn = core.spawn_lock.lock().await;
                // Re-check under the spawn lock: a concurrent recycle (which
                // also holds the spawn lock across its stop/respawn) may have
                // moved the browser to `Restarting` or brought up a fresh one
                // while we were waiting.
                let proceed = {
                    let inner = core.inner.lock().await;
                    matches!(inner.state, BrowserState::Running) && inner.child.is_none()
                };
                if proceed {
                    return core.spawn_and_store(SpawnPurpose::Boot).await;
                }
                drop(_spawn);
                continue; // State changed under us; loop and re-inspect.
            }
            Next::Wait => {
                if Instant::now() >= deadline {
                    return Err(BrowserError::BrowserUnavailable(
                        "timed out waiting for in-flight recycle".to_string(),
                    ));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BrowserManager — public API
// ---------------------------------------------------------------------------

impl BrowserManager {
    /// Create the manager. Does **not** spawn yet — call
    /// [`Self::spawn_monitoring`] once at boot (and [`Self::ensure_running`]
    /// before use). `binary` is resolved via `PATH` for the default
    /// `lightpanda`; set `BROWSER_BINARY` to override (tests/dev).
    /// `base_port` defaults to 9222; the actual port is visible via
    /// [`Self::cdp_port`] after the first spawn (it may be higher if the
    /// base port was busy — see the port scan in `spawn_browser`).
    pub async fn launch(db: Db, binary: &str, base_port: u16) -> BrowserManager {
        let initial_stats = BrowserStats {
            port: base_port,
            ..BrowserStats::default()
        };
        let core = Core {
            inner: Arc::new(Mutex::new(ManagerInner {
                child: None,
                cdp_port: base_port,
                pid: None,
                started_at: OffsetDateTime::now_utc(),
                restarts_total: 0,
                state: BrowserState::Running,
                recycle_in_progress: false,
                prev_cpu: None,
                last_health_warn: None,
                recycle_history: Vec::with_capacity(RECYCLE_HISTORY_CAP),
            })),
            db,
            stats: Arc::new(StdMutex::new(initial_stats)),
            visit_gate: Arc::new(Mutex::new(())),
            spawn_lock: Arc::new(Mutex::new(())),
            binary: binary.to_string(),
            base_port,
        };
        BrowserManager {
            core,
            health_task: StdMutex::new(None),
        }
    }

    /// Start the health-loop task (idempotent; extra calls are no-ops). The
    /// loop's first action is the boot spawn attempt via `ensure_running`.
    /// Called exactly once at boot from `main.rs`.
    pub fn spawn_monitoring(&self) {
        let mut slot = self.health_task.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return;
        }
        let core = self.core.clone();
        *slot = Some(tokio::spawn(health_loop(core)));
    }

    /// Ensure the browser is up: spawn if this is the first call, wait for an
    /// in-flight recycle otherwise. Returns the CDP port. Used by the
    /// executor (SEG-10). Fails fast with [`BrowserError::BrowserUnavailable`]
    /// when the browser is `Down` (e.g. crash-loop protection) — retry only
    /// after a successful [`Self::force_restart`].
    pub async fn ensure_running(&self) -> Result<u16, BrowserError> {
        ensure_running_core(&self.core).await
    }

    /// Port the browser currently listens on (may differ from the configured
    /// base port after a conflict scan).
    pub async fn cdp_port(&self) -> u16 {
        self.core.inner.lock().await.cdp_port
    }

    /// PID of the browser process, if one is tracked.
    pub async fn pid(&self) -> Option<u32> {
        self.core.inner.lock().await.pid
    }

    /// Total number of respawns since boot (initial spawn does not count).
    pub async fn restarts_total(&self) -> u64 {
        self.core.inner.lock().await.restarts_total
    }

    /// Cloneable handle to the **visit gate**. SEG-10's executor MUST hold
    /// `manager.visit_gate().lock().await` for the whole visit — from before
    /// `ensure_running` until the target is closed — so a recycle can never
    /// SIGTERM the browser mid-visit. A recycle waits on this gate with a
    /// cap of `visit_timeout_s + 30s`; after that the gate is taken anyway.
    pub fn visit_gate(&self) -> Arc<Mutex<()>> {
        Arc::clone(&self.core.visit_gate)
    }

    /// Latest health sample (never blocks the health loop). Fields see module
    /// docs; `running` reflects the last `/proc` poll, not a live syscall.
    pub fn stats(&self) -> BrowserStats {
        self.core
            .stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Recycle the browser, recording `reason`. Re-entrancy-guarded:
    /// concurrent calls fail with [`BrowserError::AlreadyRecycling`].
    pub async fn recycle(&self, reason: RecycleReason) -> Result<(), BrowserError> {
        self.core.recycle(reason, false).await
    }

    /// Manual recovery path: restart the browser regardless of the crash-loop
    /// guard and of a `Down` state. Resets the crash-loop window.
    pub async fn force_restart(&self) -> Result<(), BrowserError> {
        {
            let mut inner = self.core.inner.lock().await;
            inner.recycle_history.clear();
        }
        self.core.recycle(RecycleReason::Manual, true).await
    }

    /// Graceful shutdown: stop the health loop, SIGTERM the browser
    /// (waiting up to `browser_restart_timeout_s`, then SIGKILL), and record
    /// `stopped`. Waits briefly for any in-flight recycle to finish first so
    /// the child can never be orphaned.
    pub async fn shutdown(&self) -> Result<(), BrowserError> {
        // 1) Signal Stopping first: health_tick bails out early on Stopping,
        //    so the loop goes quiet but any in-flight recycle runs to
        //    completion (it holds no inner lock across its waits).
        {
            let mut inner = self.core.inner.lock().await;
            inner.state = BrowserState::Stopping;
        }

        // 2) Wait for an in-progress recycle to release the child slot so the
        //    browser can never be orphaned by teardown. Drain bound covers
        //    the recycle's worst case: visit_gate cap + restart timeout.
        let visit_timeout = crate::config::typed_i64(&self.core.db, "visit_timeout_s")
            .await
            .unwrap_or(30)
            .clamp(1, 300);
        let restart_timeout = crate::config::typed_i64(&self.core.db, "browser_restart_timeout_s")
            .await
            .unwrap_or(15)
            .clamp(1, 120);
        let drain = Duration::from_secs(
            (visit_timeout + GATE_WAIT_SLACK_S + restart_timeout + 10).max(30) as u64,
        );
        let deadline = Instant::now() + drain;
        loop {
            {
                let inner = self.core.inner.lock().await;
                if !inner.recycle_in_progress {
                    break;
                }
            }
            if Instant::now() >= deadline {
                warn!("shutdown: recycle did not finish within {drain:?}; proceeding anyway");
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // 3) Abort the health loop (it is idle or sleeping at this point).
        {
            let mut slot = self.health_task.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(handle) = slot.take() {
                handle.abort();
            }
        }

        // 4) Stop the browser. CDP connections are per-visit (the manager
        //    keeps none), so there is nothing else to close.
        let child = { self.core.inner.lock().await.child.take() };
        let mut stopped_pid = None;
        if let Some(child) = child {
            stopped_pid = child.id();
            self.core.terminate_child(child).await;
        }
        {
            let mut inner = self.core.inner.lock().await;
            inner.pid = None;
            inner.child = None;
            let uptime_s = (OffsetDateTime::now_utc() - inner.started_at)
                .whole_seconds()
                .max(0) as u64;
            let port = inner.cdp_port;
            let restarts = inner.restarts_total;
            drop(inner);
            let stats = BrowserStats {
                running: false,
                pid: None,
                port,
                rss_mb: 0.0,
                cpu_pct: 0.0,
                uptime_s,
                restarts_total: restarts,
                mem_threshold_mb: crate::config::typed_i64(&self.core.db, "memory_restart_mb")
                    .await
                    .unwrap_or(200),
            };
            self.core.write_stats(stats);
        }
        if let Err(e) = self
            .core
            .db
            .insert_browser_event("stopped", None, Some(&format!("pid={stopped_pid:?}")))
            .await
        {
            warn!(error = %e, "failed to record browser_events(stopped)");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- pure parsers / counters ---

    #[test]
    fn serve_args_bind_loopback_exactly() {
        let args = serve_args(9222);
        assert_eq!(
            args,
            vec![
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                "9222",
                "--log-level",
                "info",
            ],
            "spawn args must bind 127.0.0.1 and nothing else"
        );
        assert!(cdp_binds_loopback());
        // The host argument is not user-controlled anywhere in the spawn
        // path: BROWSER_BINARY only replaces the binary, LIGHTPANDA_CDP_PORT
        // only the port. No argument may name a non-loopback host.
        for arg in &args {
            assert!(!arg.starts_with("0.0.0.0"));
            assert!(!arg.contains("::"), "no IPv6 any-address in {arg}");
        }
    }

    #[test]
    fn parse_vm_rss_kb_reads_status() {
        let status = "Name:\tlightpanda\nVmPeak:\t 21500000 kB\nVmSize:\t 21500000 kB\n\
                      VmRSS:\t   15872 kB\nRssFile:\t    4096 kB\n";
        assert_eq!(parse_vm_rss_kb(status), Some(15872));
        assert_eq!(parse_vm_rss_kb("no rss here\n"), None);
        assert_eq!(parse_vm_rss_kb("VmRSS:\n"), None);
        assert_eq!(parse_vm_rss_kb("VmRSS:   nope kB\n"), None);
    }

    #[test]
    fn parse_stat_cpu_ticks_handles_comm_with_spaces_and_parens() {
        // comm = "light panda (serve)" — must be parsed after the LAST ')'.
        let mut fields = vec![
            "S", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "1000", "200",
        ];
        // field 14 (utime) is index 11, field 15 (stime) is index 12 of the post-comm tail.
        fields[11] = "1000"; // utime
        fields[12] = "200"; // stime
        let stat = format!("1234 (light panda (serve)) {}", fields.join(" "));
        assert_eq!(parse_stat_cpu_ticks(&stat), Some(1200));

        let stat_simple = format!("99 (sleep) {}", fields.join(" "));
        assert_eq!(parse_stat_cpu_ticks(&stat_simple), Some(1200));

        assert_eq!(parse_stat_cpu_ticks("garbage"), None);
        assert_eq!(parse_stat_cpu_ticks("99 (x) S 1"), None);
    }

    #[test]
    fn cpu_pct_first_sample_is_zero_and_deltas_scale() {
        let t0 = Instant::now();
        assert_eq!(cpu_pct_between(None, 1000, t0), 0.0);
        let prev = CpuSample {
            ticks: 1000,
            at: t0,
        };
        // 100 ticks over 1 second == 1.0 CPU-second == 100% of one core.
        let later = t0 + Duration::from_secs(1);
        assert!((cpu_pct_between(Some(&prev), 1100, later) - 100.0).abs() < 1e-6);
        // Saturating against a smaller counter yields 0, not a panic.
        assert_eq!(cpu_pct_between(Some(&prev), 500, later), 0.0);
    }

    #[test]
    fn should_warn_and_should_restart_thresholds() {
        assert!(!should_warn(160.0, 160));
        assert!(should_warn(160.1, 160));
        assert!(!should_restart(200.0, 200));
        assert!(should_restart(200.1, 200));
        // Negative thresholds are nonsensical; never trigger.
        assert!(!should_warn(1e9, -1));
        assert!(!should_restart(1e9, -1));
    }

    #[test]
    fn warn_due_rate_limits() {
        let t0 = Instant::now();
        assert!(warn_due(None, t0, HEALTH_WARN_MIN_INTERVAL));
        assert!(!warn_due(
            Some(t0),
            t0 + Duration::from_secs(10),
            HEALTH_WARN_MIN_INTERVAL
        ));
        assert!(warn_due(
            Some(t0),
            t0 + HEALTH_WARN_MIN_INTERVAL,
            HEALTH_WARN_MIN_INTERVAL
        ));
    }

    #[test]
    fn recycle_window_trips_at_five_within_sixty_seconds() {
        let mut times = Vec::new();
        let t0 = Instant::now();
        for i in 1..5 {
            assert!(
                !recycle_window_push(
                    &mut times,
                    t0 + Duration::from_secs(i),
                    RECYCLE_WINDOW,
                    CRASH_LOOP_MAX_RECYCLES
                ),
                "push {i} must not trip"
            );
        }
        assert!(
            recycle_window_push(
                &mut times,
                t0 + Duration::from_secs(5),
                RECYCLE_WINDOW,
                CRASH_LOOP_MAX_RECYCLES
            ),
            "5th recycle within 60s must trip crash-loop"
        );
        assert!(times.len() <= RECYCLE_HISTORY_CAP);
    }

    #[test]
    fn recycle_window_prunes_old_entries() {
        let mut times = Vec::new();
        let t0 = Instant::now();
        for i in 0..4 {
            recycle_window_push(
                &mut times,
                t0 + Duration::from_secs(i),
                RECYCLE_WINDOW,
                CRASH_LOOP_MAX_RECYCLES,
            );
        }
        // 121 seconds later the old entries are all pruned; no trip.
        assert!(!recycle_window_push(
            &mut times,
            t0 + Duration::from_secs(121),
            RECYCLE_WINDOW,
            CRASH_LOOP_MAX_RECYCLES
        ));
        assert_eq!(times.len(), 1);
    }

    // --- async manager behaviour (no browser binary needed) ---

    async fn test_manager() -> BrowserManager {
        let db = Db::in_memory().await.expect("in-memory db");
        crate::config::seed_settings(&db).await.expect("seed");
        BrowserManager::launch(db, "lightpanda", DEFAULT_BASE_PORT).await
    }

    #[tokio::test]
    async fn first_free_port_in_skips_busy_ports() {
        // Bind the base port; the scan must report the next one.
        let base = {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("bind ephemeral");
            let port = listener.local_addr().expect("addr").port();
            std::mem::forget(Box::new(listener)); // intentionally leaked for the test duration
            port
        };
        let picked = first_free_port_in(base, base + PORT_SCAN)
            .await
            .expect("a free port");
        assert_eq!(picked, base + 1);
    }

    #[tokio::test]
    async fn stats_default_before_any_spawn() {
        let manager = test_manager().await;
        let stats = manager.stats();
        assert!(!stats.running);
        assert_eq!(stats.pid, None);
        assert_eq!(stats.port, DEFAULT_BASE_PORT);
        assert_eq!(stats.restarts_total, 0);
        assert_eq!(stats.mem_threshold_mb, 200);
    }

    #[tokio::test]
    async fn recycle_guard_rejects_concurrent_recycle() {
        let manager = test_manager().await;
        {
            let mut inner = manager.core.inner.lock().await;
            inner.recycle_in_progress = true;
        }
        let err = manager.recycle(RecycleReason::Memory).await.unwrap_err();
        assert!(matches!(err, BrowserError::AlreadyRecycling));
        let mut inner = manager.core.inner.lock().await;
        inner.recycle_in_progress = false;
    }

    #[tokio::test]
    async fn ensure_running_fails_fast_when_down() {
        let manager = test_manager().await;
        {
            let mut inner = manager.core.inner.lock().await;
            inner.state = BrowserState::Down {
                reason: "crash-loop".to_string(),
            };
        }
        let err = manager.ensure_running().await.unwrap_err();
        match err {
            BrowserError::BrowserUnavailable(reason) => assert_eq!(reason, "crash-loop"),
            other => panic!("expected BrowserUnavailable, got {other:?}"),
        }

        let mut inner = manager.core.inner.lock().await;
        inner.state = BrowserState::Stopping;
        drop(inner);
        let err = manager.ensure_running().await.unwrap_err();
        assert!(matches!(err, BrowserError::ShuttingDown));
    }

    #[tokio::test]
    async fn visit_gate_is_shared_and_exclusive() {
        let manager = test_manager().await;
        let gate = manager.visit_gate();
        let permit = gate.try_lock().expect("gate free initially");
        let second = manager.visit_gate();
        assert!(
            second.try_lock().is_err(),
            "gate must exclude concurrent visits"
        );
        drop(permit);
        assert!(second.try_lock().is_ok());
    }

    // --- live integration tests (lightpanda + tempdir db) ---

    struct PidGuard {
        pids: Vec<u32>,
    }
    impl Drop for PidGuard {
        fn drop(&mut self) {
            for &pid in &self.pids {
                // SAFETY: best-effort cleanup of our own test children.
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
    }

    fn lightpanda_available() -> bool {
        std::process::Command::new("lightpanda")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn free_ephemeral_port() -> u16 {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("ephemeral port");
        listener.local_addr().expect("addr").port()
    }

    async fn live_manager(dir: &std::path::Path, port: u16) -> (BrowserManager, Db) {
        let db = Db::open(&dir.join("live.db")).await.expect("open db");
        crate::config::seed_settings(&db).await.expect("seed");
        // Speed the health loop and the respawn path up for the test.
        crate::config::set_setting(&db, "rss_poll_interval_s", "1")
            .await
            .expect("poll interval");
        crate::config::set_setting(&db, "browser_respawn_delay_s", "1")
            .await
            .expect("respawn delay");
        let manager_db = db.clone();
        (
            BrowserManager::launch(db, "lightpanda", port).await,
            manager_db,
        )
    }

    #[tokio::test]
    #[ignore = "requires lightpanda on PATH; spawns real browsers. Run: cargo test --locked -- --ignored browser_live"]
    async fn browser_live_full_cycle() {
        if !lightpanda_available() {
            eprintln!("lightpanda not on PATH; skipping");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let mut guard = PidGuard { pids: Vec::new() };
        let port = free_ephemeral_port();
        let (manager, db) = live_manager(dir.path(), port).await;
        manager.spawn_monitoring();
        let cdp_port = manager.ensure_running().await.expect("browser ready");
        assert_eq!(cdp_port, port, "first port should be free and used");

        let pid1 = manager.pid().await.expect("pid tracked");
        guard.pids.push(pid1);
        let stats = manager.stats();
        println!(
            "after spawn: pid={} port={} rss_mb={:.1} running={} restarts_total={}",
            pid1, stats.port, stats.rss_mb, stats.running, stats.restarts_total
        );
        assert!(stats.running);
        assert!(
            stats.rss_mb > 0.0 && stats.rss_mb < 100.0,
            "idle rss {:.1} MB out of expected range",
            stats.rss_mb
        );
        assert_eq!(stats.restarts_total, 0);

        // CDP connect works against the running browser.
        let ws_url = format!("ws://127.0.0.1:{cdp_port}/");
        let cdp = crate::browser::cdp::connect(&ws_url)
            .await
            .expect("cdp connect");
        drop(cdp);

        // Force a recycle: new pid, new connection, event rows written.
        manager.force_restart().await.expect("force_restart");
        let pid2 = manager.pid().await.expect("pid tracked after restart");
        guard.pids.push(pid2);
        assert_ne!(pid1, pid2, "recycle must produce a new pid");
        let stats = manager.stats();
        println!(
            "after force_restart: pid={} rss_mb={:.1} restarts_total={}",
            pid2, stats.rss_mb, stats.restarts_total
        );
        assert_eq!(stats.restarts_total, 1);
        assert!(stats.running);

        let cdp = crate::browser::cdp::connect(&ws_url)
            .await
            .expect("cdp reconnect after restart");
        drop(cdp);

        let started: i64 = db
            .connection()
            .call(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM browser_events WHERE event_type='started'",
                    [],
                    |r| r.get(0),
                )
            })
            .await
            .expect("count started");
        let restarted: i64 = db
            .connection()
            .call(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM browser_events WHERE event_type='restarted'",
                    [],
                    |r| r.get(0),
                )
            })
            .await
            .expect("count restarted");
        println!("browser_events: started={started} restarted={restarted}");
        assert!(started >= 1, "expected at least one started event");
        assert!(restarted >= 1, "expected at least one restarted event");

        manager.shutdown().await.expect("graceful shutdown");
        let stats = manager.stats();
        assert!(!stats.running);
        assert_eq!(stats.pid, None);
        let stopped: i64 = db
            .connection()
            .call(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM browser_events WHERE event_type='stopped'",
                    [],
                    |r| r.get(0),
                )
            })
            .await
            .expect("count stopped");
        assert!(stopped >= 1, "expected a stopped event");
    }

    #[tokio::test]
    #[ignore = "requires lightpanda on PATH; kills a real browser with SIGKILL. Run: cargo test --locked -- --ignored browser_live_crash"]
    async fn browser_live_crash_recovery() {
        if !lightpanda_available() {
            eprintln!("lightpanda not on PATH; skipping");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let mut guard = PidGuard { pids: Vec::new() };
        let port = free_ephemeral_port();
        let (manager, _db) = live_manager(dir.path(), port).await;
        manager.spawn_monitoring();
        manager.ensure_running().await.expect("browser ready");
        let pid1 = manager.pid().await.expect("pid tracked");
        guard.pids.push(pid1);

        // Kill -9: the health loop must notice within one poll interval and
        // recycle; the new pid must differ and CDP must reconnect.
        // SAFETY: pid1 is our direct child spawned by this test.
        unsafe {
            libc::kill(pid1 as i32, libc::SIGKILL);
        }

        let mut recovered = None;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if let Some(pid) = manager.pid().await
                && Some(pid) != Some(pid1)
            {
                recovered = Some(pid);
                break;
            }
        }
        let pid2 = recovered.expect("health loop did not respawn the browser within 25s");
        guard.pids.push(pid2);
        let stats = manager.stats();
        println!(
            "after kill -9: old_pid={pid1} new_pid={pid2} restarts_total={}",
            stats.restarts_total
        );
        assert!(stats.restarts_total >= 1);

        let ws_url = format!("ws://127.0.0.1:{}/", manager.cdp_port().await);
        let cdp = crate::browser::cdp::connect(&ws_url)
            .await
            .expect("cdp reconnect after crash");
        drop(cdp);
        manager.shutdown().await.expect("graceful shutdown");
    }
}
