//! uptimePanda — lightweight browser keep-alive & synthetic monitoring.
//! `/health` stays open and browser-free; everything else is behind the
//! session middleware. SEG-11: HTMX dashboard served by `web::routes`.

mod browser;
mod config;
mod db;
mod error;
mod executor;
mod interactions;
mod resources;
mod scheduler;
mod security;
mod state;
mod web;

use tracing_subscriber::EnvFilter;

/// Version string, sourced from the VERSION file (trailing newline trimmed at use).
const VERSION: &str = include_str!("../VERSION");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .init();

    // SEG-13: startup self-check — the Lightpanda CDP server must bind
    // 127.0.0.1. There is no environment/CLI path that overrides the host
    // (BROWSER_BINARY swaps the binary, LIGHTPANDA_CDP_PORT swaps the port,
    // serve_args pins the host); refuse to start if that ever regresses.
    if !browser::manager::cdp_binds_loopback() {
        tracing::error!("startup self-check failed: lightpanda CDP serve args must bind 127.0.0.1");
        std::process::exit(1);
    }

    let config = match config::Config::from_env() {
        Ok(c) => c,
        Err(msg) => {
            // Secrets are never printed; `msg` describes missing/invalid vars only.
            tracing::error!("{msg}");
            std::process::exit(1);
        }
    };
    let config = std::sync::Arc::new(config);

    // Create the parent directory for the database file (no-op when it exists).
    if let Some(parent) = config.database_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let db = db::Db::open(&config.database_path).await?;
    config::seed_settings(&db).await?;
    // SEG-07: seed the two starter compatibility profiles (idempotent by
    // name; existing rows untouched). No restart semantics.
    let seeded = browser::sessions::seed_default_profiles(&db).await?;
    if seeded > 0 {
        tracing::info!(seeded, "seeded default compatibility profiles");
    }

    // SEG-06: persistent Lightpanda process manager (recycle on >memory_restart_mb
    // RSS or crash only). The health task auto-spawns the browser at boot.
    // Dev ergonomics: if the binary is absent, log and continue serving /health.
    // BROWSER_BINARY overrides the binary path; LIGHTPANDA_CDP_PORT overrides
    // the base CDP port (default 9222, scanned upward on conflict).
    let binary = std::env::var("BROWSER_BINARY").unwrap_or_else(|_| "lightpanda".to_string());
    let base_port = std::env::var("LIGHTPANDA_CDP_PORT")
        .ok()
        .and_then(|p| p.trim().parse::<u16>().ok())
        .unwrap_or(browser::manager::DEFAULT_BASE_PORT);
    let manager = if std::process::Command::new(&binary)
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let manager =
            browser::manager::BrowserManager::launch(db.clone(), &binary, base_port).await;
        manager.spawn_monitoring();
        // SEG-08/SEG-10 consume this via app state; SEG-21 wires shutdown().
        // Kept alive here for the lifetime of the process.
        Some(std::sync::Arc::new(manager))
    } else {
        tracing::warn!(
            %binary,
            "lightpanda not found (set BROWSER_BINARY to override); browser features disabled"
        );
        None
    };
    // SEG-10: start the scheduler + executor. The scheduler emits claimed
    // jobs onto a capacity-1 dispatch channel; this consumer loop runs the
    // visit and reports the outcome back to the scheduler exactly once.
    // Panics in a visit are converted into `interaction_error` completions —
    // they never take down the worker or the HTTP listener.
    let mut scheduler_handle: Option<scheduler::SchedulerHandle> = None;
    if let Some(mgr) = &manager {
        let (tx, rx) = tokio::sync::mpsc::channel::<scheduler::VisitJob>(1);
        // Deployment-default timezone comes from Config.tz (TZ env, UTC fallback).
        let sched = scheduler::Scheduler::new(db.clone(), config.tz.clone()).start(tx);
        let exec = std::sync::Arc::new(executor::Executor::new(
            db.clone(),
            std::sync::Arc::clone(mgr),
            config.encryption_key.clone(),
            std::sync::Arc::clone(&config),
        ));
        let sched_for_loop = sched.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(job) = rx.recv().await {
                let trigger = match job.trigger {
                    scheduler::Trigger::Scheduled => executor::ExecutionTrigger::Scheduled,
                    scheduler::Trigger::Manual => executor::ExecutionTrigger::Manual,
                };
                let website_id = job.website_id;
                let exec_for_job = std::sync::Arc::clone(&exec);
                // Isolate the visit in its own task so a panic cannot kill
                // the consumer; completion is reported exactly once either way.
                let join =
                    tokio::spawn(async move { exec_for_job.execute(website_id, trigger).await });
                match join.await {
                    Ok(outcome) => {
                        tracing::info!(
                            website_id,
                            outcome = ?outcome.outcome,
                            duration_ms = outcome.duration.as_millis() as u64,
                            http_status = outcome.http_status,
                            final_url = outcome.final_url.as_deref(),
                            memory_usage = outcome.memory_usage,
                            "visit finished"
                        );
                        if let Err(e) = sched_for_loop
                            .handle_completion(
                                website_id,
                                executor::completion_outcome(outcome.outcome),
                            )
                            .await
                        {
                            tracing::error!(website_id, error = %e,
                                "failed to report scheduler completion");
                        }
                    }
                    Err(join_err) => {
                        tracing::error!(website_id, error = %join_err,
                            "visit task panicked; recording interaction_error");
                        if let Err(e) = sched_for_loop
                            .handle_completion(website_id, db::Outcome::InteractionError)
                            .await
                        {
                            tracing::error!(website_id, error = %e,
                                "failed to report scheduler completion after panic");
                        }
                    }
                }
            }
            tracing::warn!("scheduler dispatch channel closed; executor consumer exiting");
        });
        scheduler_handle = Some(sched);
        tracing::info!("scheduler and executor started");
    } else {
        tracing::warn!("lightpanda unavailable; scheduler not started (no jobs will be emitted)");
    }
    let app_state = state::SharedState::new(state::AppState::new(
        db.clone(),
        manager.clone(),
        scheduler_handle.clone(),
        &config,
        VERSION.trim(),
    ));

    let app = web::routes::build_router(app_state);

    let addr = std::net::SocketAddr::from((config.bind_addr, config.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, version = VERSION.trim(), "uptimepanda listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
