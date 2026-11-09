//! uptimePanda — lightweight browser keep-alive & synthetic monitoring.
//! Boots an HTTP listener exposing `/health`. SEG-04: resolves the
//! deployment config from the environment, seeds the DB-backed settings,
//! then serves.

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

use axum::{Json, Router, http::StatusCode, routing::get};
use serde_json::json;
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

    let config = match config::Config::from_env() {
        Ok(c) => c,
        Err(msg) => {
            // Secrets are never printed; `msg` describes missing/invalid vars only.
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    // Create the parent directory for the database file (no-op when it exists).
    if let Some(parent) = config.database_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let db = db::Db::open(&config.database_path).await?;
    config::seed_settings(&db).await?;

    let app = Router::new()
        .route("/health", get(health))
        .fallback(not_found);

    let addr = std::net::SocketAddr::from((config.bind_addr, config.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, version = VERSION.trim(), "uptimepanda listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "version": VERSION.trim() }))
}

async fn not_found() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}
