//! uptimePanda — lightweight browser keep-alive & synthetic monitoring.
//! SEG-02 scaffold: binary boots an HTTP listener exposing `/health`.

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

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let app = Router::new()
        .route("/health", get(health))
        .fallback(not_found);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
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
