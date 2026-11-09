//! Application error type + HTML fallback rendering (SEG-11).
//!
//! Internal details are logged with `tracing` and never leak into the
//! response body — clients see a generic page (or JSON for API paths).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::db::DbError;

/// Errors surfaced by handlers. Anything unrecoverable becomes a 500 page.
#[derive(Debug)]
pub enum AppError {
    Db(DbError),
    Render(askama::Error),
    Internal(String),
}

impl From<DbError> for AppError {
    fn from(e: DbError) -> Self {
        Self::Db(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match &self {
            Self::Db(e) => tracing::error!(error = %e, "database error"),
            Self::Render(e) => tracing::error!(error = %e, "template render error"),
            Self::Internal(msg) => tracing::error!(%msg, "internal error"),
        }
        crate::web::templates::error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "500",
            "An internal error occurred. Details are in the server logs.",
        )
    }
}

impl From<askama::Error> for AppError {
    fn from(e: askama::Error) -> Self {
        Self::Render(e)
    }
}
