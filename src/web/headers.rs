//! Security response headers (SEG-13).
//!
//! Applied at the OUTERMOST layer of the router so every response carries
//! them — `/health`, `/login`, `/logout`, `/public/*`, the protected pages,
//! HTMX fragments and API JSON, the 64 KB/64 MB body-limit rejections and the
//! 404/405 fallbacks alike.
//!
//! Behaviour:
//! - Always set: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
//!   `Referrer-Policy: no-referrer`, and a strict
//!   `Content-Security-Policy` (`default-src 'self'`; no `unsafe-inline`
//!   anywhere — all page behaviour lives in `/public/app.js`).
//! - `Strict-Transport-Security` only when the request arrives with
//!   `x-forwarded-proto: https` (the app never terminates TLS itself; the
//!   header is set by the fronting proxy — same convention as the
//!   `Secure` attribute on the session cookie).
//! - `Cache-Control: no-store` unless the response already carries a
//!   `Cache-Control` header (only `/public/*` does: it sets
//!   `public, max-age=3600` and is intentionally cacheable). Authenticated
//!   HTML, fragments, API JSON and `/health` are never stored.
//!
//! `frame-ancestors 'none'` in the CSP plus `X-Frame-Options: DENY` are
//! redundant on purpose (defence in depth against clickjacking).

use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// The one and only Content-Security-Policy. Exported for the unit test
/// that pins the absence of `unsafe-inline`.
pub(crate) const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
img-src 'self' data:; \
style-src 'self'; \
script-src 'self'; \
connect-src 'self'; \
font-src 'self'; \
frame-ancestors 'none'; \
base-uri 'none'; \
form-action 'self'";

pub async fn security_headers(request: Request, next: Next) -> Response {
    let forwarded_https = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false);

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    // All page behaviour lives in /public/app.js; inline scripts are
    // banned by this policy and by convention (see tests/redaction.rs).
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    if forwarded_https {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_contains_no_unsafe_inline_or_unsafe_eval() {
        let csp = CONTENT_SECURITY_POLICY;
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains("unsafe-eval"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("base-uri 'none'"));
        assert!(csp.contains("form-action 'self'"));
        assert!(csp.contains("img-src 'self' data:"));
    }
}
