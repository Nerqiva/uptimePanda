//! CSRF protection — stateless double-submit (SEG-11, hardened in SEG-13).
//!
//! The session cookie carries the session *expiry*. The CSRF token is
//! `hex(hmac_sha256(session_key, "csrf:" || expiry_unix))` — fully determined
//! by the session, so no server-side token store is needed and tokens die
//! with the session. Mutating handlers accept the token either as a
//! `csrf_token` form field (plain forms, zero JS) or as an `X-CSRF-Token`
//! header (htmx elements outside a form).
//!
//! Verification is constant-time. Any mismatch — missing token, malformed
//! session, wrong value — is rejected with 403.

use axum::http::HeaderMap;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

const CSRF_PREFIX: &str = "csrf:";

/// Derive the CSRF token for a session that expires at `expiry_unix`.
pub fn csrf_token(session_key: &[u8; 32], expiry_unix: i64) -> String {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(session_key).expect("HMAC accepts any key length");
    mac.update(CSRF_PREFIX.as_bytes());
    mac.update(expiry_unix.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time token comparison (hex-decoded digests, fixed length).
pub fn tokens_equal(a: &str, b: &str) -> bool {
    let a = match hex::decode(a) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let b = match hex::decode(b) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Verify a CSRF token against the session expiry.
pub fn verify(session_key: &[u8; 32], expiry_unix: i64, provided: &str) -> bool {
    let expected = csrf_token(session_key, expiry_unix);
    tokens_equal(&expected, provided)
}

/// Look up the token in the request: `csrf_token` form field wins, then the
/// `X-CSRF-Token` header. `form_token` is the parsed field when a form body
/// was decoded; pass `None` for bodies that were not form-parsed.
pub fn extract_token<'a>(headers: &'a HeaderMap, form_token: Option<&'a str>) -> Option<&'a str> {
    if let Some(t) = form_token
        && !t.is_empty()
    {
        return Some(t);
    }
    headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Verify the CSRF token for a mutating request. Returns `true` when the
/// request may proceed.
pub fn verify_request(
    state: &AppState,
    expiry_unix: i64,
    headers: &HeaderMap,
    form_token: Option<&str>,
) -> bool {
    match extract_token(headers, form_token) {
        Some(provided) => verify(&state.session_key, expiry_unix, provided),
        None => false,
    }
}
