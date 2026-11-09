//! CSRF protection — stateless double-submit (SEG-11, hardened in SEG-13).
//!
//! The CSRF token is `hex(hmac_sha256(session_key, "csrf:v1"))`. It depends
//! only on the key derived from `APP_PASSWORD` + `ENCRYPTION_KEY`, **not**
//! on the session cookie's expiry, so the 12h sliding renewal reissues a
//! cookie without desynchronizing the tokens embedded in already-rendered
//! pages. (Previously the token was bound to the session expiry; a renewal
//! would have invalidated every in-flight page form, producing a 403 with
//! no operator-visible cause.)
//!
//! ## Threat model (documented, accepted)
//!
//! - **What this is:** a synchronizer-token variant with no server-side
//!   store. The hidden `csrf_token` field (or `X-CSRF-Token` header) must
//!   match the value derivable only from the secret key. An attacker who
//!   cannot read the page body/meta cannot forge a valid form post;
//!   cross-site form submission therefore fails closed with 403. Endpoints
//!   remain reachable without JS (`SameSite=Lax` cookie, plain POST).
//! - **Statelessness trade-off:** the token is stable for the lifetime of
//!   `session_key`. It does not rotate per request or per page load. This
//!   is deliberate: with no server-side token store there is nothing to
//!   rotate against, and the double-submit property (unforgeability without
//!   the key) is unchanged. Rotation happens — for every page — exactly
//!   once, when the key changes (password or `ENCRYPTION_KEY` rotation).
//! - **XSS:** a same-origin script can read the token (it is in the DOM).
//!   That is outside this layer's power to prevent. Mitigation lives in the
//!   CSP (`script-src 'self'`, no `unsafe-inline`) and in the absence of
//!   inline scripts (see `tests/redaction.rs`), plus Askama's default
//!   escaping.
//! - **Network observers:** tokens travel only over TLS-terminated hops to
//!   deployments behind a proxy that sets `x-forwarded-proto: https` (the
//!   session cookie is marked `Secure` there); over plain HTTP the threat
//!   model is moot anyway (no confidentiality on-path).
//! - Mismatch — missing token, malformed hex, wrong value — is rejected
//!   with 403 + minimal HTML page. Verification compares hex-decoded
//!   fixed-length (32-byte) digests in constant time.

use axum::http::HeaderMap;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

const CSRF_MESSAGE: &[u8] = b"csrf:v1";

/// Derive the CSRF token for the session key. Stable: same output for the
/// same key, by design (see module docs).
pub fn csrf_token(session_key: &[u8; 32]) -> String {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(session_key).expect("HMAC accepts any key length");
    mac.update(CSRF_MESSAGE);
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time token comparison (hex-decoded digests, fixed length).
/// Decoded with the `hex` crate; non-hex or wrong-length inputs are
/// rejected before the comparison. The byte-wise fold has no early exit.
pub fn tokens_equal(a: &str, b: &str) -> bool {
    // An empty digest is never a valid token; refuse to "match" empties.
    if a.is_empty() || b.is_empty() {
        return false;
    }
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

/// Verify a CSRF token against the session key.
pub fn verify(session_key: &[u8; 32], provided: &str) -> bool {
    let expected = csrf_token(session_key);
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
pub fn verify_request(state: &AppState, headers: &HeaderMap, form_token: Option<&str>) -> bool {
    match extract_token(headers, form_token) {
        Some(provided) => verify(&state.session_key, provided),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn token_is_stable_for_same_key() {
        assert_eq!(csrf_token(&KEY), csrf_token(&KEY));
        assert_ne!(csrf_token(&KEY), csrf_token(&[8u8; 32]));
        assert_eq!(csrf_token(&KEY).len(), 64); // 32-byte digest, hex
    }

    #[test]
    fn verify_accepts_own_token_and_rejects_others() {
        let token = csrf_token(&KEY);
        assert!(verify(&KEY, &token));
        assert!(!verify(&[9u8; 32], &token));
        // Same length, different bytes, constant-time path.
        let mut wrong = token.clone().into_bytes();
        wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
        let wrong = String::from_utf8(wrong).unwrap();
        assert!(!verify(&KEY, &wrong));
    }

    #[test]
    fn tokens_equal_rejects_malformed_input() {
        assert!(!tokens_equal("", ""));
        assert!(!tokens_equal("zz", "zz")); // not hex
        assert!(!tokens_equal("aabb", "aabbcc")); // length mismatch
        let t = csrf_token(&KEY);
        assert!(tokens_equal(&t, &t));
        // Truncated (wrong length after decode).
        assert!(!tokens_equal(&t, &t[..t.len() - 2]));
    }
}
