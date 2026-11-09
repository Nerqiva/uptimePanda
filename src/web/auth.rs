//! Authentication (SEG-11; hardened in SEG-13).
//!
//! Session cookie `uptime_session`:
//! `base64url(expiry_unix, 8-byte BE) ++ "." ++ hex(hmac_sha256(session_key, expiry_unix_bytes))`
//! where `session_key = sha256(app_password || ":" || encryption_key)`.
//!
//! - 12h TTL, HttpOnly, SameSite=Lax, Path=/, `Secure` when the
//!   request arrives with `x-forwarded-proto: https` (we never terminate
//!   TLS ourselves; without the header the cookie is not marked Secure so
//!   plain-HTTP Flexible/local deployments keep working — set the header at
//!   the proxy to get Secure).
//! - **Sliding renewal**: an authenticated request whose session has less
//!   than `RENEW_THRESHOLD_SECS` (6h, half the TTL) remaining gets a fresh
//!   12h cookie appended to the response by `require_auth`. The cookie value
//!   is self-contained, so renewal is one HMAC — no storage, no new cookie
//!   name. The CSRF token is independent of the session expiry, so renewal
//!   does not invalidate tokens embedded in already-rendered pages.
//! - Constant-time password verification (both sides hashed to 32 bytes
//!   first, then compared with a fold — no early exit).
//! - Login rate limiting: 5 failed attempts inside a 60s sliding window
//!   lock the source IP out for 60s (in-memory, per process). The lockout
//!   message and the wrong-password message differ only after a lockout;
//!   wrong-password copies are identical for all failures.
//! - `X-Forwarded-For` is honored for rate limiting **only** when the
//!   socket peer is loopback (the normal single-proxy deployment); from any
//!   other peer the header is ignored, because otherwise a client could
//!   spoof its lockout key with one header. The first (leftmost)
//!   `X-Forwarded-For` entry is used, matching single-trusted-proxy
//!   semantics; an unparseable header falls back to the peer IP.
//! - CSRF for mutating routes lives in `web::csrf` (stateless double
//!   submit); login is intentionally CSRF-exempt (pre-session, SameSite=Lax).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::extract::ConnectInfo;
use axum::extract::{Form, FromRequestParts, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::state::{AppState, SharedState};
use crate::web::templates;

const SESSION_COOKIE: &str = "uptime_session";
const SESSION_TTL_SECS: i64 = 12 * 3600;
/// Reissue the session cookie when less than this remains (half the TTL).
pub(crate) const RENEW_THRESHOLD_SECS: i64 = 6 * 3600;
const MAX_FAILS: usize = 5;
const FAIL_WINDOW: Duration = Duration::from_secs(60);

type HmacSha256 = Hmac<Sha256>;

/// Session proof carried from `require_auth` into handlers via extensions.
#[derive(Clone, Copy, Debug)]
pub struct SessionInfo {
    pub expiry_unix: i64,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn unix_to_bytes(expiry: i64) -> [u8; 8] {
    (expiry as u64).to_be_bytes()
}

fn session_signature(session_key: &[u8; 32], expiry_unix: i64) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(session_key).expect("HMAC accepts any key length");
    mac.update(&unix_to_bytes(expiry_unix));
    mac.finalize().into_bytes().into()
}

/// Mint the cookie value for a session expiring at `expiry_unix`.
pub fn sign_session(session_key: &[u8; 32], expiry_unix: i64) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(unix_to_bytes(expiry_unix)),
        hex::encode(session_signature(session_key, expiry_unix))
    )
}

/// Verify a cookie value; returns the session expiry when valid.
pub fn verify_session(session_key: &[u8; 32], cookie_value: &str) -> Option<i64> {
    let (payload_b64, sig_hex) = cookie_value.split_once('.')?;
    let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    if payload.len() != 8 {
        return None;
    }
    let mut expiry_bytes = [0u8; 8];
    expiry_bytes.copy_from_slice(&payload);
    let expiry_unix = u64::from_be_bytes(expiry_bytes) as i64;
    let provided_sig = hex::decode(sig_hex).ok()?;
    if provided_sig.len() != 32 {
        return None;
    }
    let expected = session_signature(session_key, expiry_unix);
    let matches = expected
        .iter()
        .zip(provided_sig.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0;
    if !matches {
        return None;
    }
    if expiry_unix <= now_unix() {
        return None;
    }
    Some(expiry_unix)
}

/// Extract the `uptime_session` cookie from the raw Cookie header.
fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        let mut parts = pair.splitn(2, '=');
        let name = parts.next()?.trim();
        if name == SESSION_COOKIE {
            return parts.next().map(str::trim).map(str::to_string);
        }
    }
    None
}

/// Is the request authenticated? Returns session info when valid.
pub fn authenticate(state: &AppState, headers: &HeaderMap) -> Option<SessionInfo> {
    let cookie = session_cookie(headers)?;
    let expiry = verify_session(&state.session_key, &cookie)?;
    Some(SessionInfo {
        expiry_unix: expiry,
    })
}

/// Set-Cookie value for a fresh 12h session.
pub fn session_set_cookie(state: &AppState, headers: &HeaderMap) -> (HeaderValue, i64) {
    let expiry = now_unix() + SESSION_TTL_SECS;
    let value = sign_session(&state.session_key, expiry);
    let secure = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false);
    let cookie = format!(
        "{SESSION_COOKIE}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_TTL_SECS}{secure}",
        secure = if secure { "; Secure" } else { "" },
    );
    (
        HeaderValue::from_str(&cookie).expect("cookie value is header-safe"),
        expiry,
    )
}

/// Set-Cookie value that clears the session cookie.
pub fn session_clear_cookie() -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
    ))
    .expect("static cookie is header-safe")
}

// ---------------------------------------------------------------------------
// Constant-time password check
// ---------------------------------------------------------------------------

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = Sha256::digest(a.as_bytes());
    let b = Sha256::digest(b.as_bytes());
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// Login rate limiting (in-memory, per source IP)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FailWindow {
    failures: Vec<Instant>,
}

fn throttler() -> &'static Mutex<HashMap<IpAddr, FailWindow>> {
    static THROTTLER: OnceLock<Mutex<HashMap<IpAddr, FailWindow>>> = OnceLock::new();
    THROTTLER.get_or_init(|| Mutex::new(HashMap::new()))
}

fn purge_old(w: &mut FailWindow, now: Instant) {
    w.failures.retain(|t| now.duration_since(*t) < FAIL_WINDOW);
}

/// `Some(remaining_secs)` when the IP is locked out.
pub(crate) fn lockout_remaining(ip: IpAddr) -> Option<u64> {
    let mut guard = throttler().lock().expect("throttler mutex poisoned");
    let now = Instant::now();
    let window = guard.get_mut(&ip)?;
    purge_old(window, now);
    if window.failures.len() >= MAX_FAILS {
        // Oldest failure in the window defines when the lockout expires.
        let oldest = window.failures.iter().min().copied().unwrap_or(now);
        Some(
            FAIL_WINDOW
                .as_secs()
                .saturating_sub(now.duration_since(oldest).as_secs())
                .max(1),
        )
    } else {
        None
    }
}

pub(crate) fn record_failure(ip: IpAddr) {
    let mut guard = throttler().lock().expect("throttler mutex poisoned");
    let now = Instant::now();
    let window = guard.entry(ip).or_default();
    purge_old(window, now);
    window.failures.push(now);
}

pub(crate) fn clear_failures(ip: IpAddr) {
    let mut guard = throttler().lock().expect("throttler mutex poisoned");
    guard.remove(&ip);
}

/// Resolve the client IP for rate limiting.
///
/// `peer` is the socket peer address. `x_forwarded_for` is the raw
/// `X-Forwarded-For` header, if present. The header is trusted **only**
/// when the peer is loopback (single trusted proxy on the same host);
/// otherwise it is ignored entirely. When trusted, the first (leftmost)
/// entry is used — the address closest to the original client as seen by
/// the proxy — and an unparseable value falls back to the peer.
pub(crate) fn client_ip_from(peer: IpAddr, x_forwarded_for: Option<&str>) -> IpAddr {
    if !peer.is_loopback() {
        return peer;
    }
    let Some(raw) = x_forwarded_for else {
        return peer;
    };
    raw.split(',')
        .next()
        .map(str::trim)
        .and_then(|first| first.parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let xff = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Ok(Self(client_ip_from(peer, xff.as_deref())))
    }
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// `require_auth` wraps every non-public route.
///
/// Two gates, in order:
/// 1. **Session**: absent/invalid cookie → 303 redirect to `/login` (never
///    4xx — browsers and htmx both handle a redirect-to-login gracefully).
/// 2. **CSRF**: for mutating methods (anything but GET/HEAD/OPTIONS) the
///    double-submit token must verify — either the `X-CSRF-Token` header or
///    the `csrf_token` field of an `application/x-www-form-urlencoded` body.
///    Failure → 403 with a minimal HTML page. A urlencoded form body is read
///    and rebuilt, so downstream extractors see it unchanged.
pub async fn require_auth(
    State(state): State<SharedState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let Some(session) = authenticate(&state, &parts.headers) else {
        return Redirect::to("/login").into_response();
    };
    // Renewal mints the cookie from the *original* request headers (only the
    // `x-forwarded-proto` value matters, for the `Secure` attribute).
    let headers_snapshot = parts.headers.clone();

    let mutating = !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
    if !mutating {
        let mut request = axum::extract::Request::from_parts(parts, body);
        request.extensions_mut().insert(session);
        let response = next.run(request).await;
        return maybe_append_renewed_cookie(&state, &headers_snapshot, session, response);
    }

    let headers = parts.headers.clone();
    let (parts, body, form_token) = match read_body_if_urlencoded(parts, body).await {
        Ok(ok) => ok,
        Err(response) => return *response,
    };
    if !crate::web::csrf::verify_request(&state, &headers, form_token.as_deref()) {
        return crate::web::templates::error_page(
            StatusCode::FORBIDDEN,
            "403",
            "Forbidden — invalid or missing CSRF token. Reload the page and try again.",
        );
    }
    let mut request = axum::extract::Request::from_parts(parts, body);
    request.extensions_mut().insert(session);
    let response = next.run(request).await;
    maybe_append_renewed_cookie(&state, &headers_snapshot, session, response)
}

/// Sliding session renewal: when less than [`RENEW_THRESHOLD_SECS`] of the
/// session's TTL remains, append a fresh 12h `uptime_session` cookie to the
/// response. No-op otherwise. Self-contained cookie — nothing stored.
fn maybe_append_renewed_cookie(
    state: &AppState,
    original_headers: &HeaderMap,
    session: SessionInfo,
    response: Response,
) -> Response {
    if session.expiry_unix - now_unix() >= RENEW_THRESHOLD_SECS {
        return response;
    }
    let (cookie, _expiry) = session_set_cookie(state, original_headers);
    let mut response = response;
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

/// Read a urlencoded form body (bounded) and extract the `csrf_token` field.
/// Non-urlencoded bodies pass through untouched; the token must then come
/// from the `X-CSRF-Token` header.
async fn read_body_if_urlencoded(
    parts: axum::http::request::Parts,
    body: axum::body::Body,
) -> Result<(axum::http::request::Parts, axum::body::Body, Option<String>), Box<Response>> {
    let is_form = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);
    if !is_form {
        return Ok((parts, body, None));
    }
    let bytes = match axum::body::to_bytes(body, 64 * 1024 + 1024).await {
        Ok(b) => b,
        Err(_) => {
            return Err(Box::new(
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "form body exceeds the 64 KB limit",
                )
                    .into_response(),
            ));
        }
    };
    let token = parse_urlencoded_field(&bytes, b"csrf_token");
    Ok((parts, axum::body::Body::from(bytes), token))
}

fn parse_urlencoded_field(bytes: &[u8], key: &[u8]) -> Option<String> {
    for pair in bytes.split(|b| *b == b'&') {
        let mut kv = pair.splitn(2, |b| *b == b'=');
        let k = kv.next()?;
        let v = kv.next().unwrap_or(b"");
        if percent_decode(k).as_slice() == key {
            return Some(percent_decode_string(v));
        }
    }
    None
}

fn hex_digit(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 3 <= bytes.len() => {
                match (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push(hi * 16 + lo);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn percent_decode_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&percent_decode(bytes)).into_owned()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: String,
}

#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
}

async fn login_page(headers: HeaderMap, State(state): State<SharedState>) -> Response {
    if authenticate(&state, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    render_login("", StatusCode::OK)
}

fn render_login(error: &str, status: StatusCode) -> Response {
    match templates::render_ok(&LoginPage {
        error: error.to_string(),
    }) {
        Ok(html) => (status, html).into_response(),
        Err(e) => IntoResponse::into_response(e),
    }
}

async fn login_submit(
    State(state): State<SharedState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if let Some(_remaining) = lockout_remaining(ip) {
        return render_login(
            "Too many failed attempts. Try again in a minute.",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    if !constant_time_eq(form.password.trim(), state.app_password.trim()) {
        record_failure(ip);
        // Identical copy for every failure — no hint whether the user exists.
        return render_login("Invalid credentials", StatusCode::OK);
    }
    clear_failures(ip);
    let (cookie, _expiry) = session_set_cookie(&state, &headers);
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}

async fn logout(State(_state): State<SharedState>) -> Response {
    let mut response = Redirect::to("/login").into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_clear_cookie());
    response
}

/// Routes: registers GET/POST /login and POST /logout.
pub fn build_login_routes() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/login", axum::routing::get(login_page).post(login_submit))
        .route("/logout", axum::routing::post(logout))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xff_trusted_when_peer_is_loopback() {
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            client_ip_from(peer, Some("203.0.113.9")),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // First (leftmost) entry wins; later proxies append theirs.
        assert_eq!(
            client_ip_from(peer, Some("203.0.113.9, 10.0.0.1, 127.0.0.1")),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // Whitespace tolerated.
        assert_eq!(
            client_ip_from(peer, Some("  198.51.100.4 , 10.0.0.1")),
            "198.51.100.4".parse::<IpAddr>().unwrap()
        );
        // IPv6 entry.
        assert_eq!(
            client_ip_from(peer, Some("2001:4860:4860::8888")),
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn xff_ignored_when_peer_is_not_loopback() {
        // A direct client cannot spoof its lockout key with a header.
        let peer = "192.0.2.55".parse::<IpAddr>().unwrap();
        assert_eq!(client_ip_from(peer, Some("203.0.113.9")), peer);
        let peer6 = "2001:db8::1".parse::<IpAddr>().unwrap();
        assert_eq!(client_ip_from(peer6, Some("203.0.113.9")), peer6);
        let private_peer = "10.1.2.3".parse::<IpAddr>().unwrap();
        assert_eq!(client_ip_from(private_peer, Some("8.8.8.8")), private_peer);
    }

    #[test]
    fn xff_unparseable_falls_back_to_loopback_peer() {
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(client_ip_from(peer, Some("garbage")), peer);
        assert_eq!(client_ip_from(peer, Some("")), peer);
        assert_eq!(client_ip_from(peer, Some("a.b.c.d, 10.0.0.1")), peer);
    }

    #[test]
    fn no_xff_header_yields_peer() {
        let peer = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert_eq!(client_ip_from(peer, None), peer);
    }
}
