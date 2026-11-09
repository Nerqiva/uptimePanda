//! URL / SSRF guard for outbound visits (SEG-10; full hardening lands in
//! SEG-13).
//!
//! The visit executor navigates the shared Lightpanda process to user-
//! configured URLs, so a target that resolves to an internal address would
//! expose loopback services, cloud metadata endpoints and RFC 1918 networks.
//! This module is the v1 guard shipped in SEG-10 because no visit may happen
//! safely without it; SEG-13 keeps it and layers auth/CSRF/redaction on top.
//!
//! Policy (`validate_target` / `validate_redirect_target`):
//!
//! - scheme must be `http` or `https`; any other scheme is rejected;
//! - a host is required, and userinfo (`user:pass@host`) is rejected;
//! - IP literals (after WHATWG normalization, so `http://2130706433/` and
//!   `http://0x7f.1/` are seen as `127.0.0.1`) must be publicly routable:
//!   loopback, private (RFC 1918), link-local (incl. `169.254.0.0/16` —
//!   cloud metadata), CGNAT, unspecified, documentation/reserved, multicast
//!   and benchmarking ranges are all rejected, for IPv4 and IPv6 (incl.
//!   IPv4-mapped `::ffff:a.b.c.d`, IPv4-compatible deprecated space, NAT64
//!   `64:ff9b::/96`, ULA `fc00::/7`, link-local `fe80::/10`, Teredo/ORCHID/
//!   documentation ranges);
//! - hostnames that are structurally local (`localhost`, `*.localhost`,
//!   `*.internal`, `*.local`, bare `metadata`) are rejected;
//! - otherwise the host is resolved with the system resolver
//!   (`std::net::ToSocketAddrs` on a blocking thread) and **every**
//!   resulting A/AAAA address must be public. One private record fails the
//!   whole target — this blocks DNS round-robin answers with a private
//!   entry. Residual DNS-rebinding risk is documented and accepted for v1
//!   (the final URL is re-validated after navigation, which is the second
//!   line of defence);
//! - after navigation the **final** URL must pass the same checks; a
//!   violation aborts the visit with `navigation_error` ("redirect target
//!   violates URL safety policy").
//!
//! Error messages carry the reason and at most the host — never credentials,
//! query strings or fragments. They are safe to record in `visit_history`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use url::Url;

/// Reason a target was rejected by the guard. Kept as a plain string — the
/// messages are built to be record-safe (host only, never query/userinfo).
pub type UrlSafetyError = String;

/// Hostnames (exact, case-insensitive) or suffixes (with leading dot) that
/// are never valid monitoring targets on any network.
const BLOCKED_HOSTNAMES: &[&str] = &["localhost", "metadata"];
const BLOCKED_HOSTNAME_SUFFIXES: &[&str] = &[".localhost", ".internal", ".local", ".lan"];

// ---------------------------------------------------------------------------
// Public helpers for privacy-safe rendering
// ---------------------------------------------------------------------------

/// Render a URL as `scheme://host[:port]/path` — no query, no fragment, no
/// userinfo. This is the ONLY form of URL that may appear in logs or in
/// `visit_history.final_url`.
pub fn host_path(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let mut out = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    let path = url.path();
    if path.is_empty() {
        out.push('/');
    } else {
        out.push_str(path);
    }
    out
}

/// Query-free host+path form of a raw URL string; falls back to
/// truncation-safe handling when the value does not parse (anything from the
/// first `?` / `#` on is dropped). Used for error records.
pub fn host_path_lossy(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(u) => host_path(&u),
        Err(_) => match raw.find(['?', '#']) {
            Some(idx) => raw[..idx].to_string(),
            None => raw.to_string(),
        },
    }
}

/// Maximum length of a recorded `error_message`.
pub const MAX_ERROR_MESSAGE_LEN: usize = 400;

/// Keys whose `=value` assignments are redacted from recorded messages.
const REDACTED_ASSIGNMENT_KEYS: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "authorization",
    "auth",
    "session",
    "session_id",
    "sessionid",
    "cookie",
    "credential",
];

/// Scrub a raw error/log string for persistence or logging:
///
/// 1. every `http://` / `https://` URL in the text loses its query and
///    fragment (credentials in userinfo are dropped too);
/// 2. `key=value` assignments whose key (case-insensitive, ignoring
///    surrounding punctuation) names a known secret are replaced with
///    `key=[redacted]`;
/// 3. the result is truncated to `max` bytes on a char boundary.
pub fn redact_message(raw: &str, max: usize) -> String {
    let stripped = strip_url_queries(raw);
    let redacted = redact_sensitive_assignments(&stripped);
    truncate_chars(&redacted, max)
}

fn strip_url_queries(raw: &str) -> String {
    // Boundary chars that terminate a URL inside arbitrary text (incl.
    // JSON/HTML-ish contexts like {"url":"https://x/?a=b"}).
    const BOUNDARY: &[char] = &[
        '\0', ' ', '\t', '\n', '\r', '"', '\'', ')', ']', '}', '<', '>',
    ];
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let rest = &raw[i..];
        let scheme_len = if rest.starts_with("http://") {
            Some(7)
        } else if rest.starts_with("https://") {
            Some(8)
        } else {
            None
        };
        if let Some(start_scheme) = scheme_len {
            // Find the end of the URL token.
            let mut end = i + start_scheme;
            while end < bytes.len() {
                let ch = raw[end..].chars().next().expect("valid boundary");
                if BOUNDARY.contains(&ch) || ch.is_whitespace() {
                    break;
                }
                // Advance by the full char, not one byte.
                end += ch.len_utf8();
            }
            let token = &raw[i..end];
            match Url::parse(token) {
                Ok(u) => out.push_str(&host_path(&u)),
                Err(_) => {
                    // Not parseable: keep the token but cut query/fragment.
                    match token.find(['?', '#']) {
                        Some(idx) => out.push_str(&token[..idx]),
                        None => out.push_str(token),
                    }
                }
            }
            i = end;
        } else {
            // Copy one char (not one byte) verbatim.
            let ch = rest.chars().next().expect("i < len");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn redact_sensitive_assignments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (idx, token) in text.split_whitespace().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        out.push_str(&redact_assignment(token));
    }
    out
}

fn redact_assignment(token: &str) -> String {
    let Some(eq) = token.find('=') else {
        return token.to_string();
    };
    let key = token[..eq]
        .trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .to_ascii_lowercase();
    if REDACTED_ASSIGNMENT_KEYS.contains(&key.as_str()) {
        format!("{}=[redacted]", &token[..eq])
    } else {
        token.to_string()
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max.saturating_sub(1)).chain(['…']).collect()
}

// ---------------------------------------------------------------------------
// Target validation
// ---------------------------------------------------------------------------

/// Validate `raw` as a visit target. Returns the parsed, safe URL.
///
/// See the module docs for the full policy. Fails closed: any doubt
/// (unresolvable host, non-public record) rejects the target.
pub async fn validate_target(raw: &str) -> Result<Url, UrlSafetyError> {
    validate_url(raw, "target").await
}

/// Same policy as [`validate_target`], used for the post-navigation URL.
/// A violation aborts the visit with `navigation_error`.
pub async fn validate_redirect_target(raw: &str) -> Result<Url, UrlSafetyError> {
    validate_url(raw, "redirect target").await
}

async fn validate_url(raw: &str, what: &str) -> Result<Url, UrlSafetyError> {
    let url = check_static(raw, what)?;
    // DNS resolution check for non-IP-literal hosts.
    let is_ip_literal = matches!(url.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)));
    if !is_ip_literal {
        let host = url
            .host_str()
            .ok_or_else(|| format!("{what} has no host"))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(80);
        let addrs = resolve_public(&host, port).await?;
        if addrs.is_empty() {
            return Err(format!("{what} host resolves to no addresses"));
        }
        for addr in addrs {
            if !is_public_ip(addr) {
                return Err(format!(
                    "{what} host resolves to a non-public address ({addr})"
                ));
            }
        }
    }
    Ok(url)
}

/// Resolve `host`/`port` on a blocking thread and return every address.
/// Split out so the unit tests never touch the resolver and the live path
/// is exercised by one `#[ignore]`d test.
async fn resolve_public(host: &str, port: u16) -> Result<Vec<IpAddr>, UrlSafetyError> {
    let host = host.to_string();
    let joined = tokio::task::spawn_blocking(move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.map(|a| a.ip()).collect::<Vec<IpAddr>>())
    })
    .await
    .map_err(|_| "DNS resolution task failed".to_string())?;
    joined.map_err(|_| "DNS resolution failed for host".to_string())
}

/// Static checks (no network): scheme, host presence, userinfo, IP-literal
/// publicity and structurally-local hostnames.
///
/// Exposed for unit tests; `validate_target`/`validate_redirect_target`
/// add the DNS check on top.
pub(crate) fn check_static(raw: &str, what: &str) -> Result<Url, UrlSafetyError> {
    let url = Url::parse(raw).map_err(|_| format!("{what} is not a valid URL"))?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "{what} uses scheme '{other}'; only http and https are allowed"
            ));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "{what} must not contain userinfo (user:password@host)"
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("{what} has no host"))?;
    if host.is_empty() {
        return Err(format!("{what} has no host"));
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) => {
            if !is_public_ipv4(ip) {
                return Err(format!("{what} host is a non-public IPv4 address"));
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if !is_public_ipv6(ip) {
                return Err(format!("{what} host is a non-public IPv6 address"));
            }
        }
        Some(url::Host::Domain(domain)) => {
            if is_blocked_hostname(domain) {
                return Err(format!("{what} host is a local or internal hostname"));
            }
        }
        None => return Err(format!("{what} has no host")),
    }
    Ok(url)
}

/// Is `domain` a structurally local hostname (exact match against a blocklist
/// of names, or carrying a blocked suffix)? Case-insensitive.
pub(crate) fn is_blocked_hostname(domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if BLOCKED_HOSTNAMES.contains(&d.as_str()) {
        return true;
    }
    BLOCKED_HOSTNAME_SUFFIXES
        .iter()
        .any(|suffix| d.ends_with(suffix))
}

/// Publicly routable check for any IP address.
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // This-network 0.0.0.0/8
    if o[0] == 0 {
        return false;
    }
    // RFC 1918 private
    if o[0] == 10 {
        return false;
    }
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return false;
    }
    if o[0] == 192 && o[1] == 168 {
        return false;
    }
    // CGNAT 100.64.0.0/10
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return false;
    }
    // Loopback (127.0.0.0/8) and link-local (169.254.0.0/16 — incl. the
    // 169.254.169.254 cloud metadata address)
    if o[0] == 127 || (o[0] == 169 && o[1] == 254) {
        return false;
    }
    // IETF protocol assignments 192.0.0.0/24, benchmarking 198.18.0.0/15
    if (o[0] == 192 && o[1] == 0 && o[2] == 0) || (o[0] == 198 && (18..=19).contains(&o[1])) {
        return false;
    }
    // Documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        return false;
    }
    // 6to4 relay anycast 192.88.99.0/24 (deprecated)
    if o[0] == 192 && o[1] == 88 && o[2] == 99 {
        return false;
    }
    // Multicast 224.0.0.0/4 and reserved 240.0.0.0/4 (incl. 255.255.255.255)
    if o[0] >= 224 {
        return false;
    }
    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    // :: (unspecified) and ::1 (loopback)
    if ip.is_unspecified() || ip.is_loopback() {
        return false;
    }
    // IPv4-mapped ::ffff:a.b.c.d — defer to the embedded v4 rules.
    if seg[0..5] == [0, 0, 0, 0, 0] && seg[5] == 0xffff {
        let embedded = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        );
        return is_public_ipv4(embedded);
    }
    // Deprecated IPv4-compatible ::a.b.c.d (::/96 minus :: and ::1, already
    // handled) — reserved, reject outright.
    if seg[0..6] == [0, 0, 0, 0, 0, 0] {
        return false;
    }
    // NAT64 well-known prefix 64:ff9b::/96 — defer to the embedded v4.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        let embedded = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        );
        return is_public_ipv4(embedded);
    }
    // NAT64 local-use 64:ff9b:1::/48 (RFC 8215)
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 1 {
        return false;
    }
    // Discard-only 100::/64 (RFC 6666)
    if seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 {
        return false;
    }
    // Teredo 2001::/32 and ORCHIDv2 2001:10::/28
    if seg[0] == 0x2001 && (seg[1] == 0 || (0x0010..=0x001f).contains(&seg[1])) {
        return false;
    }
    // Documentation 2001:db8::/32
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return false;
    }
    // Link-local fe80::/10
    if (seg[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // ULA fc00::/7 (incl. fd00:ec2::254, the AWS/GCP/Azure v6 metadata range)
    if (seg[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // Multicast ff00::/8
    if (seg[0] & 0xff00) == 0xff00 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn ipv4_matrix() {
        let blocked = [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.53.0.9",
            "169.254.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "192.168.255.255",
            "198.18.0.7",
            "198.19.255.255",
            "198.51.100.9",
            "203.0.113.77",
            "224.0.0.1",
            "239.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
        ];
        for ip in blocked {
            assert!(!is_public_ip(v4(ip)), "{ip} must be blocked");
        }
        let public = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.32.0.1",
            "11.0.0.1",
        ];
        for ip in public {
            assert!(is_public_ip(v4(ip)), "{ip} must be allowed");
        }
    }

    #[test]
    fn ipv6_matrix() {
        let blocked = [
            "::",                     // unspecified
            "::1",                    // loopback
            "::ffff:127.0.0.1",       // mapped loopback
            "::ffff:10.1.2.3",        // mapped private
            "::ffff:169.254.169.254", // mapped metadata
            "::127.0.0.1",            // deprecated IPv4-compatible
            "64:ff9b::7f00:1",        // NAT64 of 127.0.0.1
            "64:ff9b::a00:1",         // NAT64 of 10.0.0.1
            "64:ff9b:1::1",           // NAT64 local-use
            "100::",                  // discard-only
            "2001::1",                // Teredo
            "2001:10::1",             // ORCHIDv2
            "2001:db8::1",            // documentation
            "fe80::1",                // link-local
            "febf::1",                // link-local (upper bound of fe80::/10)
            "fc00::1",                // ULA
            "fd00:ec2::254",          // ULA — cloud metadata (IPv6)
            "ff02::1",                // multicast
        ];
        for ip in blocked {
            assert!(!is_public_ip(v6(ip)), "{ip} must be blocked");
        }
        let public = [
            "2606:4700:4700::1111", // Cloudflare
            "2001:4860:4860::8888", // Google DNS
            "::ffff:8.8.8.8",       // mapped public
            "64:ff9b::808:808",     // NAT64 of 8.8.8.8
        ];
        for ip in public {
            assert!(is_public_ip(v6(ip)), "{ip} must be allowed");
        }
    }

    #[test]
    fn check_static_scheme_host_userinfo() {
        for bad in [
            "ftp://example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,hi",
            "gopher://example.com/",
            "http://",
            "https://user:pass@example.com/",
            "https://user@example.com/",
        ] {
            assert!(
                check_static(bad, "target").is_err(),
                "{bad} must be rejected"
            );
        }
        // WHATWG normalizes "http:///path" to host "path" — the static check
        // passes it, and the DNS stage rejects it (fail-closed) since the
        // name does not resolve.
        assert_eq!(
            check_static("http:///path", "target")
                .ok()
                .unwrap()
                .host_str(),
            Some("path")
        );
        assert!(check_static("https://example.com/", "target").is_ok());
        assert!(check_static("http://example.com:8080/path", "target").is_ok());
    }

    #[test]
    fn check_static_ip_literal_matrix() {
        for bad in [
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/admin",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://172.16.0.9/",
            "http://169.254.169.254/latest/meta-data",
            "http://169.254.170.2/",
            "http://[::1]/",
            "http://[fc00::1]/",
            "http://[fd00:ec2::254]/",
            "http://[fe80::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://2130706433/",   // 127.0.0.1 as a single dword (WHATWG)
            "http://0x7f.1/",       // 127.0.0.1 in hex shorthand (WHATWG)
            "https://192.0.2.1/",   // TEST-NET-1
            "https://203.0.113.9/", // TEST-NET-3
        ] {
            assert!(
                check_static(bad, "target").is_err(),
                "{bad} must be rejected"
            );
        }
        for good in [
            "https://8.8.8.8/",
            "http://93.184.216.34/",
            "https://[2606:4700:4700::1111]/",
        ] {
            assert!(check_static(good, "target").is_ok(), "{good} must pass");
        }
    }

    #[test]
    fn check_static_blocked_hostnames() {
        for bad in [
            "http://localhost/",
            "https://LOCALHOST:8443/",
            "http://foo.localhost/",
            "http://metadata/",
            "http://metadata.google.internal/",
            "http://service.internal/",
            "http://printer.local/",
            "http://nas.lan/",
            "http://Example.Internal/path",
        ] {
            assert!(
                check_static(bad, "target").is_err(),
                "{bad} must be rejected"
            );
        }
        assert!(is_blocked_hostname("LOCALHOST"));
        assert!(is_blocked_hostname("a.internal"));
        assert!(is_blocked_hostname("b.local.")); // trailing dot tolerated
        assert!(!is_blocked_hostname("internal.example.com"));
        assert!(!is_blocked_hostname("local.example.org"));
        assert!(!is_blocked_hostname("example.com"));
    }

    #[tokio::test]
    async fn validate_target_rejects_private_literal_before_any_io() {
        let err = validate_target("http://192.168.1.10/").await.unwrap_err();
        assert!(err.contains("non-public"), "{err}");
        let err = validate_redirect_target("http://169.254.169.254/")
            .await
            .unwrap_err();
        assert!(err.contains("redirect target"), "{err}");
    }

    #[tokio::test]
    async fn validate_target_rejects_local_hostnames() {
        assert!(validate_target("http://localhost:8080/").await.is_err());
        assert!(validate_target("http://foo.internal/").await.is_err());
    }

    #[ignore = "requires live DNS; run with --ignored"]
    #[tokio::test]
    async fn validate_target_live_example_com() {
        let url = validate_target("https://example.com/")
            .await
            .expect("example.com is public");
        assert_eq!(url.host_str(), Some("example.com"));
        assert!(
            validate_redirect_target("https://example.com/")
                .await
                .is_ok()
        );
    }

    #[test]
    fn redact_message_strips_url_queries() {
        let raw = "navigation failed: GET https://example.com/cb?token=abc123&id=7 failed";
        let out = redact_message(raw, 400);
        assert!(out.contains("https://example.com/cb"), "{out}");
        assert!(!out.contains("abc123"), "{out}");
        assert!(!out.contains('?'), "{out}");
    }

    #[test]
    fn redact_message_strips_json_embedded_urls() {
        let raw = r#"{"url":"https://evil.example.com/path?session=hunter2&x=1"}"#;
        let out = redact_message(raw, 400);
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("https://evil.example.com/path"), "{out}");
    }

    #[test]
    fn redact_message_redacts_sensitive_assignments() {
        let raw = "auth failed token=abc123 password=hunter2 ok=1 note=token=inside";
        let out = redact_message(raw, 400);
        assert!(out.contains("token=[redacted]"), "{out}");
        assert!(out.contains("password=[redacted]"), "{out}");
        assert!(!out.contains("abc123"), "{out}");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("ok=1"), "{out}");
    }

    #[test]
    fn redact_message_truncates_on_char_boundaries() {
        let raw = "é".repeat(500);
        let out = redact_message(&raw, 100);
        assert!(out.chars().count() <= 100);
        // Purely a test that it does not panic on multibyte boundaries.
        assert!(redact_message("hello", 400) == "hello");
    }

    #[test]
    fn host_path_strips_query_fragment_and_userinfo() {
        let u = Url::parse("https://user:pass@example.com:8443/a/b?c=d#frag").unwrap();
        assert_eq!(host_path(&u), "https://example.com:8443/a/b");
        let u2 = Url::parse("http://192.0.2.7/").unwrap();
        assert_eq!(host_path(&u2), "http://192.0.2.7/");
        assert_eq!(
            host_path_lossy("https://x.example.com/p?q=1#f"),
            "https://x.example.com/p"
        );
        assert_eq!(host_path_lossy("not a url?secret=1"), "not a url");
    }
}
