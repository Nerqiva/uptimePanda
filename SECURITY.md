# Security notes — uptimePanda

## Scope and authorized use

uptimePanda is a keep-alive / synthetic-monitoring tool. **Monitor only
websites you own or are explicitly authorized to monitor.** The dashboard
carries the same reminder (footer), and the login page states it as well.
There are no anti-detection, fingerprint-spoofing, CAPTCHA-bypass or proxy
rotation features, by design and by product requirement.

## Reporting

Security issues: open a private security advisory on the GitHub repository
(Nerqiva/uptimePanda). Do not file public issues for vulnerabilities.

## Threat model — DNS rebinding (residual risk, accepted for v1)

`security::validate_target` resolves the configured hostname to its A/AAAA
records and rejects the target unless **every** answer is publicly
routable; the executor re-resolves the **final** URL after navigation
(`validate_redirect_target`) and aborts the visit when it violates the
policy. This two-phase check is the designed mitigation for redirect- and
rebinding-based SSRF.

Residual risk: the two checks observe DNS at two different instants. A
hostile authoritative nameserver could answer publicly for the first lookup
and a private address for the second (TTL-0 rebinding). In that window the
browser process (which performs its own resolution when navigating) could
reach an internal address. This is accepted for v1 because:

- the second recheck happens **after** navigation, before any content is
  recorded, persisted or interacted with, and aborts the visit with
  outcome `navigation_error` ("redirect target violates URL safety
  policy");
- redirect chains to private addresses are therefore observable in
  `visit_history` (final URL) and abort rather than silently succeeding;
- deployment guidance is unchanged: do not expose the app beyond trusted
  networks, and do not configure targets you do not own.

Hardening candidates for a later segment: pin the resolver answers into the
browser's connection (not possible with the Lightpanda CDP API as of
Phase 0), or perform navigation against a pre-resolved IP with an explicit
`Host` header (rejected: breaks TLS SNI for virtually every target).

## Session and cookie handling

- `uptime_session`: HttpOnly, SameSite=Lax, Path=/, `Secure` when the
  request arrives with `x-forwarded-proto: https`; 12h TTL with sliding
  renewal (reissued when less than 6h remains). Value = base64url expiry +
  HMAC-SHA256 signature — self-contained, no server-side store.
- CSRF: stateless double-submit (`x-csrf-token` header or `csrf_token`
  field, HMAC of the session key). See `src/web/csrf.rs` for the full
  threat model.
- Password verification is constant-time; login is rate limited (5 fails /
  60s per source IP, in-memory; `X-Forwarded-For` honored only from a
  loopback peer).
- Secret values (`APP_PASSWORD`, `ENCRYPTION_KEY`, cookie contents) are
  never logged or rendered; `error_message` and log fields pass through
  `redact_message` before persistence (query/fragment stripped, secret
  `key=value` assignments scrubbed, 400-char cap).
- Cookie jars at rest are AES-256-GCM encrypted (`enc:v1:` envelope, key =
  scrypt(`ENCRYPTION_KEY`, app salt)); raw column contents are verified to
  never contain plaintext in the SEG-07 test suite
  (`browser::sessions::tests::encryption_at_rest_no_plaintext_in_rows`).

## Response headers

Every response carries `X-Frame-Options: DENY`, `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer`, a strict CSP
(`default-src 'self'`; no `unsafe-inline` — all page JS lives in
`/public/app.js`), `Cache-Control: no-store` unless the response opted into
its own caching (`/public/*` sets `max-age=3600`), and
`Strict-Transport-Security` only behind an HTTPS-terminating proxy that
sets `x-forwarded-proto: https`.
