# Changelog

All notable changes to uptimePanda are documented here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Versioning and releases

uptimePanda versions are **CalVer**: `YYYY.MM.DD.N-alpha` (for example
`2026.11.09.1-alpha`), where `N` is the per-day release counter. All releases
are **GitHub prereleases** with the `-alpha` stability suffix — there is no
stable track. `VERSION` holds the CalVer string; `Cargo.toml` carries a
monotonic SemVer projection (`YYYY.M.D-alpha.N`) because Cargo requires SemVer;
`README.md` carries the same version in its `<!-- version:start -->` block.

`.github/workflows/release.yml` automates the release side: on every push to
`main` it computes the next CalVer, rewrites `VERSION`, `Cargo.toml` and the
README version block, commits the bump as `github-actions[bot]`
(`chore(release): <version> [skip ci]`) and creates the prerelease.

This changelog is **curated, not automated** — release.yml deliberately does
not rewrite it. When a release is cut, the curator moves items from
`[Unreleased]` into its `[YYYY.MM.DD.N-alpha]` section.

## [Unreleased]

Everything below is implemented on `main` and verified locally
(fmt → clippy → test → release build), but has not shipped as a versioned
release yet.

### Added

- **Dashboard** — server-rendered HTMX + Askama UI on a dark-navy design
  system (Emerald `#34d399` accent): overview with live polling fragments,
  websites CRUD with add/edit modal, profiles page, history with pagination and
  outcome filter, system page (RSS/CPU/uptime, backups, restart), settings
  page with all tunables and **Restore defaults**.
- **Monitoring core** — persistent Lightpanda child process with
  memory-based recycling (default 200 MB RSS) and crash recovery; sequential
  profile lifecycle (single-context Lightpanda); per-profile AES-256-GCM
  cookie jars (`enc:v1:` envelope, scrypt-derived key).
- **Scheduler** — in-memory priority queue backed by SQLite
  (`scheduler_state` + lease-based claiming), uniform interval jitter,
  per-website active monitoring windows with IANA timezones, pause/resume,
  manual "Visit now", retry on `timeout`/`navigation_error` (+60s/+300s,
  max 2), boot recovery of stale `running` jobs, bounded queue
  (`max_queue_length`, default 32) and a single browser worker.
- **Interaction engine** — ordered, bounded synthetic journeys
  (`navigate`, `wait_duration`, `wait_selector`, `wait_js`, `scroll`, `click`,
  `rotate`, `end_session`); save-time validation with click-selector and
  `wait_js` denylists, selector length cap, sequence size cap and a session
  time budget; basic mode (navigate → hold → close) when no sequence is
  configured.
- **Settings** — all 23 `application_settings` keys seeded and validated,
  tuned for 512 MB / 0.15 vCPU, grouped Browser & memory / Navigation & visits /
  Scheduler & interactions / History & database / Logging; hot-applied where
  safe; `concurrent_visits` pinned to 1.
- **Persistence** — SQLite (WAL) as the sole database; schema with
  forward-only `user_version` migrations; daily retention
  (`history_retention_days`, default 7); `browser_events` trimmed to 500 rows;
  `VACUUM INTO` backups; validated restore with durable `restore_pending`
  marker and System-page acknowledgement flow.
- **Security** — session cookie auth (`uptime_session`, 12h TTL, sliding
  renewal, constant-time password check, 5-fails/60s per-IP login lockout);
  CSRF double-submit; strict CSP (no `unsafe-inline`); full
  `X-Frame-Options`/`X-Content-Type-Options`/`Referrer-Policy`/`Cache-Control`
  headers; SSRF guard (scheme allowlist, host-blocking for RFC 1918/loopback/
  link-local/metadata v4+v6, DNS resolution check, post-navigation re-check of
  the final URL); secret redaction in logs; localhost-only CDP; authorized-use
  notices in README, footer and login page.
- **Infrastructure** — multi-stage Dockerfile (Debian `stable-slim` glibc
  runtime, Lightpanda resolved to latest at build time with SHA-256
  verification, non-root user, `/health` HEALTHCHECK, `/app/data` volume);
  CI workflow (fmt → clippy → test → release build → multi-arch GHCR push,
  `linux/amd64,linux/arm64`); CalVer release workflow with automatic README
  version sync (prereleases only).
- **Docs** — this changelog, a full README (quick start, deploy notes with the
  Render/ephemeral-SQLite caveat, routes/settings/env tables, persistence
  model, security summary, architecture, troubleshooting), `SECURITY.md`,
  `docs/phase0-validation.md` (Lightpanda 1.0.3 capability matrix), and a
  README drift-guard test (`tests/readme.rs`) enforcing routes/settings/env/
  version sync in CI.

### Security

- SSRF guard blocks cloud metadata endpoints (`169.254.169.254`,
  `fd00:ec2::254`, mapped `::ffff:` forms) and structurally-local hostnames;
  residual DNS-rebinding risk is documented and accepted for v1 (two-phase
  check: pre-navigation resolution + post-navigation re-validation).
- `wait_js` is not a sandbox; it is denylist-filtered (`fetch(`, `eval(`,
  `document.cookie`, …) and the residual risk is documented in `SECURITY.md`.
- UA presets are compatibility-test overrides only and are no-ops on
  Lightpanda 1.0.3; no anti-impersonation or fingerprint-spoofing surface
  exists by design.

[Unreleased]: https://github.com/Nerqiva/uptimePanda/commits/main
