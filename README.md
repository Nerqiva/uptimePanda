# uptimePanda

Rust + Lightpanda lightweight synthetic website monitoring for 512 MB RAM / 0.15 vCPU.

<!-- version:start -->
**Version:** 2026.11.09.8-alpha ([changelog](CHANGELOG.md)) — released 2026.11.09 · [prerelease v2026.11.09.8-alpha](https://github.com/Nerqiva/uptimePanda/releases/tag/v2026.11.09.8-alpha)
<!-- version:end -->

> [!IMPORTANT]
> **Authorized use only.** uptimePanda monitors websites you own or are
> explicitly authorized to monitor. It performs ordinary, bounded browser
> visits — there are **no** anti-detection, fingerprint-spoofing, CAPTCHA-bypass
> or proxy-rotation features, by design and by product requirement. If you do
> not own the site or lack written authorization to probe it, do not monitor it.

## Features

- **Visit scheduling with jitter** — randomized revisit intervals inside
  per-website bounds (uniform in `[min_interval_seconds, max_interval_seconds]`),
  per-website active monitoring windows with IANA timezones, and SQLite-backed
  recovery of jobs that were `running` when the app stopped.
- **Browser profiles** — named, independently configured profiles (UA override,
  stored cookie jar, enabled/disabled) with sequential lifecycle management on
  the single-context Lightpanda browser.
- **Encrypted cookie jars** — per-profile cookie persistence, AES-256-GCM at
  rest (`enc:v1:` envelope), scrypt-derived key from `ENCRYPTION_KEY`.
- **Interaction engine** — bounded, explicitly configured synthetic journeys
  (navigate, waits, scroll, click, session rotation) validated at save time
  with a hard selector denylist. No arbitrary clicking, no form submission.
- **HTMX dashboard** — server-rendered pages and fragments (no SPA),
  dark-navy design system with an Emerald accent.
- **Resource limits** — the app is built to survive a 512 MB / 0.15 vCPU host:
  persistent Lightpanda child with memory-based recycling (default 200 MB RSS),
  a single browser worker, bounded queues and channels, and `/proc`-based RSS/CPU
  sampling.
- **Crash recovery** — a crashed or `kill -9`'d browser is detected and respawned
  automatically; unfinished visits are requeued from `scheduler_state`.

## Quick start

### Docker

```sh
docker run -d --name uptimepanda -p 8080:8080 \
  -v uptimepanda-data:/app/data \
  -e APP_PASSWORD=change-me-minimum-12-chars \
  -e ENCRYPTION_KEY=change-me-minimum-16-chars \
  ghcr.io/nerqiva/uptimepanda:latest
```

Then open <http://localhost:8080> and log in with `APP_PASSWORD`.

- The first CI push to `main` (or a `v*` tag) creates the GitHub Container
  Registry package; the package is public — no authentication is needed to
  pull it.
- Image tags: `latest` (default branch) and `YYYY.MM.DD.N-alpha` (one per
  release, e.g. `2026.11.09.1-alpha`).

### Docker Compose

```yaml
services:
  uptimepanda:
    image: ghcr.io/nerqiva/uptimepanda:latest
    ports:
      - "8080:8080"
    volumes:
      - uptimepanda-data:/app/data
    environment:
      APP_PASSWORD: change-me-minimum-12-chars
      ENCRYPTION_KEY: change-me-minimum-16-chars
    restart: unless-stopped

volumes:
  uptimepanda-data:
```

### From source

Prerequisites: a stable Rust toolchain (`rustup`) and the **`lightpanda`
binary on your `PATH`** (install instructions:
<https://lightpanda.io/>; release binaries are also on the
[Lightpanda releases page](https://github.com/lightpanda-io/browser/releases)).

```sh
git clone https://github.com/Nerqiva/uptimePanda.git
cd uptimePanda
APP_PASSWORD=change-me-minimum-12-chars \
ENCRYPTION_KEY=change-me-minimum-16-chars \
cargo run --release
# → http://127.0.0.1:8080
```

## Deploy notes

> [!WARNING]
> **Local SQLite on Render Free is NOT durable.** The filesystem is
> ephemeral, so the database (and any backup written next to it) disappears on
> every redeploy or restart. uptimePanda is not an always-on scheduler host on
> Render Free either — scheduled visits need a process that stays up. Use a
> host or disk layout that permits persistence (persistent disk, external
> volume), or a backup strategy that ships the database elsewhere.
> **The app does not fake traffic** to paper over downtime; if the process is
> down, no visits happen and `scheduler_state` tells the truth on the next
> boot.

Recommended: any always-on Linux VM or container host with at least 512 MB
RAM. A Docker volume mounted at `/app/data` is the persistence contract —
it holds the SQLite database (WAL mode) and the backups directory.

Behind a reverse proxy that terminates TLS, set `BIND_ADDR=0.0.0.0` and forward
`X-Forwarded-Proto: https` so the session cookie gets `Secure` and HSTS is sent.

## Configuration

All runtime configuration lives in the environment (deployment contract) or in
the database (everything tunable). There is exactly one way to set secrets: the
environment.

<!-- env:start -->
| Variable | Required | Default | Purpose |
|---|---|---|---|
| `APP_PASSWORD` | **yes** | — | Dashboard login password. Min 12 characters. Never logged; constant-time compared. |
| `ENCRYPTION_KEY` | **yes** | — | Passphrase for cookie encryption at rest (scrypt → AES-256-GCM). Min 16 characters. |
| `DATABASE_PATH` | no | `/app/data/uptimepanda.db` (container) · `./data/uptimepanda.db` (dev) | SQLite database file path. |
| `BACKUP_DIR` | no | `/app/data/backups` (container) · `./data/backups` (dev) | Directory for database backups. |
| `PORT` | no | `8080` | HTTP listen port. |
| `BIND_ADDR` | no | `127.0.0.1` (dev) · `0.0.0.0` (image) | Bind address. Containers need `0.0.0.0`. |
| `TZ` | no | `Asia/Omsk` | Timezone (IANA name); default for per-website active windows. |
| `RUST_LOG` | no | `info` | Log filter (`trace`/`debug`/`info`/`warn`/`error` or an EnvFilter directive). |
<!-- env:end -->

Everything else — memory thresholds, scheduler bounds, retention, interaction
limits — is a database setting edited on the **Settings** page
(`GET /settings`); changes hot-apply where safe and take effect after restart
otherwise. See the next section. (`APP_PASSWORD` min 12 characters and
`ENCRYPTION_KEY` min 16 characters are enforced at boot; the app refuses to
start otherwise.)

## Settings

All 23 keys live in the `application_settings` table, seeded idempotently at
boot with values tuned for 512 MB / 0.15 vCPU. The Settings page shows current
value, default, bounds and a one-line help text for each, grouped as below, and
offers **Restore defaults** (`POST /settings/restore-defaults`) which resets
all keys in one transaction. `concurrent_visits` is read-only and pinned to `1`
(single worker guarantee); `log_level` and `sqlite_maintenance_on_boot` take
effect after restart.

### Browser & memory

| Key | Default | Bounds | Help |
|---|---|---|---|
| `memory_warn_mb` | 160 | 64–320 | Browser RSS warning threshold (logs + dashboard badge) |
| `memory_restart_mb` | 200 | 96–384 | Browser RSS threshold that triggers a recycle |
| `browser_restart_timeout_s` | 15 | 1–120 | Max wait for graceful browser stop before SIGKILL |
| `browser_respawn_delay_s` | 5 | 1–30 | Pause before spawning a replacement browser |
| `concurrent_visits` | 1 | 1 (enforced) | Single worker; other values are rejected |
| `rss_poll_interval_s` | 5 | 1–60 | RSS/CPU sampling cadence |

### Navigation & visits

| Key | Default | Bounds | Help |
|---|---|---|---|
| `nav_timeout_s` | 15 | 5–120 | Hard timeout for page navigation |
| `visit_timeout_s` | 30 | 10–300 | Hard timeout for a whole visit |
| `max_session_seconds_cap` | 300 | 60–1800 | Absolute ceiling for any session |
| `default_min_interval_seconds` | 480 | 30–86400 | Default min seconds between visits (8 min) |
| `default_max_interval_seconds` | 780 | 30–86400 | Default max seconds between visits (13 min) |
| `default_min_session_seconds` | 15 | 5–3600 | Default min session length |
| `default_max_session_seconds` | 60 | 5–3600 | Default max session length |
| `ua_presets_enabled` | true | bool | UA preset overrides (compatibility testing only) |

### Scheduler & interactions

| Key | Default | Bounds | Help |
|---|---|---|---|
| `active_window_default` | 24h | `1h`–`168h` | Default monitoring window (`24h` = always, or `<N>h`) |
| `max_queue_length` | 32 | 1–256 | Bound on pending jobs; beyond this new jobs are rejected |
| `max_actions_per_sequence` | 50 | 1–100 | Ceiling on actions in an interaction sequence |
| `interaction_scroll_max_ops` | 20 | 1–100 | Safety bound on scroll operations |
| `interaction_click_wait_max_ms` | 10000 | 500–30000 | Safety bound on wait after a click |

### History & database

| Key | Default | Bounds | Help |
|---|---|---|---|
| `history_retention_days` | 7 | 1–365 | Days to keep visit history; cleanup runs daily |
| `sqlite_maintenance_on_boot` | true | bool | `PRAGMA optimize` + `wal_checkpoint(TRUNCATE)` on boot |
| `db_size_warn_mb` | 64 | 16–1024 | Dashboard warning when the SQLite file exceeds this |

### Logging

| Key | Default | Bounds | Help |
|---|---|---|---|
| `log_level` | info | `trace`\|`debug`\|`info`\|`warn`\|`error` | Log filter; restart required |

The machine-checked mirror of the same table (the drift guard in
`tests/readme.rs` asserts every key below appears here and in
`src/config.rs::SETTING_DEFAULTS`):

<!-- settings:start -->
| Key | Default | Bounds |
|---|---|---|
| `active_window_default` | `24h` | `1h`–`168h` |
| `browser_restart_timeout_s` | `15` | 1–120 |
| `browser_respawn_delay_s` | `5` | 1–30 |
| `concurrent_visits` | `1` | 1 (enforced) |
| `db_size_warn_mb` | `64` | 16–1024 |
| `default_max_interval_seconds` | `780` | 30–86400 |
| `default_max_session_seconds` | `60` | 5–3600 |
| `default_min_interval_seconds` | `480` | 30–86400 |
| `default_min_session_seconds` | `15` | 5–3600 |
| `history_retention_days` | `7` | 1–365 |
| `interaction_click_wait_max_ms` | `10000` | 500–30000 |
| `interaction_scroll_max_ops` | `20` | 1–100 |
| `log_level` | `info` | `trace`\|`debug`\|`info`\|`warn`\|`error` |
| `max_actions_per_sequence` | `50` | 1–100 |
| `max_queue_length` | `32` | 1–256 |
| `max_session_seconds_cap` | `300` | 60–1800 |
| `memory_restart_mb` | `200` | 96–384 |
| `memory_warn_mb` | `160` | 64–320 |
| `nav_timeout_s` | `15` | 5–120 |
| `rss_poll_interval_s` | `5` | 1–60 |
| `sqlite_maintenance_on_boot` | `true` | bool |
| `ua_presets_enabled` | `true` | bool |
| `visit_timeout_s` | `30` | 10–300 |
<!-- settings:end -->

## Routes

Every route registered in the router (`src/web/routes.rs`, plus the login pair
in `src/web/auth.rs`). Public routes do not require a session; all others
require the `uptime_session` cookie. Mutating routes additionally require the
CSRF double-submit token.

<!-- routes:start -->
| Route | Purpose |
|---|---|
| GET / | Overview page (totals, active monitors, browser status, next visits) |
| GET /fragments/overview | Overview fragment (HTMX poll, every 2s) |
| GET /fragments/system | System stats fragment (HTMX poll, every 2s) |
| GET /fragments/history-rows | History table rows fragment (HTMX pagination) |
| GET /websites | Websites page (table + add/edit modal) |
| POST /websites | Create a website monitor |
| PATCH /websites/{id} | Update a website monitor |
| DELETE /websites/{id} | Delete a website monitor |
| POST /websites/{id}/delete | Delete affordance for plain form posts |
| POST /websites/{id}/visit | Manual "Visit now" (runs even on paused sites) |
| POST /websites/{id}/pause | Pause scheduled visits (monitor stays configured) |
| POST /websites/{id}/resume | Resume scheduled visits |
| GET /websites/{id}/interactions | Interaction-sequence editor |
| POST /websites/{id}/interactions | Save/validate interaction sequence |
| POST /websites/{id}/interactions/clear | Delete the interaction sequence (back to basic mode) |
| GET /profiles | Profiles page (CRUD, jar stats, UA presets) |
| POST /profiles | Create a profile |
| PATCH /profiles/{id} | Update a profile |
| DELETE /profiles/{id} | Delete a profile (cascade-clears its cookie jar) |
| POST /profiles/{id}/delete | Delete affordance for plain form posts |
| POST /profiles/{id}/cookies/clear | Clear one profile's cookie jar |
| POST /profiles/cookies/clear-all | Clear every profile's cookie jar |
| GET /history | History page (paginated, filter by outcome) |
| GET /system | System page (RSS/CPU/uptime, backups, restart) |
| POST /system/restart | Recycle the Lightpanda process (manual) |
| GET /settings | Settings page (all 23 keys, grouped) |
| PATCH /settings | Update one setting (validated, hot-applied where safe) |
| POST /settings | Same as PATCH (plain-form alias) |
| POST /settings/restore-defaults | Reset all 23 settings to defaults |
| GET /api/system | Raw system stats as JSON (powers the dashboard) |
| POST /backup | Write a timestamped backup (`VACUUM INTO`) |
| POST /backup/restore | Upload a `.db` and restore it (marks restore-pending) |
| GET /backup/download | Download a backup (fresh snapshot, or `?path=…`) |
| POST /backup/delete | Delete a named backup file |
| POST /backup/restore/ack | Acknowledge a pending restore (clears the banner) |
| GET /health | Liveness probe `{"status":"ok","version":…}` (no DB write, no browser) |
| GET /login | Login page |
| POST /login | Password check (rate-limited: 5 fails → 60s lockout per IP) |
| POST /logout | Destroy the session |
| GET /public/{*path} | Vendored static assets (traversal-guarded, `max-age=3600`) |
<!-- routes:end -->

## Persistence model

Everything lives in a single SQLite database (WAL mode, `foreign_keys=ON`,
`busy_timeout=5000`, `synchronous=NORMAL`), typically at `/app/data/uptimepanda.db`
in a container volume. Tables:

| Table | Contents |
|---|---|
| `websites` | Monitor config: URL, enabled flag, profile assignment, interval/session bounds, active window + timezone |
| `browser_profiles` | Named profiles: UA selection, `configuration_json`, enabled flag, timestamps |
| `cookies` | Per-profile encrypted cookie jars (AES-256-GCM, `enc:v1:` envelope) |
| `interaction_sequences` | Per-website interaction configuration (`configuration_json`) |
| `visit_history` | One row per visit: outcome, duration, `http_status`, `final_url`, RSS sample, browser pid |
| `scheduler_state` | Per-website `next_visit_at`, `retry_count`, `job_status` (`pending`/`running`/`retry`/`paused`) with a lease for claim-once execution |
| `browser_events` | Browser lifecycle anomalies (`started`, `health_warn`, `crashed`, `restarted`, `crash_loop`, `db_size_warn`), trimmed to the last 500 rows |
| `application_settings` | The 23 settings keys + the `restore_pending` marker |

**Retention** — `history_retention_days` (default **7**), enforced on boot and
daily: old `visit_history` rows are deleted, stale `scheduler_state` rows are
removed, `browser_events` is trimmed, and SQLite is checkpointed
(`wal_checkpoint(TRUNCATE)`) / incrementally vacuumed.

**Backup & restore** — all available from the System page:

- **Backup** — `POST /backup` writes a timestamped `.db` into `BACKUP_DIR`
  using `VACUUM INTO` (consistent, no downtime). `GET /backup/download` streams
  a fresh snapshot, or a previously written backup via `?path=<name>` (validated
  filename).
- **Restore** — `POST /backup/restore` accepts a raw `.db` upload (64 MB limit),
  validates the `SQLite format 3\0` header, keeps the previous database as
  `.bak-*`, replaces the live file and sets the durable `restore_pending`
  marker. A banner is shown on the System page until you acknowledge it with
  `POST /backup/restore/ack` (the marker is stored in the restored database
  itself, so it survives restarts).
- `POST /backup/delete` removes a named backup; the System page lists backups
  newest first.

## Security

High-level model — see [SECURITY.md](SECURITY.md) for the full threat model.

- **Auth** — a single dashboard password (`APP_PASSWORD`, min 12 chars). Sessions
  use the self-contained HMAC-signed `uptime_session` cookie: HttpOnly,
  SameSite=Lax, `Secure` when the request arrives with
  `x-forwarded-proto: https`, **12h TTL with sliding renewal** (reissued when
  less than 6h remain). Password verification is constant-time and identical
  for all failure modes; login is rate-limited per source IP (5 failures →
  60s lockout, in-memory).
- **CSRF** — stateless double-submit: the `csrf_token` hidden form field (or
  `X-CSRF-Token` header) is compared against an HMAC of the session key.
  Mismatch → 403. The dashboard sends the header automatically
  (`htmx:configRequest` in `public/app.js`).
- **Cookie encryption at rest** — AES-256-GCM, envelope `enc:v1:` +
  base64(nonce ‖ ciphertext ‖ tag); key = scrypt(`ENCRYPTION_KEY`, app salt,
  N = 2^14). Cookie values never appear in logs or rendered pages.
- **SSRF / redirect guard** — only `http`/`https`, host required; rejects
  structurally-local hostnames (`localhost`, `*.localhost`, `*.internal`,
  `*.local`, `*.lan`, bare `metadata`) and any IP literal in loopback, private
  (RFC 1918), link-local (including `169.254.169.254`), CGNAT, unspecified,
  reserved, documentation or multicast ranges (v4 + v6, incl. ULA
  `fd00:ec2::254` with `::ffff:` mapped forms). The host is resolved and every
  A/AAAA answer must be public; after navigation the **final URL is
  re-validated** and the visit aborts (`navigation_error`) if a redirect lands
  somewhere disallowed. Residual risk: the two checks observe DNS at two
  different instants, so a TTL-0 rebinding nameserver could slip through
  between them — documented and accepted for v1 (see SECURITY.md).
- **Redaction** — URLs are logged host+path only (query strings may carry
  secrets); a redacting layer scrubs `APP_PASSWORD`, `ENCRYPTION_KEY`, cookie
  values, `Authorization`, `Set-Cookie` and `token=`-style assignments; error
  messages are capped at 400 chars.
- **Localhost-only CDP** — the Lightpanda CDP WebSocket is bound to
  `127.0.0.1`; the client refuses non-local hosts and the manager never
  exposes it.
- **Headers** — `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, a strict CSP (`default-src 'self'`; **no
  `unsafe-inline`** — all page JS lives in `/public/app.js`), `Cache-Control:
  no-store` on authenticated responses (`/public/*` sets `max-age=3600`), and
  `Strict-Transport-Security` only behind an HTTPS-terminating proxy.
- **Restore-pending model** — restoring a database sets a durable marker;
  the banner persists (across restarts) until acknowledged, so a half-finished
  restore is never silent.

## Architecture

```text
src/
├── main.rs              # entry: env config, tracing, boot checks, axum listener
├── config.rs            # deployment-contract env vars + 23 seed settings (validation)
├── error.rs             # AppError → HTTP error pages/responses
├── security.rs          # URL/SSRF guard, IP-range matrix, redaction
├── state.rs             # shared app state (bounded channels, restore-pending flag)
├── resources.rs         # RSS/CPU/free-memory sampling, thresholds, recycle trigger
├── executor.rs          # visit(): orchestrates one full monitoring cycle
├── db/
│   ├── mod.rs           # Db handle (tokio-rusqlite), public API
│   ├── schema.rs        # DDL + forward-only user_version migrations (WAL)
│   ├── models.rs        # row types (Website, Outcome, …)
│   ├── queries.rs       # all SQL (claim CAS, history, settings, events)
│   ├── backup.rs        # VACUUM INTO backups, restore validation
│   └── tests.rs         # integration tests (temp-file DBs)
├── browser/
│   ├── cdp.rs           # minimal CDP client (tokio-tungstenite, flatten sessions)
│   ├── manager.rs       # persistent Lightpanda child: spawn, health loop, recycle
│   ├── sessions.rs      # sequential profile lifecycle + UA presets + jar roundtrip
│   └── cookies.rs       # AES-256-GCM cookie jar (enc:v1:)
├── scheduler/
│   ├── mod.rs           # worker loop, recovery, pause/resume, manual visits
│   ├── queue.rs         # BinaryHeap + scheduler_state claim/lease logic
│   └── jitter.rs        # uniform interval jitter, active-window logic
├── interactions/
│   ├── mod.rs           # interaction engine entry points
│   ├── actions.rs       # serde-tagged `Action` enum + sequence model
│   └── validate.rs      # save-time validation + selector/JS denylists
└── web/
    ├── mod.rs           # router assembly
    ├── routes.rs        # all HTTP handlers + the route table
    ├── views.rs         # view-model structs for templates
    ├── templates.rs     # Askama rendering helpers
    ├── auth.rs          # session sign/verify, require_auth middleware, login throttle
    ├── csrf.rs          # double-submit CSRF (HMAC of session key)
    └── headers.rs       # security headers middleware (CSP et al.)
```

Module boundary (who may talk to whom):

```text
 browser/user ──HTMX──► web/routes ──► scheduler ──jobs──► executor
                          │              │                    │
                          │              ▼                    ▼
                          │         db (SQLite) ◄── interactions (validate+run)
                          │              ▲                    │
                          └── views ─────┘                    ▼
                                                     browser/manager ──CDP/WS──► Lightpanda
                                                     (127.0.0.1:9222 only)
```

`main` constructs the browser manager and the scheduler; `executor` is the
only component that runs a page through it. The scheduler only emits jobs and
never blocks on the browser; `resources` samples app/system memory (`/proc`)
and refuses a new visit when `MemAvailable < 120 MB`. Browser-recycling on
`memory_restart_mb` is owned by the manager's health loop. Templates are
compiled in at build time (Askama) — no runtime template files.

## Browser profiles & UA presets

Profiles are named, reusable identities for visits: a name, a description,
an enabled flag, an optional UA selection, and an optional
`configuration_json` blob for forward compatibility. Each profile owns its
**encrypted cookie jar**, flushed and restored around every visit.

UA presets (compatibility testing only), seeded in `src/browser/sessions.rs`
as a compile-time catalogue — currently:

| Preset | UA string (current stable) |
|---|---|
| `desktop-chrome` | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 |
| `desktop-firefox` | Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0 |
| `mobile-chrome` | Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36 |
| `mobile-safari` | Mozilla/5.0 (iPhone; CPU iPhone OS 26_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/604.1 |

> [!IMPORTANT]
> A user-agent override **does not reproduce engine, OS, hardware or network
> characteristics** — it changes one string. On Lightpanda 1.0.3 it changes
> nothing you can observe: `Network.setUserAgentOverride` and
> `Emulation.setUserAgentOverride` both return success but are **verified
> no-ops** (`navigator.userAgent` and the wire UA stay `Lightpanda/1.0` —
> see `docs/phase0-validation.md`), and the CLI refuses UA strings containing
> `Mozilla`. Presets exist so the stored configuration is ready if a future
> Lightpanda honors the override; they are not impersonation.

**Profile isolation is sequential, not parallel.** Lightpanda 1.0.3 supports
only one browser context at a time, so profiles share the single context via a
*sequential profile lifecycle*: before each visit the profile's jar is
decrypted and installed; after the visit the live jar is re-read, encrypted
and stored. Residual state can bleed between profile visits within one browser
process lifetime (the context is reused); the browser is only replaced on
memory pressure or crash. For hard isolation, restart the browser (System page →
**Restart browser**, or `POST /system/restart`). This constraint is documented
in `src/browser/sessions.rs` and `docs/phase0-validation.md`.

## Interactions

Per-website **interaction sequences** (optional — see
`GET /websites/{id}/interactions`) model a short, bounded synthetic journey as
an ordered list of actions, validated at save time and executed in order:

| Action | Semantics |
|---|---|
| `navigate{url}` | Absolute `http`/`https` URL; same-origin when a base origin is configured at validation; no userinfo |
| `wait_duration{ms, jitter_pct?}` | Wall-clock wait; `jitter_pct` defaults to ±20% |
| `wait_selector{selector, timeout_ms?}` | Wait until a CSS selector matches (default timeout 10s) |
| `wait_js{condition, timeout_ms?}` | Wait until a JS expression evaluates truthy (default timeout 10s) |
| `scroll{direction, distance_px, operations, delay_ms}` | Bounded scrolling; ±30% distance variation per operation; `operations` ≤ `interaction_scroll_max_ops` |
| `click{selector, wait_after_ms?}` | Click the **first** match of an explicitly listed selector; `wait_after_ms` ≤ `interaction_click_wait_max_ms` |
| `rotate{choices}` | Opt-in bounded variation: pick exactly one of 1–8 configured equivalents at run time (no nested `rotate`, no `end_session` inside) |
| `end_session` | Stop the sequence early (only as the final top-level action) |

Save-time validation (hard rejects, never warnings):

- Selectors ≤ 200 Unicode scalar values; element selectors only.
- **Click-selector denylist** (case-insensitive substrings): `pay`, `purchase`,
  `checkout`, `buy`, `order`, `delete`, `remove`, `confirm`, `submit`,
  `unsubscribe`, `account`, `login`, `password`, `card`, `wire`, `transfer`,
  `donate`, plus `[type=submit]`-style patterns. Such selectors can never be
  clicked. No override flag exists.
- **`wait_js` denylist**: `fetch(`, `XMLHttpRequest`, `sendBeacon`,
  `WebSocket`, `document.cookie`, `eval(`, `Function(` — conditions must not
  read or transmit page data or evaluate dynamic code.
- `max_actions_per_sequence` enforced; total waits + per-action timeouts must
  fit `max_session_seconds_cap`; at most 4 `navigate` actions per sequence.

Only selectors you explicitly list are ever clicked; there is no arbitrary
clicking, no form auto-submission, no file upload, no CAPTCHA bypass, no
fingerprinting, no proxy rotation. Clicks on denylisted targets are rejected at
save time, not silently skipped at run time.

**Basic mode (no interactions configured)** is the original, untouched path:
navigate → hold for the session duration → close. An empty `actions` list is a
valid "sequence"; a website without an interaction row behaves the same way.

## Scheduling

- **Jitter** — after every completed cycle the next interval is drawn uniformly
  in `[min_interval_seconds, max_interval_seconds]` (min == max means a fixed
  interval). Randomization defeats stampede correlation between monitors; the
  interval is ordinary RNG, not a CSPRNG (it is not security-sensitive).
- **Active windows** — per website: `active_window_start`/`active_window_end`
  (`HH:MM`) plus a per-website `timezone` (IANA name; falls back to the
  deployment `TZ`). Outside the window the site is rescheduled to the next
  window start — no visit is emitted. `start == end` (or no window) means
  always active; `active_window_default = "24h"` is the only supported global
  default. Manual visits bypass the window.
- **Pause vs disable** — pause is a per-website scheduler state
  (`scheduler_state.job_status='paused'`): the background loop never claims it.
  Disabling (`enabled=false`) stops the monitor entirely. Resume unpauses.
- **Manual visits** — "Visit now" bypasses the interval and the active window;
  it requires the site to be enabled, but **runs on paused sites** and restores
  the pause afterwards. Manual entries sort ahead of scheduled pops (priority
  without a second queue).
- **Retry** — on `timeout` or `navigation_error` outcomes (never on
  `success`): retry after +60s, then +300s (max 2 retries); the third
  consecutive failure resumes the normal cycle (`pending`, `retry_count=0`,
  next visit = now + jitter).
- **One worker** — a single Tokio worker with a 1-permit semaphore pops jobs
  from the in-memory priority queue; the queue length is bounded by
  `max_queue_length` (default 32). Scheduled refills come from the DB source of
  truth and are never rejected; enqueues beyond the bound (manual visits when
  saturated) are rejected with an error.
- **Recovery** — on boot, `scheduler_state` rows stuck in `running` (lease
  expired, e.g. after a crash) are requeued as `pending`; the heap is rebuilt
  from the DB. No job runs twice concurrently — claims are atomic SQL CAS
  (`UPDATE … WHERE job_status IN ('pending','retry')`).

## Development

Prerequisites: stable Rust (rustup), and the `lightpanda` binary on `PATH`
(see [Quick start — From source](#from-source)).

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked            # unit + integration tests (incl. the README drift guard)
cargo test --locked -- --ignored   # live-browser tests; needs a lightpanda binary
cargo build --locked --release
```

Layout: see the [Architecture](#architecture) tree. Templates (`templates/`)
are Askama — compiled in. Static assets (`public/`) are served at `/public/*`,
unauthenticated. `docs/phase0-validation.md` records the Lightpanda 1.0.3
capability matrix and the deviations from the original spec (UA override no-op,
one-context limit, Debian base image decision).

**Adding a website** — Overview or Websites page → *Add website* → name, URL,
bounds (prefilled from `default_*` settings), optional profile/window/timezone
→ Save. The scheduler picks it up on the next tick of the boot queue; a
`visit_history` row appears after the first visit.

**Releases** — CalVer `YYYY.MM.DD.N-alpha` git tags, GitHub **prereleases**
only (there is no stable track), all automation in `.github/workflows/release.yml`
(not part of this README's scope): bump `VERSION` + the `[package] version`
line in `Cargo.toml` (a monotonic SemVer projection `YYYY.M.D-alpha.N`), commit
as `github-actions[bot]`, create a prerelease, and rewrite the
`<!-- version:start -->…<!-- version:end -->` block above. The drift guard you
are reading about right now (`tests/readme.rs`) runs in CI and fails if the
README routes, settings, env or version blocks drift from the code. CI
(`.github/workflows/ci.yml`) runs fmt → clippy → test → release build, then
pushes the image to GHCR on every `main` push and `v*` tag.

## Image & releases

Images are built in CI (multi-arch `linux/amd64` + `linux/arm64`) and pushed to
**GHCR** as `ghcr.io/nerqiva/uptimepanda`:

```sh
docker pull ghcr.io/nerqiva/uptimepanda:latest
```

- Tags: `latest` (default branch) and `YYYY.MM.DD.N-alpha` per release.
- Pulling works anonymously — the package is public. The first push to `main`
  (or a `v*` tag) creates the package; making it public is a one-time package
  setting in the GitHub org (Packages → uptimePanda → Package settings →
  Change visibility).
- Size target: **< 200 MB**; the Lightpanda binary (~74 MB) dominates.
- The image runs as a non-root user (`uptimepanda`, uid 10001), stores data in
  the `/app/data` volume, and ships a `HEALTHCHECK` against `/health`.

## Troubleshooting

- **Browser shows Down / visits failing with `browser_crash`** — the System
  page shows Lightpanda state, RSS and the event log. `POST /system/restart`
  (button: **Restart browser**) re-arms crash-loop protection and respawns
  Lightpanda. If it keeps failing, check `RUST_LOG=debug` output for the spawn
  command and `browser_events` rows.
- **`RESTORE PENDING` banner on the System page** — a database was restored but
  the acknowledgement (`POST /backup/restore/ack`) hasn't happened yet. All
  restores require it deliberately; it clears the durable marker.
- **`/health` returns 200 but visits fail** — `/health` is deliberately
  browser- and database-free. Visit health lives in `GET /api/system`
  (memory, queue, DB size) and the Overview page.
- **429-ish "queue full" on manual Visit now** — the queue is bounded
  (`max_queue_length`, default 32); wait for the worker to drain or pause a
  noisy monitor. Scheduled visits are never rejected for this reason.
- **Validation error when saving an interaction** — the message names the rule
  that fired (denylisted selector/JS, over-length selector, too many actions,
  time budget exceeded). Fix the sequence at the editor; nothing is retried at
  run time that was rejected at save time.
- **Memory creeping toward 512 MB** — check `db_size_warn_mb` (default 64) and
  `history_retention_days`; `VACUUM`/retention already trims history daily. If
  Lightpanda RSS crosses `memory_restart_mb` it is recycled automatically — if
  restarts are frequent, lower `max_session_seconds_cap` or the interval, not
  the threshold.
- **Logs** — `RUST_LOG=debug` (or `trace`) re-enables verbose logging;
  `log_level` on the Settings page is stored but a restart is required to
  apply. Secrets are redacted either way.

## Tech stack

| Component | Technology |
|---|---|
| Core language | Rust stable (edition 2024) |
| Async runtime | Tokio (`full`) |
| HTTP framework | Axum |
| Browser engine | Lightpanda (CDP via tokio-tungstenite; no automation framework) |
| Templates / dashboard | Askama + HTMX v4 vendored (`public/htmx.min.js`) |
| Database | SQLite (WAL) via tokio-rusqlite + rusqlite (bundled) |
| Auth/crypto | hmac, sha2, scrypt, aes-gcm, base64, hex |
| Logging | tracing + tracing-subscriber (compact, env-filtered) |
| Design system | Hand-written dark-navy CSS, Emerald `#34d399` accent, JetBrains Mono (vendored, OFL) |
| Versioning | CalVer `YYYY.MM.DD.N-alpha` (`-alpha` prereleases only) |

## License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for the full text.
You may use, reproduce and distribute this software under the terms of that license.
