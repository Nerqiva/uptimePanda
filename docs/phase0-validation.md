# Phase 0 — Lightpanda 1.0.3 compatibility validation

Date: 2026-11-09 · Host: x86_64 Linux (Ubuntu 26.04 LTS, glibc 2.43), 3 cores, ~3.9 GB RAM
Scope: SEG-01 only. This document records facts; no Dockerfile here (SEG-19).

## 1. Install + verification

Latest release (2026-11-05): tag `1.0.3`, <https://github.com/lightpanda-io/browser/releases/tag/1.0.3>

Selected install channel: **GitHub release binary pinned to 1.0.3 + SHA-256 verification**
(preferred over the official one-liner, which installs the nightly by default:
`curl -fsSL https://pkg.lightpanda.io/install.sh | bash` — supports `bash -s "1.0.3"` but
pinning+hash verification is stronger and matches the Dockerfile pinning requirement).

Release asset digests from the release assets API (`GET /repos/lightpanda-io/browser/releases/latest`),
not from hardcoded tables:

| Asset | Bytes | SHA-256 |
|---|---|---|
| `lightpanda-x86_64-linux` | 77,403,464 | `53eb34da09159dcf8f04865dbfe3e63e9a652062684495aa7ced5ddd7c82e8b0` |
| `lightpanda-aarch64-linux` | 74,485,832 | `20a5348bf3b6f71e41088223b188552ab550c1b9c9a9cbd8f099e6f7f3d78549` |
| `lightpanda-docs.tar.gz` | 15,566 | `ea697a4da64485c2f0c389f2706e03886c93a40fc885cc7459b24e47ac9e6516` |
| `lightpanda_1.0.3_amd64.deb` | 20,037,928 | `1921c54c3515e5206a8197833ed0cf0636fb68f671332fa84a3b7f3e9655930e` |
| `lightpanda_1.0.3_arm64.deb` | 17,848,904 | `5d054dc4d05c7f4e5b58d9e5030fa7e2aa8acfcb09e730bf4011309732f31461` |

Observed quirk: direct `curl -L` of GitHub release assets from this host returns HTTP 504
(consistently), while the GitHub API works and `gh release download 1.0.3 --repo lightpanda-io/browser`
succeeded. In CI (GitHub Actions), direct asset downloads generally work; if not, use the `.deb`
assets or `gh release download`. Local workaround used: `gh release download`.

Downloaded binary sha256sum matches the API digest:

```
$ sha256sum lightpanda-x86_64-linux
53eb34da09159dcf8f04865dbfe3e63e9a652062684495aa7ced5ddd7c82e8b0  lightpanda-x86_64-linux
$ install -m 755 lightpanda-x86_64-linux /usr/local/bin/lightpanda
```

Installed at `/usr/local/bin/lightpanda` (mode 755). Binary size 73.8 MB.

Telemetry: `LIGHTPANDA_DISABLE_TELEMETRY=true` is honored (log line
`$scope=telemetry ... msg="telemetry status" disabled=true`). Set it in all environments.

## 2. CLI + exact CDP server command

Ground truth from `lightpanda help serve` and a live run (not from assumption):

```
$ lightpanda version
1.0.3
```

`lightpanda --version` is a usage error: `unknown command ... did_you_mean=version`.
The CLI is subcommand-based (`agent`, `completion`, `fetch`, `help`, `mcp`, `run`, `serve`, `version`).

**Verified serve command (host + port flags, defaults match):**

```
LIGHTPANDA_DISABLE_TELEMETRY=true lightpanda serve --host 127.0.0.1 --port 9222 --log-level info
```

`serve` defaults are already `--host 127.0.0.1 --port 9222`; `--log-level` default is `warn`.
Startup log: `address=127.0.0.1:9222 max_connections=16120 max_browser_connections=16`.
Other useful `serve` flags: `--cdp-max-connections <INT>` (default 16), `--unix-socket <PATH>`
(mode 0600, mutually exclusive with host/port), `--protocol cdp|webdriver` (default `cdp`),
`--cookie <PATH>` / `--cookie-jar <PATH>` (see §6), `--disable-metrics`,
`--remote-allow-origins <ORIGIN>` (upgrades without an Origin header are always accepted).
There is no documented "disable telemetry via flag" — use the env var above.

### HTTP endpoints (verified live)

| Endpoint | Result |
|---|---|
| `GET /json/version` | 200 — `{"Browser":"Lightpanda/1.0","Protocol-Version":"1.3","User-Agent":"Lightpanda/1.0","Lightpanda-Version":"1.0.3","webSocketDebuggerUrl":"ws://127.0.0.1:9222/"}` |
| `GET /json/protocol` | 200 — 405,936 bytes, JSON: protocol `{major:1, minor:3}`, 22 domains, 195 commands, 153 events |
| `GET /json/list` | 200 — `[]` (empty array; target lifecycle not mirrored here) |
| `GET /json/targets` | 404 `Not found` — **not implemented** |
| `GET /metrics` | 200 — Prometheus text format (default on; `--disable-metrics` to turn off) |
| WebSocket CDP | `ws://127.0.0.1:9222/` (root path) |

## 3. Linkage verdict + Alpine/musl decision

```
$ readelf -h /usr/local/bin/lightpanda
  Class: ELF64   Type: EXEC (not PIE)   Machine: X86-64
$ readelf -d /usr/local/bin/lightpanda
  NEEDED  libm.so.6
  NEEDED  libc.so.6
  NEEDED  ld-linux-x86-64.so.2
  FLAGS   BIND_NOW
$ ldd /usr/local/bin/lightpanda
  linux-vdso.so.1
  libm.so.6 => /usr/lib/x86_64-linux-gnu/libm.so.6
  libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6
  /lib64/ld-linux-x86-64.so.2
```

(`file` not installed on this host; readelf/ldd used instead.)

**Verdict: NEEDS glibc — dynamic glibc binary, not static, not musl-safe.**

Evidence beyond linkage: the official Lightpanda Docker image (`lightpanda/browser`, Dockerfile
public in `lightpanda-io/browser`) is built `FROM debian:stable-slim` for both builder and runtime
stages (runtime adds only `tini` and CA certs) — i.e. upstream ships glibc, not Alpine/musl.

**Decision for the Dockerfile (SEG-19): the plan's "Base image: Alpine Linux" is contradicted by
this finding.** On Alpine the binary would need `libc6-compat` (provides `ld-linux-x86-64.so.2` +
glibc symbols) and even then the V8/zig runtime is unverified on musl-with-compat; upstream does
not test or ship it. Options, in order of preference:

1. Switch runtime base to `debian:stable-slim` (same as upstream, lowest risk), or `ubuntu:24.04`.
2. Keep Alpine + `apk add libc6-compat` **only if** SEG-19 CI builds a smoke test proving the
   binary starts and passes `/json/version` on Alpine; otherwise do not ship it.

Either way the Lightpanda install steps stay: pin `lightpanda-x86_64-linux` / `-aarch64-linux`,
verify SHA-256 (values in §1), install `-m 755`, set `LIGHTPANDA_DISABLE_TELEMETRY=true`.

## 4. RSS / timing measurements (this host)

Fresh process, idle, after start (VmRSS from `/proc/<pid>/status`):

| Moment | VmRSS |
|---|---|
| Idle, fresh serve (two consecutive restarts) | 15,548–15,556 kB (~15.2 MB) |
| Idle, first long-running instance | 15,928 kB (~15.6 MB) |
| After first full probe run (example.com + contexts + clicks) | 28,816 kB (~28.2 MB) |
| After many probes (cookie flows, click nav, context churn) | 39,448 kB (~38.5 MB) |
| VmHWM at idle | 15,928 kB |

VmSize is ~21 TB (mostly reserved V8 address space) — not meaningful; use VmRSS.
Lightpanda's own benchmark claims ~123 MB peak per 100 pages; this host shows far lower idle/working
set for simple pages. Comfortable for the 200 MB recycle threshold, but the threshold must stay.

Timing:

| Metric | Value |
|---|---|
| `lightpanda serve` start → `/json/version` 200 | **~75 ms** (measured twice, in-shell poll, 50 ms granularity) |
| Cold start including exec overhead (first boot ever) | < 3.5 s (includes tool-call latency; steady state is 75 ms) |
| `example.com` navigation wall time (`Page.navigate` → `loadEventFired`) | 234 ms (first, cold network); 43–47 ms (warm) |
| `kill -9` → port 9222 re-bindable after restart | 75 ms |

## 5. Capability matrix (verified live against Lightpanda/1.0.3, CDP protocol 1.3)

| Capability | Status | Evidence |
|---|---|---|
| `Page.navigate` returns `loaderId`/`frameId` | **YES** | `{"frameId":"FID-0000000001","loaderId":"LID-0000000001"}` (second nav: `LID-…0002`) |
| `Page.frameNavigated` event | **YES** | Observed on initial load and after click navigation |
| `Page.loadEventFired` event | **YES** | Observed; used as navigation completion signal |
| `Runtime.evaluate` with `returnByValue` | **YES** | `document.title` → `"Example Domain"`; `1+1` → `2`; `navigator.userAgent` |
| `Network.enable` + `Network.responseReceived` | **YES** | Document response: `status=200 url=https://example.com/` (`response.protocol` was `null` — do not rely on it) |
| Main-document `http_status` capture | **YES** | Via `Network.responseReceived` where `type == "Document"` |
| Cookies: `Network.getCookies` | **YES** | Returned `session=abc123` for httpbin.org (see below) |
| Cookies: `Network.setCookie` / `setCookies` / `deleteCookies` / `getAllCookies` / `clearBrowserCookies` | **YES (protocol + spot-checked)** | `setCookie` → `{"success":true}`; returned by `getCookies` |
| Cookies: `Storage.getCookies` / `Storage.setCookies` / `Storage.clearCookies` | **YES** | `Storage.getCookies` returned the same httpbin cookie |
| Cookie isolation per browser context | **YES (single context only)** | Cookie set in context BID-1 visible in BID-1; see one-context limit below |
| UA override: `Network.setUserAgentOverride` | **NO (accepted, not applied)** | Returns `{}`; `httpbin.org/user-agent` still echoed `Lightpanda/1.0`; `navigator.userAgent` unchanged. Verified on 1.0.3 |
| UA override: `Emulation.setUserAgentOverride` | **NO (accepted, not applied)** | Same result via httpbin echo + `navigator.userAgent` |
| UA override via CLI `--user-agent` | **Partial** | Exists in `lightpanda serve` common options, but values containing `Mozilla` are **forbidden** (anti-impersonation); still sends `Sec-Ch-Ua`. Real Chrome/Firefox strings impossible. `--user-agent-suffix` appends to `Lightpanda/x.y` |
| UA presets as specced in SEG-07 (desktop-chrome etc.) | **NO — spec must change** | Cannot set a Mozilla-containing UA via CDP (no-op) or CLI (rejected). See §7 |
| Multiple targets + flatten sessions | **YES** | Two concurrent sessions (`SID-1`, `SID-2`) on one context; `Runtime.evaluate` OK in both |
| Browser contexts: `Target.createBrowserContext` | **PARTIAL** | Works, but **only one context at a time**: second call → error `-32000 "Cannot have more than one browser context at a time"`. `getBrowserContexts` shows `["BID-1"]`; `disposeBrowserContext` works |
| Isolated parallel per-profile contexts | **NO** | One-context limit forces **sequential profile lifecycle** (cookie jar per visit, or dispose/recreate context per visit) — the fallback the spec anticipated |
| `Input.dispatchMouseEvent` (click) | **YES** | `mousePressed`/`mouseReleased` at `DOM.getContentQuads` center → example.com link navigated to `https://www.iana.org/help/example-domains` (`location.href` confirmed) |
| `DOM.getContentQuads` / `DOM.getBoxModel` | **YES** | Quads `[0,155,5,155,5,160,0,160]`; box model returned |
| `DOM.querySelector` / `DOM.getDocument` | **YES** | `querySelector('a')` → `nodeId 4`; `getDocument` root `backendNodeId=1` |
| `Target.targetCrashed` / `targetDestroyed` events | **PROTOCOL YES, UNVERIFIED behavior** | Both exist in protocol events; crash path not triggered (would need a real crash) |
| `Target.createTarget` / `attachToTarget` (flatten:true) | **YES** | Verified repeatedly; `targetId` == frame id in practice (`FID-…`) |
| `Target.closeTarget` | **YES** | `{"success":true}` |
| `Performance.getMetrics` | **UNVERIFIED** | Not in the required set; see protocol domains list if needed later |

Cookie cross-check flow used: navigate target to `https://httpbin.org/cookies/set?session=abc123`
(302 → `/cookies`), then `Network.getCookies` and `Storage.getCookies` — both returned
`{domain:"httpbin.org", name:"session", value:"abc123", path:"/", secure:true, httpOnly:false, session:true}`.
Cookie set/get round trip inside one browser context verified with `Network.setCookie`
(`name:"phase0ctx", url:"https://example.com/"`).

### CLI-level cookie jar (serve mode)

`lightpanda serve` supports `--cookie <PATH>` (read-only load; CDP/Puppeteer JSON array or
Netscape cookies.txt) and `--cookie-jar <PATH>` (write-only; saved when a CDP browser context
closes; with several clients the last to close wins). Under `serve`, `--cookie-jar` saves on
exit. This is a built-in bulk jar mechanism and may complement the app's own encrypted jar;
it is plain-text JSON — treat as an operational escape hatch, not a secrets store.

## 6. Signals / lifecycle / crash behavior

| Action | Observed |
|---|---|
| `SIGTERM` | Logs `$scope=app $level=info $msg="Received termination signal..."`; exits **< 100 ms**; port released immediately; no orphan processes |
| `kill -9` | Process dies instantly; port 9222 released; **no zombie/defunct** processes remained; port re-bindable on immediate relaunch (75 ms to ready) |
| Restart after `kill -9` | Fresh `serve` rebinds 127.0.0.1:9222 with no delay; `/json/version` 200 in ~75 ms |
| PID 1 note | Upstream Dockerfile uses `tini` as PID 1 because Lightpanda handles only some signals and PID 1 has no default SIGTERM handler. In docker, use `tini -- lightpanda serve …` (or `--init`) or SIGTERM may not be honored. For non-docker (systemd/s6/direct child of the app) this does not apply — the app spawns it as a normal child and signals work |

## 7. Deviations from the original spec / SEG-06 assumptions

1. **Serve syntax**: `lightpanda serve --host 127.0.0.1 --port 9222` is correct, but both flags are
   optional (defaults are exactly 127.0.0.1:9222) and `--log-level` defaults to `warn`, not `info`.
   There is no `lightpanda --host … --port …` top-level form; `--version` is invalid
   (use `lightpanda version`). SEG-06 must spawn the subcommand form.
2. **UA override is a no-op over CDP.** SEG-07's "UA presets (desktop-chrome, desktop-firefox,
   mobile-chrome, mobile-safari)" cannot be implemented as specced. Both CDP methods return
   success responses but never change the UA on the wire or in JS. CLI `--user-agent` rejects any
   value containing `Mozilla`, and it is a process-wide start flag (requires browser restart to
   change; violates the persistent-process model). **Recommendation (SEG-07 decision needed):**
   drop the UA-preset feature or replace it with a clearly-labeled honest option:
   `--user-agent-suffix` at most, or keep presets in config but document they have no effect on
   Lightpanda 1.0.3. Do not claim browser impersonation — that would also violate the
   no-fingerprint-spoofing rule.
3. **Only one browser context at a time.** SEG-07's "independent profiles" must use the
   **sequential profile lifecycle**: one context reused for all profiles, cookies loaded/saved per
   visit (CDP `Network.getCookies` → encrypted jar → `Network.setCookies` on next visit), or
   dispose/recreate the single context per profile visit for hard isolation. Parallel isolated
   contexts are impossible on 1.0.3. Cookie jar approach is sufficient; browser-context-per-profile
   is not available.
4. **Alpine base image decision contradicted** (see §3). `libc6-compat` preemption is not enough
   evidence; upstream is Debian. SEG-19 should not ship Alpine without a CI smoke test.
5. **CDP endpoint is `/` on port 9222; HTTP helpers are `/json/version`, `/json/protocol`,
   `/json/list`** (empty array), and Prometheus `/metrics`. There is **no** `/json/targets`
   (404) — anything in SEG-05/06/11 polling `/json/targets` must use `Target.getTargets` over WS.
6. `responseReceived.response.protocol` is `null` (do not record it); `type == "Document"` is the
   reliable main-frame filter for `http_status`.
7. Direct GitHub release-asset downloads (`curl -L`) 504'd from this host throughout 2026-11-09;
   `gh release download` worked. CI builds should not assume anonymous asset curl works;
   prefer the `.deb` assets or authenticated download if needed.
8. `Page.navigate` returns `targetId == frameId` (`FID-…`) in this build; do not assume distinct
   opaque ID spaces when keying sessions.

## 8. Suggested SEG-06/07 follow-ups (not part of SEG-01)

- Spawn: `LIGHTPANDA_DISABLE_TELEMETRY=true lightpanda serve --host 127.0.0.1 --port <p> --log-level info`,
  health-check `GET /json/version` (200) rather than process polling alone.
- Treat `targetCrashed`/WS close as crash signal; restart with backoff per SEG-06.
- Cookie jar restore *before* navigation, capture *after* `loadEventFired`.
- Click path: `DOM.getDocument` → `DOM.querySelector` → `DOM.getContentQuads` →
  `Input.dispatchMouseEvent` (verified). JS `.click()` via `Runtime.evaluate` remains a fine fallback.
- Consider `--cookie-jar` as a debug/ops backup only; primary jar stays the app's encrypted store.

## 9. Artifacts

- Raw `/json/protocol` snapshot: kept at `/tmp/lp-protocol.json` during validation (not committed;
  re-fetch at any time: `curl http://127.0.0.1:9222/json/protocol`).
- Probe (throwaway, NOT committed): `/tmp/cdp-probe` (Rust, tokio-tungstenite). Example.com round
  trip: createTarget → attachToTarget(flatten) → Page.enable + Network.enable → Page.navigate →
  responseReceived(status 200) → loadEventFired → Runtime.evaluate(document.title).
- Serve logs: `/tmp/lp-serve.log`, `/tmp/lp2.log`, `/tmp/lp3.log`.
- Cleaned up: CDP server stopped; port 9222 free; probe retained only in /tmp (not in repo).
