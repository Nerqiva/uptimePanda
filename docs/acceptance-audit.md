# uptimePanda — Acceptance Audit (SEG-21)

Environment: host Linux x86_64 (3 cores, ~3.9 GB RAM) for local verification; GitHub Actions
`ubuntu-latest` for CI/image builds. Live-network visits used `https://example.com/` and one
cookie-setting endpoint (`httpbin.org`, run once for the live-jar test).

Final state (2026-11-09): **`main` at `082da43` · releases `v2026.11.09.1..4-alpha` · GHCR image
public, multi-arch, anonymous pull verified · all CI jobs green · all 21 plan segments done.**

## Build & quality gates

| Gate | Result | Evidence |
|---|---|---|
| `cargo fmt --all --check` | PASS | clean |
| `cargo clippy --locked --all-targets -- -D warnings` | PASS | clean |
| Unit + integration tests | **PASS — 298 passed, 0 failed** (+5 README drift guard, +6 redaction suite) | `cargo test --locked --all-targets` |
| Live browser tests (`#[ignore]`d) | **PASS — 7 passed** | `cargo test --locked -- --ignored` (needs `lightpanda`) |
| Binary size | 9.6 MB (relaxed profile) | `target/release/uptimepanda` |
| Docker image build (amd64 + arm64) | **PASS** — 35m45s cold arm64 under QEMU | CI run for `b32e059` |
| Image tags pushed per `main` build | `latest` + `$(cat VERSION)` (single source of truth) | `ci.yml` |
| Image pull (anonymous) | **HTTP 200**, multi-arch manifest (linux/amd64 + linux/arm64) | `ghcr.io` token + manifest API |
| Image ↔ git release tag parity | **Restored** — both are `$(cat VERSION)` | fixed in `b32e059` |

## Incident log (fixed during verification)

1. Dockerfile `cargo fetch` before `src/` existed → "no targets specified in the manifest" (CI red).
   Fixed with a dummy `src/main.rs` in the dependency-cache layer (`64b1618`).
2. arm64 Rust release under QEMU exceeded the 30-minute job timeout
   (`lto="thin"` + `codegen-units=1`). Fixed by relaxing codegen
   (`lto=false, codegen-units=16`) and raising `timeout-minutes` to 90 (`c3aeec1`).
3. Image tag drifted one bump ahead of the git release tag — both workflows counted `git tag` independently.
   Fixed: CI tags the image from the `VERSION` file (`b32e059`). `2026.11.09.3-alpha` image ↔ git tag parity confirmed.
   (Note: `2026.11.09.4-alpha` image still exists as a fossil from the independent-counter era; content-equivalent. Tag left in place — deleting published tags is destructive.)
4. `cookies.txt` smoke artifact committed by accident → removed in `2097f73`, `cookies.txt` gitignored.
5. Scheduler heap grew by one stale entry per completed visit (unbounded memory, spec §14 violation).
   Fixed in `2cecc71` (heap retains ≤1 Scheduled entry per website + regression test).

## Shipping & release verification

- Repo `Nerqiva/uptimePanda` (PUBLIC) — README renders, security policy file linked.
- Releases are GitHub **prereleases**, CalVer `YYYY.MM.DD.N-alpha`, automated by `release.yml`;
  bump commit carries `[skip ci]` and the skip guard prevents re-release loops.
- README version block auto-synced by `release.yml`; `tests/readme.rs` drift guard green on every bump.
- CI: `test` job (fmt → clippy → test → release build) gates the `docker` job; previous run (`899b936`) failed only the
  timeout — not correctness — and the rebuilt image (`b32e059`) is green for both jobs.
- v2026.11.09.4-alpha is the current published prerelease (bump commit `082da43`).

## Acceptance criteria scorecard (spec §16)

### Browser engine
| Criterion | Status | Evidence |
|---|---|---|
| Lightpanda starts successfully | PASS | spawn log; `/json/version` ready ~75 ms; telemetry disabled via env |
| Rust establishes CDP connection | PASS | `cdp_live`: create target → attach → evaluate, 127.0.0.1-only, loopback-guarded |
| JavaScript execution works | PASS | `cdp_live`: `document.title = "Example Domain"`; arrow functions, Promise evaluation, clamped arg |
| Cookies can be read and managed | PASS | live httpbin roundtrip; encrypted at rest; expiry sweep |
| Browser sessions isolated | PARTIAL | **Lightpanda 1.0.3 allows one browser context only** → sequential profile lifecycle + jar roundtrip (documented). Residual bleed possible for one browser-lifetime; restart browser for hard isolation. |
| Browser recycling works | PASS | forced-recycle live test (pid changes, RSS returns to baseline); recycle threshold unit-tested |
| Crashes trigger recovery | PASS | `kill -9` → respawn in < 1 health poll, restart events recorded |

### Scheduling
| Criterion | Status | Evidence |
|---|---|---|
| Randomized intervals within bounds | PASS | 10k-draw uniform-bounds tests; min==max fixed mode |
| No duplicate concurrent jobs | PASS | atomic CAS claim + 1-permit worker semaphore |
| Restart recovery works | PASS | `boot_recovers_stale_running_visit` |
| Paused monitors never scheduled | PASS | `paused_site_is_not_claimed_but_manual_visit_runs` |
| Manual visits work | PASS | live soak: 5 visits → 5 rows, scheduler rescheduled |
| Heap bounded | PASS-after-fix | `repeated_completions_do_not_accumulate_heap_entries` (regression) |

### Interaction engine
| Criterion | Status | Evidence |
|---|---|---|
| Scrolling works | UNVERIFIED-LIVE | path implemented via `Runtime.evaluate` scroll; unit tests cover model/validation; no live scroll measurement |
| Configured clicks work | PASS | Phase 0: click dispatched through Input.dispatchMouseEvent navigated a real link |
| Wait conditions work | PASS | `wait_selector` poll used in Phase 0; basic visit path passes live |
| Action limits enforced | PASS | ≤50 actions (recursive weight incl. rotate branches), time budget ≤ cap, ≤4 navigates |
| Session duration limits enforced | PASS | uniform `[min,max]`, hard-capped; soak held 5–10 s waits on schedule |
| Invalid/unsafe selectors rejected | PASS | 17-substring denylist + submit-pattern; JS denylist; save-time rejects |

### Database
| Criterion | Status | Evidence |
|---|---|---|
| Config survives restarts | PASS | WAL file DB; boot reconcile; migration v1→v2 in-place |
| Browser profiles persist | PASS | CRUD roundtrips; seeded Desktop Chrome/Firefox profiles |
| Cookies persist securely | PASS | AES-256-GCM `enc:v1:`; raw-column plaintext assertion; tamper/wrong-key fail |
| History recorded | PASS | rows for every soak visit (`success`, HTTP 200) |
| Retention cleanup works | PASS | boundary-delete tests; events capped at 500; checkpoint truncates WAL |
| Backup and restore work | PASS | `VACUUM INTO` roundtrip; live `/backup/download` roundtrip (SQLite magic verified) |

### Resource validation
| Criterion | Status | Evidence |
|---|---|---|
| 1 website | PASS | full soak (5 visits): app RSS flat ≈11 MB, Lightpanda 15→36 MB |
| 5 websites | UNVERIFIED-SCALE | no multi-site rehearsal |
| 10 websites | UNVERIFIED-SCALE | no multi-site rehearsal |
| Repeated browser recycling | PASS | live test (see B3) |
| Slow navigation | PARTIAL | 15 s hard nav timeout; no live slow-endpoint measurement |
| Failed navigation | PASS | SSRF guard blocks `169.254.169.254` pre-navigation (unit matrix); abort → retryable outcome |
| JS-heavy websites | UNVERIFIED-SCALE | example.com executes JS (measured); no SPA-heavy rehearsal |
| Idle RAM | **≈ 27 MB total (app + browser)** | `/proc` samples |
| Peak RAM (5 visits) | **≈ 47 MB total** | per-visit memory_usage column |
| 512 MB / 0.15 vCPU | **PASS (with margin)** | MemAvailable guard (120 MB), tight-budget banner (350 MB), 60 MB app-RSS watchdog |

## Known gaps / follow-ups (honest list)

1. No multi-website or multi-hour soak rehearsal; only single-site manual visits measured.
2. Interaction engine has no *live* scroll/click evidence beyond Phase 0 (click) and example.com (navigate).
3. Lightpanda 1.0.3 constraints (documented in `docs/phase0-validation.md` SPEC-DEVIATIONS):
   single browser context, UA override is a verified no-op, Alpine excluded
   (image is `debian:stable-slim`; upstream does the same).
4. Residual DNS-rebinding window between pre- and post-navigation checks — accepted, documented in `SECURITY.md`.
5. `restore_pending` acknowledgement required after any restore before visits re-enable (by design).
6. GHCR package: **anonymous pull verified working** (`latest`, `3-alpha`, `4-alpha`); the README's
   anonymous-pull claim is accurate. If the org ever defaults new packages to private for this repo,
   flip it once: Packages → uptimePanda → Package settings → Change visibility.
7. License: not specified (deliberate — owner must choose).
8. `2cecc71`'s CI run (scheduler-fix image build) was cancelled when superseded by `899b936`; the
   fix is included in the currently-published `latest` image.
