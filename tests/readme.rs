//! README drift guard — runs as part of `cargo test` and in CI.
//!
//! The README is the front door of this project. This test keeps it honest:
//! it fails (with actionable messages) when the README drifts from the code.
//!
//! What is verified:
//!
//! 1. **Routes** — every route registered in `src/web/routes.rs` (and the
//!    login pair in `src/web/auth.rs::build_login_routes`) appears in the
//!    `<!-- routes:start -->…<!-- routes:end -->` block of `README.md`, and
//!    vice versa (no stale rows in the README either).
//! 2. **Settings** — all 23 `application_settings` keys appear in the
//!    `<!-- settings:start -->…<!-- settings:end -->` block, and the same 23
//!    keys exist in `src/config.rs` (`SETTING_DEFAULTS`). The 23-key list is
//!    duplicated here on purpose: it is the contract both sides must hold.
//! 3. **Environment** — every deployment-contract variable appears in the
//!    `<!-- env:start -->…<!-- env:end -->` block and in `.env.example`.
//! 4. **Version** — the `<!-- version:start -->…<!-- version:end -->` block
//!    contains exactly the content of the `VERSION` file (trimmed).
//! 5. **Copy-paste leak** — the README must not reference the previous
//!    project's GitHub org path.
//!
//! Integration tests cannot import the binary crate, so everything here is
//! verified by scanning source text. That is deliberate: the guard checks
//! what the README *claims* against what the code *registers*, cheaply and
//! deterministically.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const README: &str = "README.md";
const VERSION_FILE: &str = "VERSION";
const ENV_EXAMPLE: &str = ".env.example";
const CONFIG_RS: &str = "src/config.rs";
const ROUTES_RS: &str = "src/web/routes.rs";
const AUTH_RS: &str = "src/web/auth.rs";

const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

/// The 23 `application_settings` keys — the single source of truth shared
/// with `src/config.rs::SETTING_DEFAULTS`. Changing either side without the
/// other fails this test on purpose.
const EXPECTED_KEYS: &[&str] = &[
    "active_window_default",
    "browser_restart_timeout_s",
    "browser_respawn_delay_s",
    "concurrent_visits",
    "db_size_warn_mb",
    "default_max_interval_seconds",
    "default_max_session_seconds",
    "default_min_interval_seconds",
    "default_min_session_seconds",
    "history_retention_days",
    "interaction_click_wait_max_ms",
    "interaction_scroll_max_ops",
    "log_level",
    "max_actions_per_sequence",
    "max_queue_length",
    "max_session_seconds_cap",
    "memory_restart_mb",
    "memory_warn_mb",
    "nav_timeout_s",
    "rss_poll_interval_s",
    "sqlite_maintenance_on_boot",
    "ua_presets_enabled",
    "visit_timeout_s",
];

/// The deployment-contract environment variables (`.env.example`).
const EXPECTED_ENV: &[&str] = &[
    "APP_PASSWORD",
    "ENCRYPTION_KEY",
    "DATABASE_PATH",
    "BACKUP_DIR",
    "PORT",
    "BIND_ADDR",
    "TZ",
    "RUST_LOG",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(rel: &str) -> String {
    let path = root().join(rel);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("drift guard: cannot read {}: {e}", path.display()))
}

/// Extract the text between `<!-- {name}:start -->` and `<!-- {name}:end -->`.
fn marker_block(readme: &str, name: &str) -> String {
    let start = format!("<!-- {name}:start -->");
    let end = format!("<!-- {name}:end -->");
    let s = readme
        .find(&start)
        .unwrap_or_else(|| panic!("drift guard: README.md is missing `{start}`"));
    let content_start = s + start.len();
    let e = readme[content_start..]
        .find(&end)
        .map(|rel| content_start + rel)
        .unwrap_or_else(|| panic!("drift guard: README.md is missing `{end}`"));
    readme[content_start..e].to_string()
}

/// Whole-word check: `verb` appears in `haystack` immediately followed by
/// `(`, and the character before it is not a word character.
fn contains_call(haystack: &str, verb: &str) -> bool {
    let needle = format!("{verb}(");
    let bytes = haystack.as_bytes();
    let mut start = 0usize;
    while let Some(rel) = haystack[start..].find(&needle) {
        let idx = start + rel;
        let ok = idx == 0 || !(bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'_');
        if ok {
            return true;
        }
        start = idx + 1;
    }
    false
}

/// Scan a source file for `.route("PATH", METHOD(...)...)` registrations.
///
/// Uses a string-aware balanced-paren scan (regex-free) because the route
/// calls nest arbitrary expressions (e.g. `axum::extract::DefaultBodyLimit::max(...)`).
fn extract_route_calls(src: &str) -> Vec<(String, Vec<String>)> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = src[i..].find(".route(") {
        let open = i + rel + ".route".len(); // index of '('
        let mut depth: i32 = 0;
        let mut j = open;
        let mut in_str = false;
        let mut prev = b'\0';
        while j < bytes.len() {
            let c = bytes[j];
            if in_str {
                if c == b'"' && prev != b'\\' {
                    in_str = false;
                }
            } else if c == b'"' {
                in_str = true;
            } else if c == b'(' {
                depth += 1;
            } else if c == b')' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            prev = c;
            j += 1;
        }
        let chunk = &src[open..=j];

        let q1 = chunk
            .find('"')
            .expect("drift guard: route call without a path string")
            + 1;
        let q2 = chunk[q1..]
            .find('"')
            .expect("drift guard: unterminated route path string")
            + q1;
        let path = chunk[q1..q2].to_string();

        let mut methods = Vec::new();
        for verb in ["get", "post", "put", "patch", "delete"] {
            if contains_call(chunk, verb) {
                methods.push(verb.to_ascii_uppercase());
            }
        }
        assert!(
            !methods.is_empty(),
            "drift guard: could not determine HTTP method for route {path:?} in source"
        );

        out.push((path, methods));
        i = j + 1;
    }
    out
}

/// Parse `| METHOD /path |` cells out of the README routes block.
fn readme_routes(block: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for line in block.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let mut cells = line.split('|').map(str::trim);
        let Some(cell) = cells.nth(1) else { continue };
        let mut parts = cell.split_whitespace();
        let (Some(method), Some(path), None) = (parts.next(), parts.next(), parts.next()) else {
            continue; // header/separator row
        };
        if HTTP_METHODS.contains(&method) && path.starts_with('/') {
            out.insert((method.to_string(), path.to_string()));
        }
    }
    out
}

#[test]
fn readme_routes_block_matches_source() {
    let readme = read_repo_file(README);
    let block = marker_block(&readme, "routes");

    // Routes come from the main router plus the login pair mounted via
    // `auth::build_login_routes` (`/login`, `/logout`).
    let mut expected: BTreeSet<(String, String)> = BTreeSet::new();
    for file in [ROUTES_RS, AUTH_RS] {
        for (path, methods) in extract_route_calls(&read_repo_file(file)) {
            for method in methods {
                expected.insert((method, path.clone()));
            }
        }
    }

    let actual = readme_routes(&block);

    let missing: Vec<_> = expected.difference(&actual).collect();
    let stale: Vec<_> = actual.difference(&expected).collect();

    assert!(
        missing.is_empty() && stale.is_empty(),
        "drift guard: README.md routes block is out of sync with the source.\n\
         missing from README (registered in code but not documented):\n  {}\n\
         present in README but not registered in code:\n  {}\n\
         update the `<!-- routes:start -->…<!-- routes:end -->` table in README.md",
        missing
            .iter()
            .map(|(m, p)| format!("{m} {p}"))
            .collect::<Vec<_>>()
            .join("\n  "),
        stale
            .iter()
            .map(|(m, p)| format!("{m} {p}"))
            .collect::<Vec<_>>()
            .join("\n  "),
    );
}

#[test]
fn readme_settings_block_lists_all_23_keys() {
    let readme = read_repo_file(README);
    let block = marker_block(&readme, "settings");
    let config = read_repo_file(CONFIG_RS);

    for key in EXPECTED_KEYS {
        assert!(
            block.contains(key),
            "drift guard: README.md settings block is missing setting key `{key}`\n\
             (update `<!-- settings:start -->…<!-- settings:end -->` in README.md)"
        );
        assert!(
            config.contains(&format!("key: \"{key}\"")),
            "drift guard: src/config.rs SETTING_DEFAULTS is missing expected key `{key}`\n\
             (the 23-key contract lives in tests/readme.rs)"
        );
    }

    // The code must seed exactly these 23 keys — no more, no less.
    let mut code_keys = BTreeSet::new();
    let mut rest = config.as_str();
    while let Some(rel) = rest.find("key: \"") {
        let after = &rest[rel + "key: \"".len()..];
        let Some(end) = after.find('"') else { break };
        let candidate = &after[..end];
        if !candidate.is_empty()
            && candidate
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            code_keys.insert(candidate.to_string());
        }
        rest = &after[end + 1..];
    }
    let expected: BTreeSet<String> = EXPECTED_KEYS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        code_keys, expected,
        "drift guard: src/config.rs seeds a different key set than tests/readme.rs (or count != 23).\n\
         expected: {expected:?}\nfound:     {code_keys:?}"
    );
    assert_eq!(
        EXPECTED_KEYS.len(),
        23,
        "drift guard: EXPECTED_KEYS must list exactly the 23 seeded settings"
    );
}

#[test]
fn readme_env_block_lists_all_contract_vars() {
    let readme = read_repo_file(README);
    let block = marker_block(&readme, "env");
    let env_example = read_repo_file(ENV_EXAMPLE);

    for var in EXPECTED_ENV {
        assert!(
            block.contains(var),
            "drift guard: README.md env block is missing `{var}`\n\
             (update `<!-- env:start -->…<!-- env:end -->` in README.md)"
        );
        assert!(
            env_example.contains(&format!("{var}=")),
            "drift guard: .env.example is missing contract variable `{var}`"
        );
    }
}

#[test]
fn readme_version_block_matches_version_file() {
    let readme = read_repo_file(README);
    let block = marker_block(&readme, "version");
    let version = read_repo_file(VERSION_FILE).trim().to_string();

    assert!(
        block.contains(&version),
        "drift guard: README.md version block does not contain VERSION ({version})\n\
         the block between <!-- version:start --> and <!-- version:end --> must carry it verbatim:\n{block}"
    );

    // The bold version token right after "Version:** " must be exactly VERSION.
    let token = block
        .split("Version:** ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::trim);
    assert_eq!(
        token,
        Some(version.as_str()),
        "drift guard: README.md version token does not match VERSION file"
    );
}

#[test]
fn readme_has_no_copy_paste_leaks() {
    let readme = read_repo_file(README);
    for leak in ["github.com/Nerqiva/rclone-extractor", "rclone-extractor"] {
        assert!(
            !readme.contains(leak),
            "drift guard: README.md references `{leak}` — copy-paste leak from the previous project"
        );
    }
}
