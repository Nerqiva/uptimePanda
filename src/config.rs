// The settings API keeps a few test-only helpers (e.g. `restore_default`)
// that the Settings page (SEG-14) does not call; silence dead_code for them.
#![allow(dead_code)]

//! Config module — resolves every runtime knob for uptimePanda.
//!
//! Two layers, mirroring the plan (SEG-04):
//!
//! 1. **Deployment contract** — environment variables read at boot
//!    ([`Config::from_env`]). These are `.env`/PaaS-provided values:
//!    `APP_PASSWORD`, `ENCRYPTION_KEY`, `DATABASE_PATH`, `BACKUP_DIR`,
//!    `PORT`, `BIND_ADDR`, `TZ`, `RUST_LOG`. See `.env.example`.
//! 2. **Application settings** — DB-backed rows in `application_settings`,
//!    seeded from [`SETTING_DEFAULTS`] (tuned for 512 MB / 0.15 vCPU) and
//!    editable at runtime via the Settings page (SEG-14). Only the
//!    deployment-contract vars come from the environment; everything else
//!    lives in the database.
//!
//! Secrets (`APP_PASSWORD`, `ENCRYPTION_KEY`) are never logged or printed;
//! the [`Config`] `Debug` impl redacts them manually.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::db::{Db, DbError};

// ---------------------------------------------------------------------------
// Deployment contract (env)
// ---------------------------------------------------------------------------

/// Resolved deployment configuration.
///
/// Construct via [`Config::from_env`] (or [`Config::resolve`] in tests).
/// The `Debug` impl redacts `app_password` and `encryption_key`.
pub struct Config {
    pub database_path: PathBuf,
    pub backup_dir: PathBuf,
    pub app_password: String,
    pub encryption_key: String,
    pub port: u16,
    pub bind_addr: IpAddr,
    pub tz: String,
    pub log_level: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_path", &self.database_path)
            .field("backup_dir", &self.backup_dir)
            .field("app_password", &"<redacted>")
            .field("encryption_key", &"<redacted>")
            .field("port", &self.port)
            .field("bind_addr", &self.bind_addr)
            .field("tz", &self.tz)
            .field("log_level", &self.log_level)
            .finish()
    }
}

impl Config {
    /// Pure, testable resolver. `get` maps an env var name to its raw value.
    ///
    /// Defaults (dev ergonomics): `DATABASE_PATH=./data/uptimepanda.db`,
    /// `BACKUP_DIR=./data/backups` (next to the db), `PORT=8080`,
    /// `BIND_ADDR=127.0.0.1`, `TZ=Asia/Omsk`, `RUST_LOG=info`.
    ///
    /// `APP_PASSWORD` (min 12 chars) and `ENCRYPTION_KEY` (min 16 chars) are
    /// required. All problems are collected and reported as one multiline
    /// error.
    pub fn resolve(get: &dyn Fn(&str) -> Option<String>) -> Result<Config, String> {
        let mut problems: Vec<String> = Vec::new();

        let database_path = PathBuf::from(
            get("DATABASE_PATH").unwrap_or_else(|| "./data/uptimepanda.db".to_string()),
        );
        let backup_dir =
            PathBuf::from(get("BACKUP_DIR").unwrap_or_else(|| "./data/backups".to_string()));

        let app_password = match get("APP_PASSWORD") {
            None => {
                problems.push(
                    "APP_PASSWORD is required (min 12 characters); set it to the dashboard login password"
                        .to_string(),
                );
                String::new()
            }
            Some(p) if p.chars().count() < 12 => {
                problems.push(format!(
                    "APP_PASSWORD is too short ({} chars; min 12)",
                    p.chars().count()
                ));
                p
            }
            Some(p) => p,
        };

        let encryption_key = match get("ENCRYPTION_KEY") {
            None => {
                problems.push(
                    "ENCRYPTION_KEY is required (min 16 characters); passphrase for cookie encryption at rest (scrypt -> AES-256-GCM)"
                        .to_string(),
                );
                String::new()
            }
            Some(k) if k.chars().count() < 16 => {
                problems.push(format!(
                    "ENCRYPTION_KEY is too short ({} chars; min 16)",
                    k.chars().count()
                ));
                k
            }
            Some(k) => k,
        };

        let port = match get("PORT") {
            None => 8080,
            Some(raw) => match raw.trim().parse::<u16>() {
                Ok(p) => p,
                Err(_) => {
                    problems.push(format!(
                        "PORT must be a valid port number (0-65535), got {raw:?}"
                    ));
                    8080
                }
            },
        };

        let bind_addr = match get("BIND_ADDR") {
            None => IpAddr::from([127, 0, 0, 1]),
            Some(raw) => match raw.trim().parse::<IpAddr>() {
                Ok(a) => a,
                Err(_) => {
                    problems.push(format!(
                        "BIND_ADDR must be a valid IP address (e.g. 127.0.0.1 or 0.0.0.0), got {raw:?}"
                    ));
                    IpAddr::from([127, 0, 0, 1])
                }
            },
        };

        let tz = get("TZ").unwrap_or_else(|| "Asia/Omsk".to_string());
        if tz.parse::<chrono_tz::Tz>().is_err() {
            problems.push(format!(
                "TZ={tz:?} is not a known IANA timezone (e.g. Asia/Omsk, UTC, Europe/Berlin)"
            ));
        }
        let log_level = get("RUST_LOG").unwrap_or_else(|| "info".to_string());

        if !problems.is_empty() {
            return Err(format!(
                "uptimePanda configuration error(s):\n  - {}",
                problems.join("\n  - ")
            ));
        }

        Ok(Config {
            database_path,
            backup_dir,
            app_password,
            encryption_key,
            port,
            bind_addr,
            tz,
            log_level,
        })
    }

    /// Thin wrapper over [`Config::resolve`] reading the process environment.
    pub fn from_env() -> Result<Config, String> {
        Config::resolve(&|k| std::env::var(k).ok())
    }
}

// ---------------------------------------------------------------------------
// Application settings (DB-backed, 512 MB / 0.15 vCPU tuned)
// ---------------------------------------------------------------------------

/// Default row for a `application_settings` key.
///
/// `min`/`max` are inclusive bounds for integer-valued keys (`None` for
/// booleans and pattern-validated keys). `is_bool` marks keys whose value
/// must be exactly `true` or `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingDefault {
    pub key: &'static str,
    pub value: &'static str,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub is_bool: bool,
    pub help: &'static str,
}

/// The complete seed table — exactly the keys from SEG-04 of the plan,
/// defaults tuned for a 512 MB / 0.15 vCPU host.
pub const SETTING_DEFAULTS: &[SettingDefault] = &[
    SettingDefault {
        key: "memory_warn_mb",
        value: "160",
        min: Some(64),
        max: Some(320),
        is_bool: false,
        help: "Log + dashboard warning when browser RSS exceeds this many MB",
    },
    SettingDefault {
        key: "memory_restart_mb",
        value: "200",
        min: Some(96),
        max: Some(384),
        is_bool: false,
        help: "Recycle the Lightpanda process when RSS exceeds this many MB",
    },
    SettingDefault {
        key: "browser_restart_timeout_s",
        value: "15",
        min: Some(1),
        max: Some(120),
        is_bool: false,
        help: "Max seconds to wait for a graceful browser stop before SIGKILL",
    },
    SettingDefault {
        key: "browser_respawn_delay_s",
        value: "5",
        min: Some(1),
        max: Some(30),
        is_bool: false,
        help: "Seconds to pause before spawning a replacement browser",
    },
    SettingDefault {
        key: "concurrent_visits",
        value: "1",
        min: Some(1),
        max: Some(1),
        is_bool: false,
        help: "Enforced to 1 (single worker); any other value is rejected",
    },
    SettingDefault {
        key: "rss_poll_interval_s",
        value: "5",
        min: Some(1),
        max: Some(60),
        is_bool: false,
        help: "Resource-manager cadence in seconds (RSS/CPU sampling)",
    },
    SettingDefault {
        key: "nav_timeout_s",
        value: "15",
        min: Some(5),
        max: Some(120),
        is_bool: false,
        help: "Hard timeout in seconds for page navigation",
    },
    SettingDefault {
        key: "visit_timeout_s",
        value: "30",
        min: Some(10),
        max: Some(300),
        is_bool: false,
        help: "Hard timeout in seconds for a whole visit",
    },
    SettingDefault {
        key: "max_session_seconds_cap",
        value: "300",
        min: Some(60),
        max: Some(1800),
        is_bool: false,
        help: "Absolute ceiling in seconds for any monitoring session",
    },
    SettingDefault {
        key: "max_actions_per_sequence",
        value: "50",
        min: Some(1),
        max: Some(100),
        is_bool: false,
        help: "Ceiling on actions in an interaction sequence",
    },
    SettingDefault {
        key: "max_queue_length",
        value: "32",
        min: Some(1),
        max: Some(256),
        is_bool: false,
        help: "Bound on pending jobs; beyond this, new jobs are rejected",
    },
    SettingDefault {
        key: "history_retention_days",
        value: "7",
        min: Some(1),
        max: Some(365),
        is_bool: false,
        help: "Days to keep visit history; cleanup runs daily",
    },
    SettingDefault {
        key: "sqlite_maintenance_on_boot",
        value: "true",
        min: None,
        max: None,
        is_bool: true,
        help: "Run PRAGMA optimize + wal_checkpoint(TRUNCATE) on boot",
    },
    SettingDefault {
        key: "default_min_interval_seconds",
        value: "480",
        min: Some(30),
        max: Some(86400),
        is_bool: false,
        help: "Default minimum seconds between visits (8 min)",
    },
    SettingDefault {
        key: "default_max_interval_seconds",
        value: "780",
        min: Some(30),
        max: Some(86400),
        is_bool: false,
        help: "Default maximum seconds between visits (13 min)",
    },
    SettingDefault {
        key: "default_min_session_seconds",
        value: "15",
        min: Some(5),
        max: Some(3600),
        is_bool: false,
        help: "Default minimum session length in seconds",
    },
    SettingDefault {
        key: "default_max_session_seconds",
        value: "60",
        min: Some(5),
        max: Some(3600),
        is_bool: false,
        help: "Default maximum session length in seconds",
    },
    SettingDefault {
        key: "interaction_scroll_max_ops",
        value: "20",
        min: Some(1),
        max: Some(100),
        is_bool: false,
        help: "Safety bound on scroll operations per interaction",
    },
    SettingDefault {
        key: "interaction_click_wait_max_ms",
        value: "10000",
        min: Some(500),
        max: Some(30000),
        is_bool: false,
        help: "Safety bound on wait after a click, in milliseconds",
    },
    SettingDefault {
        key: "ua_presets_enabled",
        value: "true",
        min: None,
        max: None,
        is_bool: true,
        help: "Enable UA preset overrides (compatibility testing only)",
    },
    SettingDefault {
        key: "active_window_default",
        value: "24h",
        min: None,
        max: None,
        is_bool: false,
        help: "Default monitoring window; '24h' or '<N>h' with N in 1..=168",
    },
    SettingDefault {
        key: "db_size_warn_mb",
        value: "64",
        min: Some(16),
        max: Some(1024),
        is_bool: false,
        help: "Dashboard warning when the SQLite file exceeds this many MB",
    },
    SettingDefault {
        key: "log_level",
        value: "info",
        min: None,
        max: None,
        is_bool: false,
        help: "Log level (trace|debug|info|warn|error); read on boot, writable from UI",
    },
];

const INTERVAL_PAIR: (&str, &str) = (
    "default_min_interval_seconds",
    "default_max_interval_seconds",
);
const SESSION_PAIR: (&str, &str) = ("default_min_session_seconds", "default_max_session_seconds");

fn pair_for(key: &str) -> Option<(&'static str, &'static str)> {
    if key == INTERVAL_PAIR.0 || key == INTERVAL_PAIR.1 {
        Some(INTERVAL_PAIR)
    } else if key == SESSION_PAIR.0 || key == SESSION_PAIR.1 {
        Some(SESSION_PAIR)
    } else {
        None
    }
}

fn default_for(key: &str) -> Option<&'static SettingDefault> {
    SETTING_DEFAULTS.iter().find(|d| d.key == key)
}

const LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

fn validate_active_window(value: &str) -> Result<(), String> {
    let hours = value.strip_suffix('h').ok_or_else(|| {
        format!("active_window_default must be '<int>h' (e.g. '24h'), got {value:?}")
    })?;
    let n: i64 = hours.parse().map_err(|_| {
        format!("active_window_default must be '<int>h' (e.g. '24h'), got {value:?}")
    })?;
    if !(1..=168).contains(&n) {
        return Err(format!(
            "active_window_default must be between 1h and 168h, got {n}h"
        ));
    }
    Ok(())
}

/// Validate a single `key`/`value` pair against the bounds in
/// [`SETTING_DEFAULTS`]. Unknown keys are rejected.
pub fn validate_setting(key: &str, value: &str) -> Result<(), String> {
    let def = default_for(key).ok_or_else(|| format!("unknown setting key: {key:?}"))?;

    if def.is_bool {
        return match value {
            "true" | "false" => Ok(()),
            other => Err(format!("{key} must be 'true' or 'false', got {other:?}")),
        };
    }

    match key {
        "active_window_default" => return validate_active_window(value),
        "log_level" => {
            let v = value.trim().to_ascii_lowercase();
            return if LOG_LEVELS.contains(&v.as_str()) {
                Ok(())
            } else {
                Err(format!(
                    "log_level must be one of trace|debug|info|warn|error, got {value:?}"
                ))
            };
        }
        "concurrent_visits" => {
            let n: i64 = value
                .trim()
                .parse()
                .map_err(|_| format!("concurrent_visits must be an integer, got {value:?}"))?;
            return if n == 1 {
                Ok(())
            } else {
                Err(format!(
                    "concurrent_visits is enforced to 1 (single worker guarantee); got {n}"
                ))
            };
        }
        _ => {}
    }

    let n: i64 = value
        .trim()
        .parse()
        .map_err(|_| format!("{key} must be an integer, got {value:?}"))?;
    if let Some(min) = def.min
        && n < min
    {
        return Err(format!("{key} must be >= {min}, got {n}"));
    }
    if let Some(max) = def.max
        && n > max
    {
        return Err(format!("{key} must be <= {max}, got {n}"));
    }
    Ok(())
}

fn default_pair_value(key: &str) -> i64 {
    // SETTING_DEFAULTS is a static table of valid integer values for the
    // pair keys; a parse failure here is a programming error.
    default_for(key)
        .expect("pair keys exist in SETTING_DEFAULTS")
        .value
        .parse()
        .expect("pair defaults are integers")
}

fn check_default_pair(pair: (&str, &str)) -> Result<(), DbError> {
    let (min_key, max_key) = pair;
    let min = default_pair_value(min_key);
    let max = default_pair_value(max_key);
    if min > max {
        return Err(DbError::Validation(format!(
            "default {min_key} ({min}) must be <= default {max_key} ({max})"
        )));
    }
    Ok(())
}

/// Seed all [`SETTING_DEFAULTS`] into `application_settings` with
/// `INSERT OR IGNORE` — existing (user-edited) values are preserved, so
/// re-seeding on every boot is safe and idempotent. Called at boot.
pub async fn seed_settings(db: &Db) -> Result<(), DbError> {
    // Cross-check the min <= max invariants on the seed table itself.
    check_default_pair(INTERVAL_PAIR)?;
    check_default_pair(SESSION_PAIR)?;
    for def in SETTING_DEFAULTS {
        db.seed_application_setting_if_absent(def.key, def.value)
            .await?;
    }
    Ok(())
}

/// Read a setting from the DB, falling back to its [`SETTING_DEFAULTS`]
/// default when the row is missing. Unknown keys are an error.
pub async fn get_setting(db: &Db, key: &str) -> Result<String, DbError> {
    if let Some(v) = db.get_application_setting(key).await? {
        return Ok(v);
    }
    default_for(key)
        .map(|d| d.value.to_string())
        .ok_or_else(|| DbError::Validation(format!("unknown setting key: {key:?}")))
}

/// Read a setting and parse it as `i64`.
pub async fn typed_i64(db: &Db, key: &str) -> Result<i64, DbError> {
    let raw = get_setting(db, key).await?;
    raw.trim()
        .parse::<i64>()
        .map_err(|_| DbError::Validation(format!("{key} is not an integer: {raw:?}")))
}

/// Read a setting and parse it as `bool` (`true`/`false` only).
pub async fn typed_bool(db: &Db, key: &str) -> Result<bool, DbError> {
    let raw = get_setting(db, key).await?;
    match raw.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(DbError::Validation(format!(
            "{key} is not a boolean: {other:?}"
        ))),
    }
}

/// Validate and write a setting. `value` must pass [`validate_setting`].
/// For the interval/session pairs, the write is rejected when it would
/// make min > max (checked against the effective value of the counterpart,
/// i.e. the DB row if present, else the default).
pub async fn set_setting(db: &Db, key: &str, value: &str) -> Result<(), String> {
    validate_setting(key, value)?;

    if let Some((min_key, max_key)) = pair_for(key) {
        let min_raw = if key == min_key {
            value.to_string()
        } else {
            get_setting(db, min_key).await.map_err(|e| e.to_string())?
        };
        let max_raw = if key == max_key {
            value.to_string()
        } else {
            get_setting(db, max_key).await.map_err(|e| e.to_string())?
        };
        let min_i: i64 = min_raw
            .trim()
            .parse()
            .map_err(|_| format!("{min_key} is not an integer: {min_raw:?}"))?;
        let max_i: i64 = max_raw
            .trim()
            .parse()
            .map_err(|_| format!("{max_key} is not an integer: {max_raw:?}"))?;
        if min_i > max_i {
            return Err(format!(
                "{min_key} ({min_i}) must be <= {max_key} ({max_i})"
            ));
        }
    }

    db.upsert_application_setting(key, value)
        .await
        .map_err(|e| e.to_string())
}

/// Overwrite a setting with its [`SETTING_DEFAULTS`] default.
/// Used to implement "Restore defaults" semantics per key.
pub async fn restore_default(db: &Db, key: &str) -> Result<(), String> {
    let def = default_for(key).ok_or_else(|| format!("unknown setting key: {key:?}"))?;
    set_setting(db, key, def.value).await
}

/// One row of the settings view — for rendering the Settings page (SEG-14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingView {
    pub key: &'static str,
    /// Effective value (DB row if present, else the default).
    pub value: String,
    pub default: &'static str,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub is_bool: bool,
    pub help: &'static str,
}

/// Effective view of a single setting. Returns `None` for unknown keys —
/// lets the Settings page re-render one row fragment after a write (or a
/// rejected write) without loading the whole table.
pub async fn view_setting(db: &Db, key: &str) -> Result<Option<SettingView>, DbError> {
    let Some(def) = default_for(key) else {
        return Ok(None);
    };
    Ok(Some(SettingView {
        key: def.key,
        value: get_setting(db, def.key).await?,
        default: def.value,
        min: def.min,
        max: def.max,
        is_bool: def.is_bool,
        help: def.help,
    }))
}

/// Effective view of every known setting, in table order.
pub async fn effective_settings(db: &Db) -> Result<Vec<SettingView>, DbError> {
    let mut views = Vec::with_capacity(SETTING_DEFAULTS.len());
    for def in SETTING_DEFAULTS {
        views.push(SettingView {
            key: def.key,
            value: get_setting(db, def.key).await?,
            default: def.value,
            min: def.min,
            max: def.max,
            is_bool: def.is_bool,
            help: def.help,
        });
    }
    Ok(views)
}

/// Reset **every** [`SETTING_DEFAULTS`] key to its default value in a
/// single database transaction (all-or-nothing). Default values are
/// canonical — they bypass [`validate_setting`] on purpose, and the
/// interval/session pair invariants hold for the seed table itself
/// (enforced by [`seed_settings`]). `concurrent_visits` is "restored" to
/// `1`, its canonical single-worker value.
///
/// Returns the number of keys written.
pub async fn restore_all_defaults(db: &Db) -> Result<usize, String> {
    // Re-assert the seed-table pair invariant before overwriting live data.
    check_default_pair(INTERVAL_PAIR).map_err(|e| e.to_string())?;
    check_default_pair(SESSION_PAIR).map_err(|e| e.to_string())?;
    let pairs: Vec<(&str, &str)> = SETTING_DEFAULTS.iter().map(|d| (d.key, d.value)).collect();
    db.reset_application_settings(&pairs)
        .await
        .map_err(|e| e.to_string())
}

/// Is `key` a boolean-typed setting? Returns `None` for unknown keys.
pub fn is_bool_key(key: &str) -> Option<bool> {
    default_for(key).map(|d| d.is_bool)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_with(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    fn valid_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("APP_PASSWORD", "correct-horse-battery"),
            ("ENCRYPTION_KEY", "0123456789abcdef"),
        ]
    }

    // --- resolve() ---

    #[test]
    fn valid_env_applies_defaults() {
        let cfg = Config::resolve(&env_with(&valid_env())).expect("valid env resolves");
        assert_eq!(cfg.database_path, PathBuf::from("./data/uptimepanda.db"));
        assert_eq!(cfg.backup_dir, PathBuf::from("./data/backups"));
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.bind_addr, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(cfg.tz, "Asia/Omsk");
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.app_password, "correct-horse-battery");
        assert_eq!(cfg.encryption_key, "0123456789abcdef");
    }

    #[test]
    fn explicit_env_values_are_used() {
        let mut pairs = valid_env();
        pairs.extend([
            ("DATABASE_PATH", "/app/data/uptimepanda.db"),
            ("BACKUP_DIR", "/app/data/backups"),
            ("PORT", "9090"),
            ("BIND_ADDR", "0.0.0.0"),
            ("TZ", "Europe/Berlin"),
            ("RUST_LOG", "debug"),
        ]);
        let cfg = Config::resolve(&env_with(&pairs)).expect("valid env resolves");
        assert_eq!(cfg.database_path, PathBuf::from("/app/data/uptimepanda.db"));
        assert_eq!(cfg.backup_dir, PathBuf::from("/app/data/backups"));
        assert_eq!(cfg.port, 9090);
        assert_eq!(cfg.bind_addr, IpAddr::from([0, 0, 0, 0]));
        assert_eq!(cfg.tz, "Europe/Berlin");
        assert_eq!(cfg.log_level, "debug");
    }

    #[test]
    fn invalid_tz_is_an_error() {
        for bogus in ["Mars/Olympus_Mons", "Omsk", "UTC+6"] {
            let mut pairs = valid_env();
            pairs.push(("TZ", bogus));
            let err = Config::resolve(&env_with(&pairs)).expect_err("invalid TZ must fail");
            assert!(err.contains("TZ"), "error names TZ {bogus:?}: {err}");
        }
    }

    #[test]
    fn missing_app_password_is_an_error() {
        let err = Config::resolve(&env_with(&[("ENCRYPTION_KEY", "0123456789abcdef")]))
            .expect_err("missing APP_PASSWORD must fail");
        assert!(
            err.contains("APP_PASSWORD"),
            "error names APP_PASSWORD: {err}"
        );
    }

    #[test]
    fn short_app_password_is_rejected() {
        let mut pairs = valid_env();
        pairs.retain(|(k, _)| *k != "APP_PASSWORD");
        pairs.push(("APP_PASSWORD", "short"));
        let err = Config::resolve(&env_with(&pairs)).expect_err("short password must fail");
        assert!(
            err.contains("APP_PASSWORD"),
            "error names APP_PASSWORD: {err}"
        );
    }

    #[test]
    fn short_encryption_key_is_rejected() {
        let mut pairs = valid_env();
        pairs.retain(|(k, _)| *k != "ENCRYPTION_KEY");
        pairs.push(("ENCRYPTION_KEY", "too-short"));
        let err = Config::resolve(&env_with(&pairs)).expect_err("short key must fail");
        assert!(
            err.contains("ENCRYPTION_KEY"),
            "error names ENCRYPTION_KEY: {err}"
        );
    }

    #[test]
    fn multiple_problems_are_all_listed() {
        let err = Config::resolve(&env_with(&[])).expect_err("empty env must fail");
        assert!(err.contains("APP_PASSWORD"), "lists APP_PASSWORD: {err}");
        assert!(
            err.contains("ENCRYPTION_KEY"),
            "lists ENCRYPTION_KEY: {err}"
        );
    }

    #[test]
    fn invalid_port_is_rejected() {
        let mut pairs = valid_env();
        pairs.push(("PORT", "not-a-port"));
        let err = Config::resolve(&env_with(&pairs)).expect_err("bad PORT must fail");
        assert!(err.contains("PORT"), "error names PORT: {err}");
    }

    #[test]
    fn out_of_range_port_is_rejected() {
        let mut pairs = valid_env();
        pairs.push(("PORT", "70000"));
        let err = Config::resolve(&env_with(&pairs)).expect_err("out-of-range PORT must fail");
        assert!(err.contains("PORT"), "error names PORT: {err}");
    }

    #[test]
    fn invalid_bind_addr_is_rejected() {
        let mut pairs = valid_env();
        pairs.push(("BIND_ADDR", "not-an-ip"));
        let err = Config::resolve(&env_with(&pairs)).expect_err("bad BIND_ADDR must fail");
        assert!(err.contains("BIND_ADDR"), "error names BIND_ADDR: {err}");
    }

    #[test]
    fn debug_impl_redacts_secrets() {
        let cfg = Config::resolve(&env_with(&valid_env())).expect("valid env resolves");
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("correct-horse-battery"),
            "password leaks in Debug: {dbg}"
        );
        assert!(
            !dbg.contains("0123456789abcdef"),
            "key leaks in Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "redaction marker present: {dbg}"
        );
    }

    // --- validate_setting() ---

    #[test]
    fn defaults_table_contains_exactly_the_23_keys() {
        assert_eq!(SETTING_DEFAULTS.len(), 23);
        let keys: Vec<&str> = SETTING_DEFAULTS.iter().map(|d| d.key).collect();
        let expected = [
            "memory_warn_mb",
            "memory_restart_mb",
            "browser_restart_timeout_s",
            "browser_respawn_delay_s",
            "concurrent_visits",
            "rss_poll_interval_s",
            "nav_timeout_s",
            "visit_timeout_s",
            "max_session_seconds_cap",
            "max_actions_per_sequence",
            "max_queue_length",
            "history_retention_days",
            "sqlite_maintenance_on_boot",
            "default_min_interval_seconds",
            "default_max_interval_seconds",
            "default_min_session_seconds",
            "default_max_session_seconds",
            "interaction_scroll_max_ops",
            "interaction_click_wait_max_ms",
            "ua_presets_enabled",
            "active_window_default",
            "db_size_warn_mb",
            "log_level",
        ];
        for e in expected {
            assert!(keys.contains(&e), "missing key {e}");
        }
        // Seed table values must all pass their own validation.
        for def in SETTING_DEFAULTS {
            validate_setting(def.key, def.value)
                .unwrap_or_else(|e| panic!("default for {} invalid: {e}", def.key));
        }
    }

    #[test]
    fn bounds_are_enforced() {
        assert!(validate_setting("memory_restart_mb", "50").is_err());
        assert!(validate_setting("memory_restart_mb", "96").is_ok());
        assert!(validate_setting("memory_restart_mb", "384").is_ok());
        assert!(validate_setting("memory_restart_mb", "385").is_err());
        assert!(validate_setting("memory_warn_mb", "64").is_ok());
        assert!(validate_setting("memory_warn_mb", "321").is_err());
        assert!(validate_setting("db_size_warn_mb", "16").is_ok());
        assert!(validate_setting("db_size_warn_mb", "1025").is_err());
        assert!(validate_setting("history_retention_days", "0").is_err());
        assert!(validate_setting("history_retention_days", "366").is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(validate_setting("no_such_key", "1").is_err());
    }

    #[test]
    fn bool_values_must_be_true_or_false() {
        assert!(validate_setting("ua_presets_enabled", "true").is_ok());
        assert!(validate_setting("ua_presets_enabled", "false").is_ok());
        assert!(validate_setting("ua_presets_enabled", "yes").is_err());
        assert!(validate_setting("ua_presets_enabled", "1").is_err());
        assert!(validate_setting("sqlite_maintenance_on_boot", "TRUE").is_err());
    }

    #[test]
    fn active_window_default_parse() {
        assert!(validate_setting("active_window_default", "24h").is_ok());
        assert!(validate_setting("active_window_default", "1h").is_ok());
        assert!(validate_setting("active_window_default", "168h").is_ok());
        assert!(validate_setting("active_window_default", "0h").is_err());
        assert!(validate_setting("active_window_default", "169h").is_err());
        assert!(validate_setting("active_window_default", "24").is_err());
        assert!(validate_setting("active_window_default", "abc").is_err());
        assert!(validate_setting("active_window_default", "h").is_err());
    }

    #[test]
    fn log_level_parse() {
        for level in ["trace", "debug", "info", "warn", "error"] {
            assert!(validate_setting("log_level", level).is_ok(), "{level}");
        }
        assert!(validate_setting("log_level", "verbose").is_err());
    }

    #[test]
    fn concurrent_visits_is_enforced_to_1() {
        assert!(validate_setting("concurrent_visits", "1").is_ok());
        let err = validate_setting("concurrent_visits", "2").expect_err("2 must be rejected");
        assert!(
            err.contains("single worker"),
            "explains the invariant: {err}"
        );
    }

    // --- DB-backed behavior ---

    #[tokio::test]
    async fn seed_is_idempotent() {
        let db = Db::in_memory().await.expect("open in-memory db");
        seed_settings(&db).await.expect("first seed");
        seed_settings(&db).await.expect("second seed");
        let rows = db.all_application_settings().await.expect("read settings");
        assert_eq!(rows.len(), SETTING_DEFAULTS.len());
        assert_eq!(rows.len(), 23);
    }

    #[tokio::test]
    async fn seed_preserves_user_edits() {
        let db = Db::in_memory().await.expect("open in-memory db");
        seed_settings(&db).await.expect("first seed");
        db.upsert_application_setting("memory_warn_mb", "180")
            .await
            .expect("edit");
        seed_settings(&db).await.expect("re-seed");
        let v = get_setting(&db, "memory_warn_mb").await.expect("read");
        assert_eq!(v, "180", "re-seed must not clobber user edits");
    }

    #[tokio::test]
    async fn get_setting_falls_back_to_default() {
        let db = Db::in_memory().await.expect("open in-memory db");
        let v = get_setting(&db, "memory_restart_mb")
            .await
            .expect("fallback");
        assert_eq!(v, "200");
        let v = typed_i64(&db, "memory_restart_mb")
            .await
            .expect("typed fallback");
        assert_eq!(v, 200);
        let v = typed_bool(&db, "ua_presets_enabled")
            .await
            .expect("bool fallback");
        assert!(v);
    }

    #[tokio::test]
    async fn get_setting_unknown_key_errors() {
        let db = Db::in_memory().await.expect("open in-memory db");
        assert!(get_setting(&db, "no_such_key").await.is_err());
    }

    #[tokio::test]
    async fn set_setting_rejects_out_of_bounds() {
        let db = Db::in_memory().await.expect("open in-memory db");
        seed_settings(&db).await.expect("seed");
        let err = set_setting(&db, "memory_restart_mb", "50")
            .await
            .expect_err("50 is out of bounds");
        assert!(err.contains("96"), "mentions the bound: {err}");
        let v = get_setting(&db, "memory_restart_mb")
            .await
            .expect("unchanged");
        assert_eq!(v, "200", "rejected write must not persist");
    }

    #[tokio::test]
    async fn set_setting_enforces_interval_pair() {
        let db = Db::in_memory().await.expect("open in-memory db");
        seed_settings(&db).await.expect("seed");
        // Default max is 780; raising min above it must fail.
        let err = set_setting(&db, "default_min_interval_seconds", "900")
            .await
            .expect_err("min > max must fail");
        assert!(err.contains("default_min_interval_seconds"), "{err}");
        // Raising max above current min is fine.
        set_setting(&db, "default_max_interval_seconds", "900")
            .await
            .expect("max >= min is allowed");
        // ... but then min may go up to 900 as well.
        set_setting(&db, "default_min_interval_seconds", "900")
            .await
            .expect("min == max is allowed");
        // And setting max below min fails.
        assert!(
            set_setting(&db, "default_max_interval_seconds", "100")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn set_setting_enforces_session_pair() {
        let db = Db::in_memory().await.expect("open in-memory db");
        seed_settings(&db).await.expect("seed");
        assert!(
            set_setting(&db, "default_min_session_seconds", "120")
                .await
                .is_err()
        );
        set_setting(&db, "default_max_session_seconds", "120")
            .await
            .expect("max raised");
        assert!(
            set_setting(&db, "default_max_session_seconds", "10")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn restore_default_overwrites_with_seed_value() {
        let db = Db::in_memory().await.expect("open in-memory db");
        seed_settings(&db).await.expect("seed");
        set_setting(&db, "nav_timeout_s", "60").await.expect("edit");
        restore_default(&db, "nav_timeout_s")
            .await
            .expect("restore");
        let v = get_setting(&db, "nav_timeout_s").await.expect("read");
        assert_eq!(v, "15");
        assert!(restore_default(&db, "no_such_key").await.is_err());
    }

    #[tokio::test]
    async fn effective_settings_covers_all_keys() {
        let db = Db::in_memory().await.expect("open in-memory db");
        let views = effective_settings(&db).await.expect("views");
        assert_eq!(views.len(), 23);
        let warn = views
            .iter()
            .find(|v| v.key == "memory_warn_mb")
            .expect("key");
        assert_eq!(warn.value, "160");
        assert_eq!(warn.default, "160");
        assert_eq!(warn.min, Some(64));
        assert_eq!(warn.max, Some(320));
        assert!(!warn.is_bool);
        assert!(!warn.help.is_empty());
        let maint = views
            .iter()
            .find(|v| v.key == "sqlite_maintenance_on_boot")
            .expect("key");
        assert!(maint.is_bool);
        assert_eq!(maint.value, "true");
    }

    #[test]
    fn seed_default_table_pairs_are_consistent() {
        // Belt-and-braces: the seed table itself must satisfy min <= max.
        check_default_pair(INTERVAL_PAIR).expect("interval pair consistent");
        check_default_pair(SESSION_PAIR).expect("session pair consistent");
    }
}
