// Browser sessions — named profiles, encrypted per-profile cookie jars,
// UA compatibility presets. Consumed by SEG-10 (visit executor) and
// SEG-11 (profiles page); until then only the in-crate tests exercise it.
#![allow(dead_code)]

//! Profile lifecycle for visits to Lightpanda — without any browser-context API.
//!
//! # Why sequential, not parallel
//! Phase 0 (`docs/phase0-validation.md` §5) verified that Lightpanda 1.0.3
//! supports **exactly one browser context at a time** (`Target.createBrowserContext`
//! twice → `-32000 "Cannot have more than one browser context at a time"`;
//! `Target.createBrowserContext`/`disposeBrowserContext` otherwise works).
//! Parallel isolated per-profile contexts are therefore impossible. Instead:
//!
//! `with_sequential_isolation` semantics — one shared browser, one profile
//! visit at a time, cookies round-tripped per visit:
//!
//! 1. **Fresh page target per visit.** The executor opens a new target for
//!    every visit ([`crate::browser::cdp::CdpHandle::open_page`]); nothing
//!    about the page (DOM, JS state) survives the visit.
//! 2. **Cookie jar restored before navigation.** After `Page.enable` +
//!    `Network.enable` (inside `open_page`) and **before** the first
//!    navigation, the saved jar for the visit's profile is re-installed via
//!    `PageSession::set_cookies`.
//! 3. **Jar captured after visit end.** After the session hold ends and
//!    before the target is closed, the live jar is read via
//!    `PageSession::get_cookies` and handed to
//!    [`ProfileSession::persist_after_visit`], which (encrypted) replaces the
//!    stored jar wholesale.
//! 4. **Target closed.** The target is closed before the next profile gets
//!    the browser; the context itself persists across targets.
//!
//! ## Residual risk (read this, SEG-10)
//! Cookies restored for profile A remain visible to the *same browser
//! context* after visit A ends, even if A's target is closed. Profile B's
//! navigation would therefore see profile A's cookies **unless B's visit
//! also starts from a clean restore**. The round-trip above is only safe if
//! **both** steps always happen: capture A's jar *and* restore B's jar
//! before B navigates. There is no in-engine isolation to fall back on —
//! if a step is skipped (e.g. the executor closes the target before
//! capturing the jar), cookies leak across profiles on the next visit.
//!
//! Mitigation: this module is the only place that reads/writes jars; the
//! executor must pair `to_cookie_inputs` (pre-navigation) with
//! `persist_after_visit` (post-visit, before `Target.closeTarget`) for every
//! visit, for every profile — no exceptions for "basic" mode. The window
//! system is responsible for ordering (SEG-08 scheduler runs one worker;
//! 1 concurrent visit is enforced by the app, and the manager's `visit_gate`
//! serializes the browser).
//!
//! Additional hardening available (not wired yet, SEG-10/SEG-06 territory):
//! dispose + recreate the single browser context per profile visit
//! (`Target.disposeBrowserContext` → `createBrowserContext`). That gives
//! hard isolation at the cost of losing context-global state; it requires a
//! manager-level change and is documented here, not implemented.
//!
//! # UA presets are compatibility testing only
//! Every user-visible surface that shows or uses a UA preset must carry
//! [`USER_AGENT_OVERRIDE_LABEL`]. `Network.setUserAgentOverride` /
//! `Emulation.setUserAgentOverride` are accepted by Lightpanda 1.0.3 but
//! are a **verified no-op** — they never change the UA on the wire or in
//! JS, and the CLI flag rejects any string containing `Mozilla`. The
//! presets therefore exist as configuration + forward-compat wire traffic,
//! nothing more. No fingerprint spoofing features (canvas noise, plugin
//! lists, etc.) exist in this codebase and none may be added.
//!
//! # Cookie encryption at rest
//! Every `cookies.encrypted_cookie_data` value is an `enc:v1:` envelope
//! (see [`crate::browser::cookies`]). The passphrase is received as a
//! `&str` argument — this module never reads the environment. Plaintext
//! cookie bytes never touch disk, logs, or `Debug` output.

use std::collections::BTreeMap;
use std::fmt;

use time::OffsetDateTime;
use tracing::debug;

use crate::browser::cdp::{CookieInput, PageSession};
use crate::browser::cookies::{
    CookieCryptoError, StoredCookie, StoredDomainJar, decode_domain_jar, encode_domain_jar,
};
use crate::db::{BrowserProfile, Db, DbError};

/// Label that must accompany every UA preset surface (UI, logs, docs).
/// Exact wording per Phase 0 findings.
pub const USER_AGENT_OVERRIDE_LABEL: &str = "User-agent override (compatibility testing only) — does not reproduce the engine, OS, hardware, or network characteristics of the real browser.";

/// Maximum accepted length of a (custom) user-agent string, in bytes.
/// Longer values are rejected at the persistence boundary and resolve to
/// "engine default" (see [`resolve_user_agent`]).
pub const MAX_USER_AGENT_LEN: usize = 512;

/// Session cookie marker inside a [`StoredCookie`]: `expires = -1.0`.
/// (`CookieInput::expires == 0.0` is the CDP-side representation, omitted on
/// the wire.)
const SESSION_EXPIRY: f64 = -1.0;

/// Errors surfaced by the profile/cookie lifecycle.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Profile is missing, or exists but is disabled.
    #[error("invalid profile: {0}")]
    InvalidProfile(String),
    /// Cookie decryption failed (wrong passphrase or tampered blob). No
    /// oracle detail is attached.
    #[error(transparent)]
    Crypto(#[from] CookieCryptoError),
    /// A stored jar row was structurally unusable (not valid JSON).
    #[error("corrupt cookie jar for domain {0:?}")]
    JarCorrupt(String),
    /// Database failure.
    #[error(transparent)]
    Db(#[from] DbError),
    /// JSON (de)serialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// One entry of the static UA preset catalogue. Not persisted anywhere —
/// `browser_profiles.user_agent` stores the resolved string.
#[derive(Debug, Clone, Copy)]
pub struct UserAgentPreset {
    /// Stable identifier used by the UI/config (`select` value).
    pub id: &'static str,
    /// Short human label for the preset (the compatibility label lives in
    /// [`USER_AGENT_OVERRIDE_LABEL`], rendered next to it by the UI).
    pub label: &'static str,
    /// The UA string sent (as a no-op on Lightpanda 1.0.3) when chosen.
    /// Contains `Mozilla/5.0` by design — that is the point of
    /// `Network.setUserAgentOverride`; no constraint applies here.
    pub ua: &'static str,
}

/// Static catalogue of UA compatibility presets (NOT profiles, NOT settings).
///
/// UA strings reflect stable releases as of 2026-11 (Chrome 142, Firefox 144,
/// iOS/Safari 26) — **refresh periodically**; these are compile-time
/// catalogue entries, never fetched or generated at runtime.
pub const USER_AGENT_PRESETS: &[UserAgentPreset] = &[
    UserAgentPreset {
        id: "desktop-chrome",
        label: "Desktop Chrome (compatibility)",
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    },
    UserAgentPreset {
        id: "desktop-firefox",
        label: "Desktop Firefox (compatibility)",
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
    },
    UserAgentPreset {
        id: "mobile-chrome",
        label: "Mobile Chrome — Android (compatibility)",
        ua: "Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
    },
    UserAgentPreset {
        id: "mobile-safari",
        label: "Mobile Safari — iOS (compatibility)",
        ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 26_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/604.1",
    },
];

/// Resolve a UA selection to the string to send on the wire.
///
/// - `custom` (trimmed) wins when provided and non-empty.
/// - otherwise `selection` may name a preset id (see [`USER_AGENT_PRESETS`]).
/// - returns `None` for "engine default": no selection, unknown preset id,
///   or a custom string longer than [`MAX_USER_AGENT_LEN`] (such input is
///   **rejected**: executors proceed with the engine default, and the
///   persistence boundary — `Db::create_profile` / `Db::update_profile` —
///   refuses to store it, so over-long values never reach this function
///   from validated profiles).
pub fn resolve_user_agent(selection: Option<&str>, custom: Option<&str>) -> Option<String> {
    if let Some(custom) = custom {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            // Over-long input is rejected outright (engine default).
            return (trimmed.len() <= MAX_USER_AGENT_LEN).then(|| trimmed.to_string());
        }
    }
    selection
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|id| USER_AGENT_PRESETS.iter().find(|p| p.id == id))
        .map(|p| p.ua.to_string())
}

/// Apply the resolved identity for a visit. Thin wrapper so SEG-10 has one
/// call site: passes `ua` to the page session's
/// `Network.setUserAgentOverride` (a **verified no-op on Lightpanda 1.0.3**).
///
/// Call exactly once per visit — either via `CdpHandle::open_page(url, ua)`
/// at open time, or via this function immediately after `open_page(url, None)`.
/// Never both (harmless on 1.0.3, but wasteful). `None` means engine default;
/// errors from the wire command are logged and swallowed — UA override must
/// never fail a visit.
pub async fn apply_identity(session: &PageSession, ua: Option<&str>) {
    if let Some(ua) = ua
        && let Err(e) = session.set_user_agent_override(ua).await
    {
        debug!(error = %e, "ua override failed; continuing with engine default");
    }
}

/// Statistics from [`ProfileSession::persist_after_visit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PersistStats {
    /// Domain jars written (one row each).
    pub jars_written: u64,
    /// Cookies stored (after the expiry sweep).
    pub cookies_written: u64,
    /// Live cookies dropped by the expiry sweep before storing.
    pub expired_dropped: u64,
    /// Live cookies skipped because they carried no domain (CDP jars always
    /// carry one; this is defensive).
    pub domainless_dropped: u64,
}

/// A loaded, enabled profile plus the database handle. Holds no CDP state —
/// the cookie jar round-trip is all this type knows about the browser.
///
/// `Debug` prints the profile row only (no cookie data).
pub struct ProfileSession {
    db: Db,
    profile: BrowserProfile,
}

impl fmt::Debug for ProfileSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileSession")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl ProfileSession {
    /// Load profile by id. Fails with [`SessionError::InvalidProfile`] when
    /// the profile is missing or disabled.
    pub async fn load_profile(db: Db, id: i64) -> Result<Self, SessionError> {
        let profile = db
            .profile_by_id(id)
            .await?
            .ok_or_else(|| SessionError::InvalidProfile(format!("profile id {id} not found")))?;
        if !profile.enabled {
            return Err(SessionError::InvalidProfile(format!(
                "profile id {id} ({:?}) is disabled",
                profile.name
            )));
        }
        Ok(Self { db, profile })
    }

    /// The underlying profile row.
    pub fn profile(&self) -> &BrowserProfile {
        &self.profile
    }

    /// The UA string to send for this profile (preset-resolved string stored
    /// in the row, or `None` for the engine default).
    ///
    /// Note this is whatever was stored — resolution happens at configuration
    /// time via [`resolve_user_agent`]; the stored value is trusted as-is
    /// (it was validated on write).
    pub fn user_agent(&self) -> Option<&str> {
        self.profile.user_agent.as_deref()
    }

    /// Decrypt every jar of this profile and return a flattened,
    /// expiry-swept list of cookies ready for `Network.setCookies`.
    ///
    /// Cookies with `expires <= now` (and not session cookies) are dropped.
    /// A jar that fails to decrypt aborts the whole restore — callers must
    /// surface the error rather than navigate with a partial jar.
    pub async fn to_cookie_inputs(
        &self,
        passphrase: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<CookieInput>, SessionError> {
        let now_epoch = now.unix_timestamp() as f64;
        let records = self.db.list_cookie_jars(self.profile.id).await?;
        let mut out = Vec::new();
        for record in &records {
            let bytes = crate::browser::cookies::decrypt_cookie_blob(
                passphrase,
                &record.encrypted_cookie_data,
            )?;
            let jar = decode_domain_jar(&bytes)
                .map_err(|_| SessionError::JarCorrupt(record.domain.clone()))?;
            for cookie in &jar.cookies {
                if cookie.expires != SESSION_EXPIRY && cookie.expires <= now_epoch {
                    continue; // expired — sweep on use
                }
                out.push(stored_to_cookie_input(cookie));
            }
        }
        Ok(out)
    }

    /// Persist the live post-visit jar, replacing the stored one wholesale.
    ///
    /// **Merge policy — replace, not merge.** The live jar read from the
    /// browser after the visit is the authoritative post-visit state (the
    /// site may have set, overwritten *or deleted* cookies; a server-side
    /// deletion appears as absence in the live jar). The stored jar is
    /// therefore replaced atomically (single transaction): deletions
    /// propagate, no stale cookies linger, and there is no identity-keyed
    /// merge to get subtly wrong. Expired cookies are swept before storage.
    ///
    /// `live` items with `expires == 0.0` are session cookies; `expires` in
    /// the past (and non-zero) are dropped. Items with no `domain` are
    /// skipped (defensive; CDP jars always carry one).
    pub async fn persist_after_visit(
        &self,
        passphrase: &str,
        now: OffsetDateTime,
        live: Vec<CookieInput>,
    ) -> Result<PersistStats, SessionError> {
        let now_epoch = now.unix_timestamp() as f64;
        let mut stats = PersistStats::default();
        let mut by_domain: BTreeMap<String, Vec<StoredCookie>> = BTreeMap::new();

        for input in &live {
            if input.expires != 0.0 && input.expires <= now_epoch {
                stats.expired_dropped += 1;
                continue;
            }
            if input.domain.is_empty() {
                stats.domainless_dropped += 1;
                continue;
            }
            let domain = input.domain.clone();
            by_domain
                .entry(domain.clone())
                .or_default()
                .push(cookie_input_to_stored(input));
        }

        let mut jars: Vec<(String, String, Option<OffsetDateTime>)> =
            Vec::with_capacity(by_domain.len());
        for (domain, cookies) in by_domain {
            stats.cookies_written += cookies.len() as u64;
            let jar = StoredDomainJar {
                domain: domain.clone(),
                cookies,
            };
            let plaintext = encode_domain_jar(&jar)?;
            let blob = crate::browser::cookies::encrypt_cookie_blob(passphrase, &plaintext);
            jars.push((domain, blob, jar_expiry(&jar)));
        }
        stats.jars_written = jars.len() as u64;
        self.db
            .replace_profile_cookies(self.profile.id, jars)
            .await?;
        Ok(stats)
    }

    /// Delete every stored cookie jar for this profile. Returns rows deleted.
    pub async fn clear_cookies(&self) -> Result<u64, SessionError> {
        Ok(self.db.delete_profile_cookies(self.profile.id).await?)
    }

    /// Delete the stored jar for one domain. Returns rows deleted (0 or 1).
    pub async fn clear_cookies_for_domain(&self, domain: &str) -> Result<u64, SessionError> {
        Ok(self
            .db
            .delete_profile_cookies_for_domain(self.profile.id, domain)
            .await?)
    }

    /// "Reset profile" = clear cookies only; the profile row (and its
    /// websites' references to it) survives. Returns rows deleted.
    pub async fn reset_profile(&self) -> Result<u64, SessionError> {
        self.clear_cookies().await
    }
}

/// Convert a CDP-side cookie into its stored form.
fn cookie_input_to_stored(input: &CookieInput) -> StoredCookie {
    StoredCookie {
        name: input.name.clone(),
        value: input.value.clone(),
        domain: input.domain.clone(),
        path: if input.path.is_empty() {
            "/".to_string()
        } else {
            input.path.clone()
        },
        secure: input.secure,
        http_only: input.http_only,
        same_site: input.same_site.clone(),
        expires: if input.expires == 0.0 {
            SESSION_EXPIRY
        } else {
            input.expires
        },
    }
}

/// Convert a stored cookie back into its CDP-side form for `setCookies`.
fn stored_to_cookie_input(cookie: &StoredCookie) -> CookieInput {
    CookieInput {
        name: cookie.name.clone(),
        value: cookie.value.clone(),
        url: None,
        domain: cookie.domain.clone(),
        path: cookie.path.clone(),
        expires: if cookie.expires == SESSION_EXPIRY {
            0.0 // omitted on the wire → session cookie
        } else {
            cookie.expires
        },
        http_only: cookie.http_only,
        secure: cookie.secure,
        same_site: cookie.same_site.clone(),
    }
}

/// `expires_at` for a stored jar row: the **maximum** per-cookie expiry, or
/// `NULL` if any cookie in the jar is a session cookie.
fn jar_expiry(jar: &StoredDomainJar) -> Option<OffsetDateTime> {
    let mut max_expiry: Option<f64> = None;
    for cookie in &jar.cookies {
        if cookie.expires == SESSION_EXPIRY {
            return None; // any session cookie → NULL, per schema contract
        }
        max_expiry = Some(max_expiry.map_or(cookie.expires, |m: f64| m.max(cookie.expires)));
    }
    max_expiry.and_then(|secs| OffsetDateTime::from_unix_timestamp(secs as i64).ok())
}

/// Seed the two starter compatibility profiles on first boot. Idempotent by
/// name — existing rows are never touched. Returns the number inserted
/// (0 on re-run).
///
/// Profile descriptions carry [`USER_AGENT_OVERRIDE_LABEL`] verbatim, so any
/// UI surface listing these profiles shows the required label with the UA.
pub async fn seed_default_profiles(db: &Db) -> Result<usize, DbError> {
    let chrome_ua = USER_AGENT_PRESETS
        .iter()
        .find(|p| p.id == "desktop-chrome")
        .map(|p| p.ua)
        .expect("desktop-chrome preset exists");
    let firefox_ua = USER_AGENT_PRESETS
        .iter()
        .find(|p| p.id == "desktop-firefox")
        .map(|p| p.ua)
        .expect("desktop-firefox preset exists");

    const SEEDS: [(&str, &str); 2] = [
        ("Desktop Chrome compatibility profile", "desktop-chrome"),
        ("Desktop Firefox compatibility profile", "desktop-firefox"),
    ];

    let mut inserted = 0usize;
    for (name, preset_id) in SEEDS {
        if db.profile_by_name(name).await?.is_some() {
            continue;
        }
        let ua = match preset_id {
            "desktop-chrome" => chrome_ua,
            _ => firefox_ua,
        };
        let now = OffsetDateTime::now_utc();
        let profile = BrowserProfile {
            id: 0,
            name: name.to_string(),
            description: USER_AGENT_OVERRIDE_LABEL.to_string(),
            user_agent: Some(ua.to_string()),
            enabled: true,
            configuration_json: "{}".to_string(),
            created_at: now,
            updated_at: now,
        };
        db.create_profile(&profile).await?;
        inserted += 1;
    }
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    const PASS: &str = "test-passphrase-0123456789";

    /// 2027-01-15T08:00:00Z — comfortably in the past/future relative to
    /// cookie expiries used below.
    fn base_now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp")
    }

    fn live_cookie(name: &str, value: &str, domain: &str, expires: f64) -> CookieInput {
        CookieInput {
            name: name.to_string(),
            value: value.to_string(),
            url: None,
            domain: domain.to_string(),
            path: "/".to_string(),
            expires,
            http_only: true,
            secure: true,
            same_site: Some("Lax".to_string()),
        }
    }

    fn sample_profile(name: &str) -> BrowserProfile {
        let now = base_now();
        BrowserProfile {
            id: 0,
            name: name.to_string(),
            description: "test profile".to_string(),
            user_agent: None,
            enabled: true,
            configuration_json: "{}".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    async fn raw_cookie_rows(db: &Db) -> Vec<(String, Option<String>)> {
        db.connection()
            .call(|c| -> rusqlite::Result<Vec<(String, Option<String>)>> {
                let mut stmt = c.prepare(
                    "SELECT encrypted_cookie_data, expires_at FROM cookies ORDER BY domain",
                )?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .expect("raw cookie query")
    }

    async fn create_and_load(db: &Db, name: &str) -> ProfileSession {
        let id = db
            .create_profile(&sample_profile(name))
            .await
            .expect("create profile");
        ProfileSession::load_profile(db.clone(), id)
            .await
            .expect("load profile")
    }

    // --- UA preset resolution ---

    #[test]
    fn presets_resolve_by_id() {
        for preset in USER_AGENT_PRESETS {
            let resolved = resolve_user_agent(Some(preset.id), None);
            assert_eq!(resolved, Some(preset.ua.to_string()));
            assert!(resolved.as_deref().unwrap().contains("Mozilla/5.0"));
        }
        assert!(USER_AGENT_PRESETS.iter().any(|p| p.id == "desktop-chrome"));
        assert!(USER_AGENT_PRESETS.iter().any(|p| p.id == "desktop-firefox"));
        assert!(USER_AGENT_PRESETS.iter().any(|p| p.id == "mobile-chrome"));
        assert!(USER_AGENT_PRESETS.iter().any(|p| p.id == "mobile-safari"));
    }

    #[test]
    fn custom_agent_wins_over_preset() {
        let resolved = resolve_user_agent(Some("desktop-chrome"), Some("MyAgent/1.0"));
        assert_eq!(resolved.as_deref(), Some("MyAgent/1.0"));
    }

    #[test]
    fn custom_agent_containing_mozilla_is_allowed() {
        // The network override has no Mozilla constraint (the CLI does; we
        // never use the CLI path) — presets exist precisely to carry it.
        let ua = "Mozilla/5.0 (Test) Chrome/142.0.0.0 Safari/537.36";
        assert_eq!(resolve_user_agent(None, Some(ua)).as_deref(), Some(ua));
    }

    #[test]
    fn absent_selection_means_engine_default() {
        assert_eq!(resolve_user_agent(None, None), None);
        assert_eq!(resolve_user_agent(Some(""), None), None);
        assert_eq!(resolve_user_agent(Some("   "), None), None);
        assert_eq!(resolve_user_agent(None, Some("")), None);
        assert_eq!(resolve_user_agent(None, Some("   ")), None);
    }

    #[test]
    fn unknown_preset_id_means_engine_default() {
        assert_eq!(resolve_user_agent(Some("netscape-navigator"), None), None);
    }

    #[test]
    fn whitespace_only_custom_falls_back_to_selection() {
        let resolved = resolve_user_agent(Some("desktop-firefox"), Some("   "));
        assert!(resolved.as_deref().unwrap().contains("Firefox/144"));
    }

    #[test]
    fn custom_longer_than_512_bytes_is_rejected() {
        let long = "A".repeat(MAX_USER_AGENT_LEN + 1);
        assert_eq!(
            resolve_user_agent(Some("desktop-chrome"), Some(&long)),
            None
        );
        let exact = "A".repeat(MAX_USER_AGENT_LEN);
        assert_eq!(
            resolve_user_agent(None, Some(&exact)).as_deref(),
            Some(exact.as_str())
        );
    }

    #[test]
    fn override_label_is_exact_and_present_in_seed_profiles() {
        assert_eq!(
            USER_AGENT_OVERRIDE_LABEL,
            "User-agent override (compatibility testing only) — does not reproduce the engine, OS, hardware, or network characteristics of the real browser."
        );
    }

    // --- Profile CRUD ---

    #[tokio::test]
    async fn profile_crud_roundtrip() {
        let db = Db::in_memory().await.expect("open db");
        let id = db
            .create_profile(&sample_profile("alpha"))
            .await
            .expect("create");
        let fetched = db.profile_by_id(id).await.expect("fetch").expect("exists");
        assert_eq!(fetched.name, "alpha");

        let mut updated = fetched.clone();
        updated.description = "new description".to_string();
        updated.configuration_json = r#"{"viewport":"1280x800"}"#.to_string();
        assert!(db.update_profile(&updated).await.expect("update"));
        let fetched = db.profile_by_id(id).await.expect("fetch").expect("exists");
        assert_eq!(fetched.description, "new description");
        assert_eq!(fetched.configuration_json, r#"{"viewport":"1280x800"}"#);

        assert!(db.set_profile_enabled(id, false).await.expect("disable"));
        let disabled = db.profile_by_id(id).await.expect("fetch").expect("exists");
        assert!(!disabled.enabled);
        assert!(db.set_profile_enabled(id, true).await.expect("enable"));

        let names: Vec<String> = db
            .list_profiles()
            .await
            .expect("list")
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, vec!["alpha"]);
        assert_eq!(db.profile_by_name("alpha").await.unwrap().unwrap().id, id);

        assert!(db.delete_profile(id).await.expect("delete"));
        assert!(db.profile_by_id(id).await.expect("fetch").is_none());
        // Deleting again is a no-op.
        assert!(!db.delete_profile(id).await.expect("delete again"));
    }

    #[tokio::test]
    async fn create_profile_rejects_overlong_user_agent() {
        let db = Db::in_memory().await.expect("open db");
        let mut profile = sample_profile("too-long-ua");
        profile.user_agent = Some("A".repeat(MAX_USER_AGENT_LEN + 1));
        let err = db.create_profile(&profile).await.expect_err("too long");
        assert!(matches!(err, DbError::Validation(_)));
    }

    #[tokio::test]
    async fn load_profile_rejects_missing_and_disabled() {
        let db = Db::in_memory().await.expect("open db");
        let err = ProfileSession::load_profile(db.clone(), 4242)
            .await
            .expect_err("missing profile");
        assert!(matches!(err, SessionError::InvalidProfile(_)));

        let id = db
            .create_profile(&sample_profile("disabled-profile"))
            .await
            .expect("create");
        db.set_profile_enabled(id, false).await.expect("disable");
        let err = ProfileSession::load_profile(db.clone(), id)
            .await
            .expect_err("disabled profile");
        assert!(matches!(err, SessionError::InvalidProfile(_)));

        db.set_profile_enabled(id, true).await.expect("enable");
        ProfileSession::load_profile(db.clone(), id)
            .await
            .expect("enabled profile loads");
    }

    // --- Cookie persist / restore ---

    #[tokio::test]
    async fn persist_then_restore_roundtrip() {
        let db = Db::in_memory().await.expect("open db");
        let session = create_and_load(&db, "jar-roundtrip").await;
        let now = base_now();
        let live = vec![
            live_cookie("session", "supersecret-token", ".example.com", 0.0),
            live_cookie("prefs", "lang=de", ".example.com", 1_900_000_000.0),
            live_cookie("other", "v", "other.example.net", 1_900_000_000.0),
        ];
        let stats = session
            .persist_after_visit(PASS, now, live)
            .await
            .expect("persist");
        assert_eq!(stats.jars_written, 2);
        assert_eq!(stats.cookies_written, 3);
        assert_eq!(stats.expired_dropped, 0);

        let restored = session.to_cookie_inputs(PASS, now).await.expect("restore");
        assert_eq!(restored.len(), 3);
        let session_cookie = restored
            .iter()
            .find(|c| c.name == "session")
            .expect("session cookie restored");
        assert_eq!(session_cookie.value, "supersecret-token");
        assert_eq!(session_cookie.expires, 0.0); // session on the wire
        let prefs = restored
            .iter()
            .find(|c| c.name == "prefs")
            .expect("prefs restored");
        assert_eq!(prefs.expires, 1_900_000_000.0);
    }

    #[tokio::test]
    async fn expired_cookies_are_swept_at_restore() {
        let db = Db::in_memory().await.expect("open db");
        let session = create_and_load(&db, "jar-expiry").await;
        let now = base_now();
        // Persist a cookie expiring 100s after `now`.
        session
            .persist_after_visit(
                PASS,
                now,
                vec![live_cookie(
                    "shortlived",
                    "v",
                    ".exp.test",
                    now.unix_timestamp() as f64 + 100.0,
                )],
            )
            .await
            .expect("persist");
        let at_restore = session
            .to_cookie_inputs(PASS, now)
            .await
            .expect("restore at t");
        assert_eq!(at_restore.len(), 1);
        let later = now + Duration::seconds(200);
        let at_later = session
            .to_cookie_inputs(PASS, later)
            .await
            .expect("restore at t+200");
        assert_eq!(at_later.len(), 0, "expired cookie must be swept");
    }

    #[tokio::test]
    async fn expired_live_cookies_are_not_stored() {
        let db = Db::in_memory().await.expect("open db");
        let session = create_and_load(&db, "jar-sweep").await;
        let now = base_now();
        let stats = session
            .persist_after_visit(
                PASS,
                now,
                vec![
                    live_cookie(
                        "dead",
                        "v",
                        ".sweep.test",
                        now.unix_timestamp() as f64 - 1.0,
                    ),
                    live_cookie(
                        "alive",
                        "v",
                        ".sweep.test",
                        now.unix_timestamp() as f64 + 100.0,
                    ),
                ],
            )
            .await
            .expect("persist");
        assert_eq!(stats.expired_dropped, 1);
        assert_eq!(stats.cookies_written, 1);
    }

    #[tokio::test]
    async fn persist_replaces_jar_and_deletions_propagate() {
        let db = Db::in_memory().await.expect("open db");
        let session = create_and_load(&db, "jar-replace").await;
        let now = base_now();

        session
            .persist_after_visit(
                PASS,
                now,
                vec![
                    live_cookie("a", "1", ".replace.test", 1_900_000_000.0),
                    live_cookie("b", "2", ".replace.test", 1_900_000_000.0),
                ],
            )
            .await
            .expect("persist v1");

        // Second visit: live jar has `a` overwritten and `b` deleted.
        session
            .persist_after_visit(
                PASS,
                now,
                vec![live_cookie("a", "2", ".replace.test", 1_900_000_000.0)],
            )
            .await
            .expect("persist v2");

        let restored = session.to_cookie_inputs(PASS, now).await.expect("restore");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].name, "a");
        assert_eq!(restored[0].value, "2");

        // Persisting an empty live jar clears everything.
        session
            .persist_after_visit(PASS, now, vec![])
            .await
            .expect("persist empty");
        assert!(raw_cookie_rows(&db).await.is_empty());
    }

    #[tokio::test]
    async fn session_cookie_yields_null_expires_at() {
        let db = Db::in_memory().await.expect("open db");
        let session = create_and_load(&db, "jar-session-expiry").await;
        let now = base_now();
        session
            .persist_after_visit(
                PASS,
                now,
                vec![
                    live_cookie("sess", "v", ".sess.test", 0.0),
                    live_cookie("dated", "v", ".sess.test", 1_900_000_000.0),
                ],
            )
            .await
            .expect("persist");
        let rows = raw_cookie_rows(&db).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, None, "any session cookie → NULL expires_at");

        // Dated-only jar → expires_at = max expiry.
        session
            .persist_after_visit(
                PASS,
                now,
                vec![live_cookie("dated", "v", ".sess.test", 1_900_000_000.0)],
            )
            .await
            .expect("persist dated only");
        let rows = raw_cookie_rows(&db).await;
        assert_eq!(
            rows[0].1.as_deref(),
            Some("2030-03-17T17:46:40.000Z"),
            "max expiry, DB timestamp shape"
        );
    }

    #[tokio::test]
    async fn encryption_at_rest_no_plaintext_in_rows() {
        let db = Db::in_memory().await.expect("open db");
        let session = create_and_load(&db, "jar-at-rest").await;
        let now = base_now();
        session
            .persist_after_visit(
                PASS,
                now,
                vec![live_cookie("token", "supersecret-token", ".rest.test", 0.0)],
            )
            .await
            .expect("persist");
        let rows = raw_cookie_rows(&db).await;
        assert_eq!(rows.len(), 1);
        let (blob, _) = &rows[0];
        assert!(
            blob.starts_with("enc:v1:"),
            "envelope prefix present: {blob}"
        );
        assert!(
            !blob.contains("supersecret-token"),
            "plaintext leaked into cookies table"
        );
    }

    #[tokio::test]
    async fn wrong_passphrase_cannot_restore() {
        let db = Db::in_memory().await.expect("open db");
        let session = create_and_load(&db, "jar-wrong-key").await;
        let now = base_now();
        session
            .persist_after_visit(
                PASS,
                now,
                vec![live_cookie("k", "supersecret-token", ".key.test", 0.0)],
            )
            .await
            .expect("persist");
        let err = session
            .to_cookie_inputs("wrong-passphrase-xxxxx", now)
            .await
            .expect_err("wrong key must fail");
        assert!(matches!(
            err,
            SessionError::Crypto(CookieCryptoError::DecryptionFailed)
        ));
    }

    // --- Clear / reset paths ---

    #[tokio::test]
    async fn clear_cookies_paths() {
        let db = Db::in_memory().await.expect("open db");
        let session = create_and_load(&db, "jar-clear").await;
        let now = base_now();
        session
            .persist_after_visit(
                PASS,
                now,
                vec![
                    live_cookie("a", "1", ".a.test", 1_900_000_000.0),
                    live_cookie("b", "2", ".b.test", 1_900_000_000.0),
                ],
            )
            .await
            .expect("persist");

        assert_eq!(
            session.clear_cookies_for_domain(".a.test").await.unwrap(),
            1
        );
        assert_eq!(
            session.clear_cookies_for_domain(".a.test").await.unwrap(),
            0
        );
        let rows = raw_cookie_rows(&db).await;
        assert_eq!(rows.len(), 1);

        // Reset clears the rest but keeps the profile row.
        assert_eq!(session.reset_profile().await.unwrap(), 1);
        assert!(raw_cookie_rows(&db).await.is_empty());
        assert!(
            db.profile_by_id(session.profile().id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn delete_profile_cascades_cookies() {
        let db = Db::in_memory().await.expect("open db");
        let session = create_and_load(&db, "jar-cascade").await;
        let profile_id = session.profile().id;
        let now = base_now();
        session
            .persist_after_visit(
                PASS,
                now,
                vec![live_cookie("a", "1", ".cascade.test", 1_900_000_000.0)],
            )
            .await
            .expect("persist");
        assert_eq!(raw_cookie_rows(&db).await.len(), 1);
        drop(session);
        assert!(db.delete_profile(profile_id).await.unwrap());
        assert!(
            raw_cookie_rows(&db).await.is_empty(),
            "FK cascade must clear cookies"
        );
    }

    // --- Seed ---

    #[tokio::test]
    async fn seed_default_profiles_is_idempotent() {
        let db = Db::in_memory().await.expect("open db");
        let first = seed_default_profiles(&db).await.expect("first seed");
        assert_eq!(first, 2);
        let second = seed_default_profiles(&db).await.expect("second seed");
        assert_eq!(second, 0);

        let profiles = db.list_profiles().await.expect("list");
        assert_eq!(profiles.len(), 2);
        let chrome = profiles
            .iter()
            .find(|p| p.name == "Desktop Chrome compatibility profile")
            .expect("chrome seed");
        let firefox = profiles
            .iter()
            .find(|p| p.name == "Desktop Firefox compatibility profile")
            .expect("firefox seed");
        assert!(chrome.enabled && firefox.enabled);
        assert!(chrome.user_agent.as_deref().unwrap().contains("Chrome/142"));
        assert!(
            firefox
                .user_agent
                .as_deref()
                .unwrap()
                .contains("Firefox/144")
        );
        // Both carry the required compatibility label.
        assert_eq!(chrome.description, USER_AGENT_OVERRIDE_LABEL);
        assert_eq!(firefox.description, USER_AGENT_OVERRIDE_LABEL);

        // A user-edited row with the same name is never overwritten.
        let mut edited = chrome.clone();
        edited.description = "user-edited".to_string();
        db.update_profile(&edited).await.expect("edit");
        let third = seed_default_profiles(&db).await.expect("third seed");
        assert_eq!(third, 0);
        let chrome = db
            .profile_by_name("Desktop Chrome compatibility profile")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chrome.description, "user-edited");
    }
}
