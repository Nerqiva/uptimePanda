//! Shared application state (SEG-11).
//!
//! Hoisted once in `main` and handed to the router. Cheap to clone via
//! [`SharedState`] (every field is cheap to clone or behind `Arc`).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use crate::browser::manager::BrowserManager;
use crate::config::Config;
use crate::db::Db;
use crate::scheduler::SchedulerHandle;

/// Application state shared with every handler.
pub struct AppState {
    pub db: Db,
    /// `None` when the Lightpanda binary is absent — handlers must not
    /// assume a browser is up.
    pub manager: Option<Arc<BrowserManager>>,
    /// `None` when no browser is available (scheduler not started).
    pub scheduler: Option<SchedulerHandle>,
    /// Held for the SEG-13 wiring (e.g. cookie operations reseeding keys);
    /// the executor currently carries its own copy from `Config`.
    #[allow(dead_code)]
    pub encryption_key: String,
    /// Dashboard login password, held for constant-time verification.
    pub app_password: String,
    /// `sha256(app_password || ":" || encryption_key)` — session/CSRF key.
    pub session_key: [u8; 32],
    pub database_path: PathBuf,
    pub backup_dir: PathBuf,
    pub version: &'static str,
    /// Process boot, stamped at construction — powers `uptime_s` in
    /// `/api/system`.
    pub boot_instant: Instant,
    /// In-memory marker shared with the executor — set by the restore
    /// handler to signal "a database restore was activated in *this*
    /// process" (the live file was swapped; the still-open connection
    /// points at the old inode). The executor's pre-flight guard refuses
    /// visits while this is set, and the System page shows the
    /// restore-pending banner. Process-local by design; the durable
    /// marker is the `restore_pending` row in the *restored* database's
    /// `application_settings` (written before the swap), which re-arms the
    /// banner + guard after a restart. Shared as an `Arc` with the
    /// executor — a plain `AtomicBool` cannot be seen by both.
    pub restore_pending: Arc<AtomicBool>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(
        db: Db,
        manager: Option<Arc<BrowserManager>>,
        scheduler: Option<SchedulerHandle>,
        config: &Config,
        version: &'static str,
        restore_pending: Arc<AtomicBool>,
    ) -> Self {
        use sha2::Digest as _;
        let session_key: [u8; 32] = sha2::Sha256::digest(
            format!("{}:{}", config.app_password, config.encryption_key).as_bytes(),
        )
        .into();
        Self {
            db,
            manager,
            scheduler,
            encryption_key: config.encryption_key.clone(),
            app_password: config.app_password.clone(),
            session_key,
            database_path: config.database_path.clone(),
            backup_dir: config.backup_dir.clone(),
            version,
            boot_instant: Instant::now(),
            restore_pending,
        }
    }
}
