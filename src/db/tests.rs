//! In-crate tests for the database module.
//!
//! Most tests run against in-memory databases; the file-backed tests
//! (WAL pragma, re-open idempotency, backup→restore) use a unique temp
//! directory per test and clean up via `tempfile`.

use super::models::*;
use super::{Db, backup, schema};
use rusqlite::params;
use time::{Duration, OffsetDateTime};

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn fmt_ts(t: OffsetDateTime) -> String {
    format_db_ts(t).expect("format timestamp")
}

fn sample_website(name: &str) -> Website {
    let ts = now();
    Website {
        id: 0,
        name: name.to_string(),
        url: format!("https://{name}.example.com/"),
        enabled: true,
        profile_id: None,
        monitoring_mode: MonitoringMode::Basic,
        min_interval_seconds: 10,
        max_interval_seconds: 20,
        min_session_seconds: 5,
        max_session_seconds: 10,
        last_visit_at: None,
        next_visit_at: None,
        created_at: ts,
        updated_at: ts,
    }
}

fn sample_visit(website_id: i64, started_at: OffsetDateTime) -> VisitHistoryRow {
    VisitHistoryRow {
        id: 0,
        website_id,
        profile_id: None,
        started_at,
        completed_at: Some(started_at + Duration::seconds(3)),
        duration_ms: Some(3_000),
        http_status: Some(200),
        final_url: Some("https://example.com/".to_string()),
        outcome: Outcome::Success,
        error_message: None,
        browser_pid: Some(1234),
        memory_usage: Some(42 * 1024 * 1024),
    }
}

fn scheduler_state(website_id: i64) -> SchedulerState {
    SchedulerState {
        website_id,
        next_visit_at: None,
        last_execution_at: None,
        retry_count: 0,
        job_status: JobStatus::Pending,
        lease_expires_at: None,
    }
}

/// Count rows matching a fixture-owned `where_clause` (integer literals
/// only — never user input).
async fn raw_count(db: &Db, table: &str, where_clause: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE {where_clause}");
    db.connection()
        .call(move |c| c.query_row(&sql, [], |r| r.get(0)))
        .await
        .expect("count query")
}

#[tokio::test]
async fn fresh_in_memory_db_has_version_and_strict_tables() {
    let db = Db::in_memory().await.expect("open in-memory db");

    let version: i64 = db
        .connection()
        .call(|c| schema::user_version(c))
        .await
        .expect("user_version");
    assert_eq!(version, schema::SCHEMA_VERSION);

    let has_strict = db
        .connection()
        .call(|c| {
            let sql: String = c.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'websites'",
                [],
                |r| r.get(0),
            )?;
            Ok::<_, rusqlite::Error>(sql.contains("STRICT"))
        })
        .await
        .expect("table sql");
    assert!(has_strict, "websites table must be STRICT");
}

#[tokio::test]
async fn migrate_is_idempotent() {
    let db = Db::in_memory().await.expect("open in-memory db");
    // Running the migration again must succeed and keep the version.
    db.connection()
        .call(schema::migrate)
        .await
        .expect("re-migrate");
    let version: i64 = db
        .connection()
        .call(|c| schema::user_version(c))
        .await
        .expect("user_version");
    assert_eq!(version, schema::SCHEMA_VERSION);
}

#[tokio::test]
async fn file_backed_reopen_is_clean_and_wal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reopen.db");

    let website_id;
    {
        let db = Db::open(&path).await.expect("first open");
        let mode: String = db
            .connection()
            .call(|c| c.query_row("PRAGMA journal_mode", [], |r| r.get(0)))
            .await
            .expect("journal_mode");
        assert_eq!(mode, "wal");

        website_id = db
            .insert_website(&sample_website("reopen"))
            .await
            .expect("insert");
        assert!(website_id > 0);
        db.integrity_check().await.expect("integrity check");
    }

    {
        let db = Db::open(&path).await.expect("re-open");
        let version: i64 = db
            .connection()
            .call(|c| schema::user_version(c))
            .await
            .expect("user_version");
        assert_eq!(version, schema::SCHEMA_VERSION);
        let website = db
            .get_website(website_id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(website.name, "reopen");
    }
}

#[tokio::test]
async fn fk_cascade_from_website_delete() {
    let db = Db::in_memory().await.expect("open in-memory db");
    let website_id = db
        .insert_website(&sample_website("cascade"))
        .await
        .expect("insert website");

    let visit_id = db
        .record_visit(&sample_visit(website_id, now()))
        .await
        .expect("record visit");
    assert!(visit_id > 0);

    db.upsert_scheduler_state(&scheduler_state(website_id))
        .await
        .expect("upsert scheduler state");

    // interaction_sequences has no write helper yet — seed it raw.
    db.connection()
        .call(move |c| {
            c.execute(
                "INSERT INTO interaction_sequences (website_id) VALUES (?1)",
                params![website_id],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .expect("seed interaction sequence");

    assert_eq!(
        raw_count(&db, "visit_history", &format!("website_id = {website_id}")).await,
        1
    );
    assert!(db.delete_website(website_id).await.expect("delete"));

    assert_eq!(
        raw_count(&db, "visit_history", &format!("website_id = {website_id}")).await,
        0
    );
    assert_eq!(
        raw_count(
            &db,
            "interaction_sequences",
            &format!("website_id = {website_id}")
        )
        .await,
        0
    );
    assert_eq!(
        raw_count(
            &db,
            "scheduler_state",
            &format!("website_id = {website_id}")
        )
        .await,
        0
    );
}

#[tokio::test]
async fn profile_delete_cascades_cookies_and_nulls_website_profile() {
    let db = Db::in_memory().await.expect("open in-memory db");

    db.connection()
        .call(|c| {
            c.execute(
                "INSERT INTO browser_profiles (name) VALUES ('p-cascade')",
                [],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .expect("insert profile");

    let mut website = sample_website("linked");
    website.profile_id = Some(1);
    let website_id = db.insert_website(&website).await.expect("insert website");

    db.connection()
        .call(|c| {
            c.execute(
                "INSERT INTO cookies (profile_id, domain, encrypted_cookie_data)
                 VALUES (1, 'example.com', 'enc:v1:deadbeef')",
                [],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .expect("insert cookie");

    assert_eq!(raw_count(&db, "cookies", "profile_id = 1").await, 1);

    db.connection()
        .call(|c| {
            c.execute("DELETE FROM browser_profiles WHERE id = 1", [])?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .expect("delete profile");

    assert_eq!(raw_count(&db, "cookies", "profile_id = 1").await, 0);

    let website = db
        .get_website(website_id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        website.profile_id, None,
        "profile_id must be SET NULL on profile delete"
    );
}

#[tokio::test]
async fn website_fk_rejects_bogus_profile() {
    let db = Db::in_memory().await.expect("open in-memory db");
    let mut website = sample_website("bogus");
    website.profile_id = Some(999);
    let err = db
        .insert_website(&website)
        .await
        .expect_err("FK must reject");
    assert!(matches!(err, crate::db::DbError::Sqlite(_)));
}

#[tokio::test]
async fn claim_due_job_claims_only_due_jobs_first_come_first_served() {
    let db = Db::in_memory().await.expect("open in-memory db");

    let due_a = db
        .insert_website(&sample_website("due-a"))
        .await
        .expect("a");
    let due_b = db
        .insert_website(&sample_website("due-b"))
        .await
        .expect("b");
    let future = db
        .insert_website(&sample_website("future"))
        .await
        .expect("c");

    let now_ts = now();
    for (id, offset) in [(due_a, -10), (due_b, -30), (future, 3600)] {
        let mut state = scheduler_state(id);
        state.next_visit_at = Some(now_ts + Duration::seconds(offset));
        db.upsert_scheduler_state(&state).await.expect("upsert");
    }

    // Earliest due job (due_b, 30s in the past) is claimed first.
    let claimed = db
        .claim_due_job(now_ts, 120)
        .await
        .expect("claim")
        .expect("something due");
    assert_eq!(claimed.website_id, due_b);
    assert_eq!(claimed.job_status, JobStatus::Running);
    let lease = claimed.lease_expires_at.expect("lease set");
    assert!(lease >= now_ts + Duration::seconds(119) && lease <= now_ts + Duration::seconds(121));

    // Second claim takes due_a; future stays untouched.
    let claimed = db
        .claim_due_job(now_ts, 120)
        .await
        .expect("claim")
        .expect("due_a due");
    assert_eq!(claimed.website_id, due_a);

    // Nothing left due.
    assert!(
        db.claim_due_job(now_ts, 120)
            .await
            .expect("claim")
            .is_none()
    );

    // The future job is still pending.
    let pending = db
        .connection()
        .call(move |c| {
            c.query_row(
                "SELECT job_status FROM scheduler_state WHERE website_id = ?1",
                params![future],
                |r| r.get::<_, String>(0),
            )
        })
        .await
        .expect("status");
    assert_eq!(pending, "pending");
}

#[tokio::test]
async fn claim_due_job_picks_up_retry_jobs() {
    let db = Db::in_memory().await.expect("open in-memory db");
    let id = db
        .insert_website(&sample_website("retry"))
        .await
        .expect("insert");

    let mut state = scheduler_state(id);
    state.job_status = JobStatus::Retry;
    state.next_visit_at = Some(now() - Duration::seconds(5));
    state.retry_count = 1;
    db.upsert_scheduler_state(&state).await.expect("upsert");

    let claimed = db.claim_due_job(now(), 60).await.expect("claim");
    assert_eq!(claimed.map(|s| s.website_id), Some(id));
}

#[tokio::test]
async fn recover_stale_running_requeues_expired_and_unleased_jobs() {
    let db = Db::in_memory().await.expect("open in-memory db");
    let stale = db
        .insert_website(&sample_website("stale"))
        .await
        .expect("insert");
    let fresh = db
        .insert_website(&sample_website("fresh"))
        .await
        .expect("insert");
    let unleased = db
        .insert_website(&sample_website("unleased"))
        .await
        .expect("insert");

    for (id, lease) in [
        (stale, Some(now() - Duration::seconds(3600))),
        (fresh, Some(now() + Duration::seconds(3600))),
        (unleased, None),
    ] {
        let mut state = scheduler_state(id);
        state.job_status = JobStatus::Running;
        state.last_execution_at = Some(now());
        state.lease_expires_at = lease;
        db.upsert_scheduler_state(&state).await.expect("upsert");
    }

    let recovered = db.recover_stale_running(60).await.expect("recover");
    assert_eq!(recovered, 2, "stale + unleased must be recovered");

    for (id, expected) in [
        (stale, "pending"),
        (unleased, "pending"),
        (fresh, "running"),
    ] {
        let status: String = db
            .connection()
            .call(move |c| {
                c.query_row(
                    "SELECT job_status FROM scheduler_state WHERE website_id = ?1",
                    params![id],
                    |r| r.get(0),
                )
            })
            .await
            .expect("status");
        assert_eq!(status, expected);
    }
}

#[tokio::test]
async fn cleanup_expired_history_respects_retention_boundary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cleanup.db"); // file-backed to exercise checkpoint
    let db = Db::open(&path).await.expect("open");

    let website_id = db
        .insert_website(&sample_website("retention"))
        .await
        .expect("insert");
    let now_ts = now();
    for offset_days in [-8, -6, 0] {
        db.record_visit(&sample_visit(
            website_id,
            now_ts + Duration::days(offset_days),
        ))
        .await
        .expect("record visit");
    }

    // Browser events: insert 505, expect trim to 500.
    let event_ts = fmt_ts(now_ts);
    db.connection()
        .call(move |c| {
            for i in 0..505 {
                c.execute(
                    "INSERT INTO browser_events (event_type, timestamp, details)
                     VALUES ('health_warn', ?1, ?2)",
                    params![event_ts.as_str(), format!("event-{i}")],
                )?;
            }
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .expect("insert browser events");

    let stats = db.cleanup_expired_history(7).await.expect("cleanup");
    assert_eq!(
        stats.visit_history_deleted, 1,
        "only the >7d old visit is deleted"
    );
    assert_eq!(stats.browser_events_deleted, 5, "505 -> 500 newest kept");

    let remaining = db
        .recent_visits(10, Some(website_id))
        .await
        .expect("visits");
    assert_eq!(remaining.len(), 2);

    let events_left = raw_count(&db, "browser_events", "id > 0").await;
    assert_eq!(events_left, 500);

    // Oldest five events (ids 1..=5) are gone; newest survive.
    let min_id: i64 = db
        .connection()
        .call(|c| c.query_row("SELECT MIN(id) FROM browser_events", [], |r| r.get(0)))
        .await
        .expect("min id");
    assert_eq!(min_id, 6);
}

#[tokio::test]
async fn backup_validate_restore_roundtrip_and_overwrite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src_path = dir.path().join("source.db");
    let dest_path = dir.path().join("backup.db");

    {
        let db = Db::open(&src_path).await.expect("open source");
        let w1 = db
            .insert_website(&sample_website("backup-1"))
            .await
            .expect("insert 1");
        let _w2 = db
            .insert_website(&sample_website("backup-2"))
            .await
            .expect("insert 2");
        for _ in 0..3 {
            db.record_visit(&sample_visit(w1, now()))
                .await
                .expect("visit");
        }

        // Pre-create a garbage destination; backup_to must overwrite it.
        std::fs::write(&dest_path, b"definitely not sqlite").expect("write garbage");
        db.backup_to(&dest_path).await.expect("backup");
    }

    backup::validate_backup(&dest_path).expect("backup must validate");

    let restored = Db::open(&dest_path).await.expect("open restored");
    let websites = restored.list_enabled_websites().await.expect("list");
    assert_eq!(websites.len(), 2);
    let visits = restored.recent_visits(10, None).await.expect("visits");
    assert_eq!(visits.len(), 3);
    restored
        .integrity_check()
        .await
        .expect("restored integrity");
}

#[tokio::test]
async fn validate_backup_rejects_non_sqlite_files() {
    let dir = tempfile::tempdir().expect("tempdir");

    let garbage = dir.path().join("garbage.bin");
    std::fs::write(&garbage, b"definitely not sqlite").expect("write");
    let err = backup::validate_backup(&garbage).expect_err("must reject");
    assert!(matches!(err, crate::db::DbError::InvalidBackup(_)));

    let empty = dir.path().join("empty.bin");
    std::fs::write(&empty, b"").expect("write");
    assert!(backup::validate_backup(&empty).is_err());

    let truncated = dir.path().join("truncated.db");
    std::fs::write(&truncated, b"SQLite for").expect("write");
    assert!(backup::validate_backup(&truncated).is_err());
}

#[tokio::test]
async fn website_round_trip_through_database_preserves_fields() {
    let db = Db::in_memory().await.expect("open in-memory db");
    let mut website = sample_website("roundtrip");
    website.monitoring_mode = MonitoringMode::Interaction;
    website.min_interval_seconds = 60;
    website.max_interval_seconds = 90;
    website.min_session_seconds = 10;
    website.max_session_seconds = 20;
    website.next_visit_at = Some(now() + Duration::seconds(300));

    let id = db.insert_website(&website).await.expect("insert");
    let fetched = db.get_website(id).await.expect("get").expect("present");

    assert_eq!(fetched.name, "roundtrip");
    assert_eq!(fetched.monitoring_mode, MonitoringMode::Interaction);
    assert_eq!(fetched.min_interval_seconds, 60);
    assert_eq!(fetched.max_interval_seconds, 90);
    assert_eq!(fetched.min_session_seconds, 10);
    assert_eq!(fetched.max_session_seconds, 20);
    assert!(fetched.enabled);
    assert!(fetched.created_at > now() - Duration::minutes(1));
    assert_eq!(
        fetched.next_visit_at.map(|t| t.unix_timestamp()),
        website.next_visit_at.map(|t| t.unix_timestamp())
    );
}

#[tokio::test]
async fn update_website_refreshes_updated_at_and_reports_rows() {
    let db = Db::in_memory().await.expect("open in-memory db");
    let mut website = sample_website("update");
    let old = now() - Duration::days(10);
    website.created_at = old;
    website.updated_at = old;

    let id = db.insert_website(&website).await.expect("insert");
    website.id = id;
    website.name = "update-renamed".to_string();
    assert!(db.update_website(&website).await.expect("update"));

    let fetched = db.get_website(id).await.expect("get").expect("present");
    assert_eq!(fetched.name, "update-renamed");
    assert!(fetched.updated_at > old);

    website.id = 999_999;
    assert!(!db.update_website(&website).await.expect("update missing"));
    assert!(!db.delete_website(999_999).await.expect("delete missing"));
}

#[tokio::test]
async fn list_enabled_websites_excludes_disabled() {
    let db = Db::in_memory().await.expect("open in-memory db");
    let enabled_id = db
        .insert_website(&sample_website("enabled"))
        .await
        .expect("insert");
    let disabled_id = db
        .insert_website(&sample_website("disabled"))
        .await
        .expect("insert");

    let mut disabled = db
        .get_website(disabled_id)
        .await
        .expect("get")
        .expect("present");
    disabled.enabled = false;
    assert!(db.update_website(&disabled).await.expect("disable"));

    let websites = db.list_enabled_websites().await.expect("list");
    let names: Vec<&str> = websites.iter().map(|w| w.name.as_str()).collect();
    assert!(names.contains(&"enabled"));
    assert!(!names.contains(&"disabled"));
    let _ = enabled_id;
}

#[tokio::test]
async fn model_serde_round_trips_with_rfc3339_timestamps() {
    let website = sample_website("serde");
    let json = serde_json::to_string(&website).expect("serialize");
    let back: Website = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(website, back);

    let outcome_json = serde_json::to_string(&Outcome::InteractionError).expect("serialize");
    assert_eq!(outcome_json, "\"interaction_error\"");

    let state = scheduler_state(7);
    let state_json = serde_json::to_string(&state).expect("serialize");
    let state_back: SchedulerState = serde_json::from_str(&state_json).expect("deserialize");
    assert_eq!(state, state_back);
}

#[tokio::test]
async fn cleanup_expired_history_with_zero_retention_deletes_everything() {
    let db = Db::in_memory().await.expect("open in-memory db");
    let website_id = db
        .insert_website(&sample_website("zero"))
        .await
        .expect("insert");
    db.record_visit(&sample_visit(website_id, now() - Duration::seconds(1)))
        .await
        .expect("visit");
    let stats = db.cleanup_expired_history(0).await.expect("cleanup");
    assert!(stats.visit_history_deleted >= 1);
}
