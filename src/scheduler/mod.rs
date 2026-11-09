// The module is the application's public scheduling API, consumed by
// SEG-10 (executor), SEG-11/15/16 (web/system surfaces).
#![allow(dead_code, unused_imports)]

//! Scheduler module — jittered interval selection + a bounded,
//! SQLite-backed in-memory priority queue.
//!
//! * [`jitter`] — pure jitter helpers (ordinary RNG; no CSPRNG needed).
//! * [`queue`] — the [`Scheduler`] worker, the cloneable [`SchedulerHandle`]
//!   used by the web layer and the executor, and the window math.
//!
//! Wiring note: SEG-10 starts the scheduler from `main` with `tz =`
//! `Config.tz` and spawns the dispatch-channel consumer: each emitted
//! [`VisitJob`] goes through `Executor::execute`, and the outcome is fed
//! back via [`SchedulerHandle::handle_completion`] exactly once.

pub mod jitter;
pub mod queue;

pub use crate::db::models::Outcome;
pub use jitter::{Jitter, next_interval};
pub use queue::{
    EnqueueAck, Scheduler, SchedulerError, SchedulerHandle, Trigger, VisitJob, next_window_start,
    retry_delay_seconds, within_window,
};
