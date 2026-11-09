// The module is the application's public scheduling API, consumed by
// SEG-10 (executor), SEG-11/15/16 (web/system surfaces). The binary does
// not call it yet — same pattern as src/db/mod.rs — so silence dead_code
// for the re-exports until the wiring lands.
#![allow(dead_code, unused_imports)]

//! Scheduler module — jittered interval selection + a bounded,
//! SQLite-backed in-memory priority queue.
//!
//! * [`jitter`] — pure jitter helpers (ordinary RNG; no CSPRNG needed).
//! * [`queue`] — the [`Scheduler`] worker, the cloneable [`SchedulerHandle`]
//!   used by the web layer and the executor, and the window math.
//!
//! Wiring note: the worker is *not* started in `main` yet — SEG-10
//! (executor) consumes the dispatch channel and drives
//! [`SchedulerHandle::handle_completion`].

pub mod jitter;
pub mod queue;

pub use crate::db::models::Outcome;
pub use jitter::{Jitter, next_interval};
pub use queue::{
    EnqueueAck, Scheduler, SchedulerError, SchedulerHandle, Trigger, VisitJob, next_window_start,
    retry_delay_seconds, within_window,
};
