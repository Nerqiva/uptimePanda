//! Interaction engine — safe, bounded synthetic journeys (SEG-09).
//!
//! # Safety posture (non-negotiable, mirrors the product spec)
//!
//! uptimePanda monitors **only owned/authorized websites**, and its
//! interactions exist to emulate a *reader*, never to transact:
//!
//! - Only actions the user has explicitly configured ever run. There is no
//!   arbitrary clicking, no link discovery, no form auto-submission, no file
//!   upload, no transaction, no CAPTCHA bypass, no fingerprinting, no proxy
//!   rotation, and no "dangerously allow" escape hatch anywhere in this
//!   module or in the validation layer.
//! - Click selectors are screened against a denylist of payment / deletion /
//!   account / submission patterns at **save time**; violations hard-reject
//!   the sequence with an explanation. They are never warnings.
//! - `wait_js` conditions are denylisted against data-read / data-transmit /
//!   dynamic-eval patterns. This is a control, not a sandbox, and is
//!   documented as such in `validate.rs`.
//! - `navigate` targets are absolute http(s) only; when the website's origin
//!   is known, navigation is pinned to that origin.
//! - Everything is bounded: action count, wall-clock budget, scroll ops,
//!   click wait time, navigate count, rotation branch count (≤ 8, full
//!   static weight). Validation is conservative — a sequence only passes if
//!   every possible execution fits the limits.
//! - Bounded randomness is opt-in only: built-in jitter on waits/scrolls and,
//!   for action selection, the `rotate` action among user-configured
//!   equivalents. Nothing else varies.
//!
//! # Module layout
//!
//! - [`actions`] — the serde-tagged [`Action`] model, [`InteractionSequence`]
//!   (the parsed `configuration_json`), and (de)serialization helpers.
//! - [`validate`] — [`validate_sequence`], [`InteractionLimits`] and
//!   [`InteractionError`]: save-time, fail-collecting hard validation.
//!
//! This module contains **no execution logic**. Picking a `rotate` choice,
//! applying jitter at run time, dispatching CDP calls and recording the
//! chosen branch in the visit log are the executor's job (SEG-10), which
//! must call [`validate_sequence`] first (and may fail-fast on error as
//! defence in depth). Basic monitoring mode (no configured sequence, or an
//! empty one) is navigate → hold → close and remains valid untouched.
//!
//! The database row is [`crate::db::models::InteractionSequence`];
//! [`InteractionSequence`] re-exported here is the parsed model.

// The interaction model/validation API (Action, validate_sequence, …) is
// consumed only by unit tests until the executor lands (SEG-10) and the
// Interaction editor page lands (SEG-11); silence dead_code for it until
// then — same pattern as src/db/mod.rs and src/config.rs.
#![allow(dead_code)]

pub mod actions;
pub mod validate;

#[allow(unused_imports)] // re-exported for SEG-10/11 consumers; unused for now
pub use actions::{
    Action, InteractionSequence, OnError, ScrollDirection, parse_sequence_json, to_json,
};
#[allow(unused_imports)] // re-exported for SEG-10/11 consumers; unused for now
pub use validate::{
    CLICK_SELECTOR_DENYLIST, CLICK_TYPE_SUBMIT_PATTERNS, InteractionError, InteractionLimits,
    MAX_NAVIGATES, MAX_ROTATE_CHOICES, MAX_SELECTOR_LEN, MAX_WAIT_JS_LEN, WAIT_JS_DENYLIST,
    validate_sequence,
};
