//! Action model — the only interactions a synthetic journey may perform.
//!
//! An interaction sequence is stored in `interaction_sequences.configuration_json`
//! as JSON and deserialized with [`parse_sequence_json`]. Serialization uses an
//! internally tagged enum (`#[serde(tag = "type")]`, `snake_case` variant names),
//! so a sequence looks like:
//!
//! ```json
//! {
//!   "actions": [
//!     { "type": "navigate", "url": "https://example.com/" },
//!     { "type": "wait_selector", "selector": "main article", "timeout_ms": 8000 },
//!     { "type": "scroll", "direction": "vertical", "distance_px": 600, "operations": 3, "delay_ms": 400 }
//!   ],
//!   "on_error": "abort"
//! }
//! ```
//!
//! Bounded randomness (the "opt-in variation" of SEG-09):
//!
//! - `wait_duration` and `scroll` carry built-in jitter — a wait of `N` ms with
//!   jitter `p` sleeps a uniformly drawn value in `[N*(1-p/100), N*(1+p/100)]`
//!   (jitter defaults to 20 when omitted; the plan's `wait_duration` default).
//! - `rotate` is the only form of action-level variation: it holds explicitly
//!   configured, equivalent choices (e.g. two allowed landing links) and picks
//!   exactly ONE of them uniformly at *run time* (the executor, SEG-10, does the
//!   pick and records which choice ran in the visit log). Rotation never expands
//!   scope beyond what the user explicitly configured and can never produce an
//!   action the validator has not seen. Nested `rotate` is rejected at save time.
//!
//! Structural notes:
//! - `end_session` may appear at most once and only as the final top-level action.
//! - There is no form-submission, no file-upload, no arbitrary-click, no
//!   "dangerously allow" escape hatch anywhere in this model — by design.
//! - This module is the *model* only. Runtime behaviour (executing actions,
//!   picking rotation choices, applying jitter) lives in the executor (SEG-10).
//!
//! [`InteractionSequence`] here is the parsed JSON model; the database row
//! (`interaction_sequences` table) is [`crate::db::models::InteractionSequence`].

use serde::{Deserialize, Serialize};

/// Direction of a `scroll` action. Deserialized from `"vertical"` / `"horizontal"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrollDirection {
    Vertical,
    Horizontal,
}

/// What to do when an action fails at run time.
///
/// `abort` (default) terminates the sequence early (the session ends and the
/// visit is recorded as `interaction_error`); `continue` skips the failed
/// action and proceeds with the rest. Validation still hard-rejects invalid
/// sequences at save time regardless of this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    #[default]
    Abort,
    Continue,
}

/// A single safe action. Tagged by `type` in JSON (see module docs).
///
/// `rotate` holds the *only* form of opt-in bounded randomness allowed by the
/// spec ("action set may rotate among explicitly configured equivalents … only
/// if user opts in"): the executor picks exactly one choice at run time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Navigate to an absolute http(s) URL. When validation is given a
    /// `base_origin`, the URL must be same-origin; cross-origin navigation is
    /// rejected at save time. Fragments are allowed; userinfo is not.
    Navigate { url: String },

    /// Wait `ms` milliseconds, with optional relative jitter in percent
    /// (0–100). `jitter_pct` defaults to 20 when omitted (spec default).
    WaitDuration {
        ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jitter_pct: Option<f64>,
    },

    /// Wait until `selector` matches at least one element, up to
    /// `timeout_ms` (default 10_000). Selector rules are enforced by
    /// [`crate::interactions::validate::validate_sequence`].
    WaitSelector {
        selector: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },

    /// Wait until the JS expression `condition` evaluates truthy, up to
    /// `timeout_ms` (default 10_000). The expression is evaluated via CDP
    /// `Runtime.evaluate`. Dangerous access patterns are denylisted at save
    /// time; there is no sandbox — see `validate.rs` for the exact list and
    /// the threat model.
    WaitJs {
        condition: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },

    /// Scroll the page. `distance_px` per operation is varied ±30% at run
    /// time (built-in jitter); `operations` is bounded by the
    /// `interaction_scroll_max_ops` setting.
    Scroll {
        direction: ScrollDirection,
        distance_px: i64,
        operations: u32,
        delay_ms: u64,
    },

    /// Click the first element matching `selector`. Only selectors explicitly
    /// listed here are ever clicked — there is no arbitrary clicking.
    /// `selector` is checked against a denylist of payment/deletion/account/
    /// submission patterns at save time (see `validate.rs`). Clicks are never
    /// followed by any form submission the selector did not name.
    /// `wait_after_ms` is an extra settle wait after the click, bounded by
    /// `interaction_click_wait_max_ms`.
    Click {
        selector: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wait_after_ms: Option<u64>,
    },

    /// Opt-in bounded variation: pick exactly ONE choice uniformly at run
    /// time (executor records which). Constraints enforced at save time:
    /// 1–8 choices, every choice validated recursively with full weight,
    /// no nested `rotate`, no `end_session` inside `rotate`.
    /// Choices may mix action types (they are alternatives by configuration,
    /// not by type); each choice is still a fully validated action.
    Rotate { choices: Vec<Action> },

    /// End the session early. At most one, and only as the final top-level
    /// action. Structural — never allowed inside `rotate`.
    EndSession,
}

/// A parsed interaction sequence (`configuration_json` of the
/// `interaction_sequences` row).
///
/// An *empty* `actions` list is valid and means "basic mode"
/// (navigate → hold → close); callers may prefer storing no row at all.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InteractionSequence {
    pub actions: Vec<Action>,
    /// On-error behaviour; defaults to `abort` when omitted from JSON.
    #[serde(default)]
    pub on_error: OnError,
    /// Reserved for future use: a caller-chosen seed for deterministic
    /// rotation/jitter sampling. Not interpreted by the validator or (yet)
    /// by the executor; serde-default `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variation_group_seed: Option<u64>,
}

impl Default for InteractionSequence {
    /// Empty sequence = basic mode (navigate → hold → close).
    fn default() -> Self {
        Self {
            actions: Vec::new(),
            on_error: OnError::Abort,
            variation_group_seed: None,
        }
    }
}

/// Parse `configuration_json` into an [`InteractionSequence`].
///
/// Errors carry serde's own context (including the offending `type` tag for
/// unknown action variants).
pub fn parse_sequence_json(s: &str) -> Result<InteractionSequence, serde_json::Error> {
    serde_json::from_str(s)
}

/// Serialize a sequence back to compact JSON for storage.
pub fn to_json(seq: &InteractionSequence) -> Result<String, serde_json::Error> {
    serde_json::to_string(seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sequence() -> InteractionSequence {
        InteractionSequence {
            actions: vec![
                Action::Navigate {
                    url: "https://example.com/".to_string(),
                },
                Action::WaitDuration {
                    ms: 1500,
                    jitter_pct: Some(10.0),
                },
                Action::WaitSelector {
                    selector: "main article".to_string(),
                    timeout_ms: Some(8000),
                },
                Action::WaitJs {
                    condition: "document.readyState === 'complete'".to_string(),
                    timeout_ms: None,
                },
                Action::Scroll {
                    direction: ScrollDirection::Vertical,
                    distance_px: 600,
                    operations: 3,
                    delay_ms: 400,
                },
                Action::Click {
                    selector: "nav a.docs-link".to_string(),
                    wait_after_ms: Some(500),
                },
                Action::Rotate {
                    choices: vec![
                        Action::WaitDuration {
                            ms: 250,
                            jitter_pct: None,
                        },
                        Action::Scroll {
                            direction: ScrollDirection::Horizontal,
                            distance_px: 200,
                            operations: 1,
                            delay_ms: 100,
                        },
                    ],
                },
                Action::EndSession,
            ],
            on_error: OnError::Continue,
            variation_group_seed: Some(42),
        }
    }

    #[test]
    fn round_trip_all_action_types() {
        let seq = sample_sequence();
        let json = to_json(&seq).expect("serialize");
        let back = parse_sequence_json(&json).expect("parse");
        assert_eq!(seq, back);
    }

    #[test]
    fn round_trip_with_defaults_omitted() {
        // Minimal JSON: no on_error, no seed, no jitter, no timeouts.
        let json = r#"{"actions":[{"type":"wait_duration","ms":1000}]}"#;
        let seq = parse_sequence_json(json).expect("parse");
        assert_eq!(seq.on_error, OnError::Abort);
        assert_eq!(seq.variation_group_seed, None);
        assert_eq!(
            seq.actions[0],
            Action::WaitDuration {
                ms: 1000,
                jitter_pct: None
            }
        );
        // Re-serializing omits the absent Option fields again. `on_error`
        // has a default but is always serialized explicitly.
        let json2 = to_json(&seq).expect("serialize");
        assert!(json2.contains("\"on_error\":\"abort\""));
        assert!(!json2.contains("variation_group_seed"));
        assert!(!json2.contains("jitter_pct"));
    }

    #[test]
    fn on_error_parses_continue_and_abort() {
        let json = r#"{"actions":[],"on_error":"continue"}"#;
        let seq = parse_sequence_json(json).expect("parse");
        assert_eq!(seq.on_error, OnError::Continue);

        let json = r#"{"actions":[],"on_error":"abort"}"#;
        let seq = parse_sequence_json(json).expect("parse");
        assert_eq!(seq.on_error, OnError::Abort);

        let json = r#"{"actions":[],"on_error":"explode"}"#;
        assert!(parse_sequence_json(json).is_err());
    }

    #[test]
    fn variation_group_seed_round_trips() {
        let json = r#"{"actions":[],"variation_group_seed":12345}"#;
        let seq = parse_sequence_json(json).expect("parse");
        assert_eq!(seq.variation_group_seed, Some(12345));
        let back = to_json(&seq).expect("serialize");
        assert!(back.contains("\"variation_group_seed\":12345"));
    }

    #[test]
    fn empty_sequence_round_trips() {
        let seq = InteractionSequence::default();
        let json = to_json(&seq).expect("serialize");
        let back = parse_sequence_json(&json).expect("parse");
        assert_eq!(seq, back);
        assert!(json.contains("\"actions\":[]"));
    }

    #[test]
    fn unknown_action_tag_error_carries_context() {
        let json = r#"{"actions":[{"type":"teleport","url":"https://example.com/"}]}"#;
        let err = parse_sequence_json(json).expect_err("unknown tag must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("teleport"),
            "error names the offending tag: {msg}"
        );
    }

    #[test]
    fn missing_type_tag_error_carries_context() {
        let json = r#"{"actions":[{"url":"https://example.com/"}]}"#;
        assert!(parse_sequence_json(json).is_err());
    }

    #[test]
    fn scroll_direction_uses_snake_case() {
        let json = r#"{"type":"scroll","direction":"horizontal","distance_px":100,"operations":1,"delay_ms":100}"#;
        let action: Action = serde_json::from_str(json).expect("parse scroll");
        assert_eq!(
            action,
            Action::Scroll {
                direction: ScrollDirection::Horizontal,
                distance_px: 100,
                operations: 1,
                delay_ms: 100
            }
        );

        let json = r#"{"type":"scroll","direction":"diagonal","distance_px":100,"operations":1,"delay_ms":100}"#;
        assert!(serde_json::from_str::<Action>(json).is_err());
    }

    #[test]
    fn end_session_serializes_without_payload() {
        let json = to_json(&InteractionSequence {
            actions: vec![Action::EndSession],
            ..InteractionSequence::default()
        })
        .expect("serialize");
        assert_eq!(
            json,
            r#"{"actions":[{"type":"end_session"}],"on_error":"abort"}"#
        );
    }
}
