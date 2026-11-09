//! Save-time validation for interaction sequences — hard reject, never warn.
//!
//! Two enforcement points exist in this codebase:
//!
//! 1. **Save path** (settings UI / API, SEG-11/14): call [`validate_sequence`],
//!    return *all* collected errors to the user, block the save. This is the
//!    security control; every violation is reported in one pass.
//! 2. **Execution path** (executor, SEG-10): the executor may fail-fast on the
//!    first stored violation as defence in depth, but a sequence that passed
//!    save-time validation must pass validation unchanged.
//!
//! Validation is purely static and conservative:
//!
//! - `rotate` inner actions are counted with **full weight** (as if every
//!   branch executed), even though only one branch runs at a time. Action
//!   count, the per-sequence navigate cap and the conservative time budget
//!   all use this rule.
//! - The conservative time budget sums, over *every* concrete action:
//!   - `wait_duration` → `ceil(ms * (1 + jitter_pct/100))` (jitter defaults to 20 %),
//!   - `wait_selector` / `wait_js` → their `timeout_ms` or 10 000 ms,
//!   - `scroll` → `operations * delay_ms`,
//!   - `navigate` / `click` → a 10 000 ms per-action ceiling (a `click` adds its `wait_after_ms` on top),
//!   - `rotate` → the sum of its inner actions' budgets (no phantom base),
//!   - `end_session` → 0 (it is instantaneous).
//!
//!   The total must fit `InteractionLimits::max_total_session_ms`
//!   (`max_session_seconds_cap * 1000`). Websites with smaller session caps
//!   should construct tighter limits — that is the caller's choice.
//!
//! Selector safety model
//! ---------------------
//! Selectors are length-bounded (≤ 200 chars), single-line, and may not
//! contain `{`, `}`, a backtick, or `javascript:` / `data:` (any case).
//! **Click** selectors face an additional denylist of case-insensitive
//! substrings associated with payment, deletion, account and submission
//! flows (see [`CLICK_SELECTOR_DENYLIST`]) — plus regex-free rejection of
//! `[type=submit]`-style patterns. These are hard rejections with an
//! explanation; there is no `dangerously_allow` escape hatch. Clicks are
//! only ever performed on explicitly configured selectors; nothing is ever
//! discovered or inferred at run time.
//!
//! `wait_js` conditions are capped at 500 chars and checked against an
//! exfiltration-flavoured denylist ([`WAIT_JS_DENYLIST`]: `fetch(`,
//! `XMLHttpRequest`, …). This is an honest control, not a sandbox: arbitrary
//! JS *cannot* be safely filtered, so patterns that read or send data off
//! the page are rejected. The page itself may still do anything — that is
//! the site's own behaviour, not something this validator grants.
//!
//! Duplicate-navigate cap: at most 4 `navigate` actions per sequence
//! (counted recursively, full weight) — a bounded journey cannot wander.
//!
//! `end_session` is structural: at most one per sequence, and only as the
//! final top-level action. `rotate` may not contain `end_session` or a
//! nested `rotate`.
//!
//! An empty action list is valid: the executor treats it as basic mode
//! (navigate → hold → close).

use std::fmt;

use serde::{Deserialize, Serialize};
use url::Url;

use super::actions::{Action, InteractionSequence};

/// Default per-action timeout ceiling used for the conservative time budget.
pub const DEFAULT_ACTION_TIMEOUT_MS: u64 = 10_000;

/// Maximum number of `navigate` actions allowed per sequence (recursive count).
pub const MAX_NAVIGATES: usize = 4;

/// Maximum length of any selector (in Unicode scalar values).
pub const MAX_SELECTOR_LEN: usize = 200;

/// Maximum length of a `wait_js` condition.
pub const MAX_WAIT_JS_LEN: usize = 500;

/// Maximum number of choices in a `rotate` action.
pub const MAX_ROTATE_CHOICES: usize = 8;

/// Case-insensitive substrings forbidden in **click** selectors.
///
/// Every entry denotes an action category that synthesizing a click could
/// trigger — payments, purchases, orders, deletions, confirmations, account
/// and credential flows, subscriptions. The spec does not permit overriding
/// this list; hits are hard validation errors, never warnings.
pub const CLICK_SELECTOR_DENYLIST: &[&str] = &[
    "pay",
    "purchase",
    "checkout",
    "buy",
    "order",
    "delete",
    "remove",
    "confirm",
    "submit",
    "unsubscribe",
    "account",
    "login",
    "password",
    "card",
    "wire",
    "transfer",
    "donate",
];

/// Regex-free `[type=submit]`-style patterns forbidden in **click** selectors
/// (matched case-insensitively). Complements the `"submit"` substring above for
/// attribute-selector spellings without the keyword.
pub const CLICK_TYPE_SUBMIT_PATTERNS: &[&str] =
    &["[type=submit]", "[type='submit']", "[type=\"submit\"]"];

/// Case-insensitive substrings forbidden in `wait_js` conditions.
///
/// These read or transmit page data / invoke dynamic code evaluation.
/// Filtering JS is not a sandbox — this list blocks the well-known
/// exfiltration and evaluation patterns relevant to this use case and is the
/// documented control for `wait_js`. The page's own behaviour is out of scope.
pub const WAIT_JS_DENYLIST: &[&str] = &[
    "fetch(",
    "XMLHttpRequest",
    "sendBeacon",
    "WebSocket",
    "document.cookie",
    "eval(",
    "Function(",
];

/// Bounds applied by [`validate_sequence`], built from settings:
///
/// | field | setting (SEG-04) |
/// |---|---|
/// | `max_actions` | `max_actions_per_sequence` |
/// | `max_click_wait_ms` | `interaction_click_wait_max_ms` |
/// | `max_scroll_ops` | `interaction_scroll_max_ops` |
/// | `max_total_session_ms` | `max_session_seconds_cap * 1000` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteractionLimits {
    /// Hard cap on the number of concrete actions in a sequence, counting
    /// `rotate` as 1 and its inner actions (all branches) with full weight.
    pub max_actions: usize,
    /// Maximum `wait_after_ms` on a click action.
    pub max_click_wait_ms: u64,
    /// Maximum `operations` on a scroll action.
    pub max_scroll_ops: u32,
    /// Conservative upper bound on total wall-clock time, in milliseconds.
    pub max_total_session_ms: u64,
}

impl InteractionLimits {
    pub fn new(
        max_actions: usize,
        max_click_wait_ms: u64,
        max_scroll_ops: u32,
        max_total_session_ms: u64,
    ) -> Self {
        Self {
            max_actions,
            max_click_wait_ms,
            max_scroll_ops,
            max_total_session_ms,
        }
    }
}

/// One validation violation. `action_index` is the 0-based index of the
/// offending *top-level* action (nested violations inside a `rotate` report
/// the `rotate`'s index with the branch spelled out in `message`); `None`
/// for sequence-level violations (action count, time budget, navigate cap).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionError {
    pub action_index: Option<usize>,
    pub message: String,
}

impl InteractionError {
    fn at(index: usize, message: impl Into<String>) -> Self {
        Self {
            action_index: Some(index),
            message: message.into(),
        }
    }

    fn sequence(message: impl Into<String>) -> Self {
        Self {
            action_index: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for InteractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.action_index {
            Some(i) => write!(f, "action {i}: {}", self.message),
            None => write!(f, "sequence: {}", self.message),
        }
    }
}

impl std::error::Error for InteractionError {}

/// Validate `seq` against `limits`. Returns `Ok(())` when valid, otherwise
/// **every** violation found (never fail-fast), suitable for reporting all
/// problems to the user in one pass.
///
/// `base_origin`, when provided, pins `navigate` actions to the same origin
/// (scheme + host + port). When `None`, any absolute http(s) URL is accepted
/// (e.g. validation at import time before the website row exists).
pub fn validate_sequence(
    seq: &InteractionSequence,
    limits: &InteractionLimits,
    base_origin: Option<&Url>,
) -> Result<(), Vec<InteractionError>> {
    let mut errors = Vec::new();

    // Per-action validation (recursive).
    for (index, action) in seq.actions.iter().enumerate() {
        validate_action(action, limits, base_origin, index, "", &mut errors);
    }

    // Structural rules for end_session (top-level only).
    let end_positions: Vec<usize> = seq
        .actions
        .iter()
        .enumerate()
        .filter_map(|(i, a)| matches!(a, Action::EndSession).then_some(i))
        .collect();
    if end_positions.len() > 1 {
        for &i in &end_positions[1..] {
            errors.push(InteractionError::at(
                i,
                "at most one end_session action is allowed per sequence",
            ));
        }
    }
    for &i in &end_positions {
        if i != seq.actions.len() - 1 {
            errors.push(InteractionError::at(
                i,
                "end_session is structural and may only appear as the final action",
            ));
        }
    }

    // Sequence-level rules: total action count (recursive, full weight).
    let total_actions: usize = seq.actions.iter().map(count_action).sum();
    if total_actions > limits.max_actions {
        errors.push(InteractionError::sequence(format!(
            "too many actions ({total_actions} counted with full weight, including rotate branches); \
             limits.max_actions is {}",
            limits.max_actions
        )));
    }

    // Sequence-level rule: conservative time budget.
    let total_ms: u64 = seq
        .actions
        .iter()
        .fold(0u64, |acc, a| acc.saturating_add(conservative_cost_ms(a)));
    if total_ms > limits.max_total_session_ms {
        errors.push(InteractionError::sequence(format!(
            "conservative session cost {total_ms}ms exceeds max_total_session_ms {}ms",
            limits.max_total_session_ms
        )));
    }

    // Sequence-level rule: navigate cap (recursive, full weight).
    let navigates: usize = seq.actions.iter().map(count_navigates).sum();
    if navigates > MAX_NAVIGATES {
        errors.push(InteractionError::sequence(format!(
            "too many navigate actions ({navigates} counted with full weight, including rotate branches); \
             at most {MAX_NAVIGATES} allowed per sequence"
        )));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Number of concrete actions in a tree: `rotate` counts 1 for itself plus
/// the full weight of every inner branch (conservative static count).
fn count_action(action: &Action) -> usize {
    match action {
        Action::Rotate { choices } => 1 + choices.iter().map(count_action).sum::<usize>(),
        _ => 1,
    }
}

/// Navigate cap — recursive, full weight (conservative).
fn count_navigates(action: &Action) -> usize {
    match action {
        Action::Navigate { .. } => 1,
        Action::Rotate { choices } => choices.iter().map(count_navigates).sum(),
        _ => 0,
    }
}

/// Conservative wall-clock budget for an action tree, in milliseconds.
/// Uses saturating arithmetic; see module docs for the per-action rules.
fn conservative_cost_ms(action: &Action) -> u64 {
    match action {
        Action::Navigate { .. } => DEFAULT_ACTION_TIMEOUT_MS,
        Action::WaitDuration { ms, jitter_pct } => {
            let jitter = jitter_pct.unwrap_or(20.0).max(0.0);
            let scaled = (*ms as f64) * (1.0 + jitter / 100.0);
            if scaled.is_finite() && scaled > 0.0 {
                scaled.ceil() as u64
            } else {
                0
            }
        }
        Action::WaitSelector { timeout_ms, .. } => timeout_ms.unwrap_or(DEFAULT_ACTION_TIMEOUT_MS),
        Action::WaitJs { timeout_ms, .. } => timeout_ms.unwrap_or(DEFAULT_ACTION_TIMEOUT_MS),
        Action::Scroll {
            operations,
            delay_ms,
            ..
        } => (*operations as u64).saturating_mul(*delay_ms),
        Action::Click { wait_after_ms, .. } => {
            DEFAULT_ACTION_TIMEOUT_MS.saturating_add(wait_after_ms.unwrap_or(0))
        }
        Action::Rotate { choices } => choices
            .iter()
            .fold(0u64, |acc, c| acc.saturating_add(conservative_cost_ms(c))),
        Action::EndSession => 0,
    }
}

/// Recursive per-action validation. `context` is empty at the top level and
/// e.g. `", rotate choice 2"` for nested calls; `top_index` is the index of
/// the top-level action to report in [`InteractionError::action_index`].
fn validate_action(
    action: &Action,
    limits: &InteractionLimits,
    base_origin: Option<&Url>,
    top_index: usize,
    context: &str,
    errors: &mut Vec<InteractionError>,
) {
    let where_ = |msg: String| format!("{msg}{context}");
    match action {
        Action::Navigate { url } => validate_navigate(url, base_origin, top_index, &where_, errors),
        Action::WaitDuration { ms: _, jitter_pct } => {
            if let Some(j) = jitter_pct
                && (!j.is_finite() || *j < 0.0 || *j > 100.0)
            {
                errors.push(InteractionError::at(
                    top_index,
                    where_(format!(
                        "jitter_pct must be a finite number in [0.0, 100.0], got {j}"
                    )),
                ));
            }
        }
        Action::WaitSelector {
            selector,
            timeout_ms: _,
        } => validate_selector(selector, false, top_index, &where_, errors),
        Action::WaitJs {
            condition,
            timeout_ms: _,
        } => validate_wait_js(condition, top_index, &where_, errors),
        Action::Scroll {
            direction: _,
            distance_px,
            operations,
            delay_ms,
        } => {
            if !(1..=5000).contains(distance_px) {
                errors.push(InteractionError::at(
                    top_index,
                    where_(format!(
                        "scroll distance_px must be within [1, 5000], got {distance_px}"
                    )),
                ));
            }
            if *operations == 0 || *operations > limits.max_scroll_ops {
                errors.push(InteractionError::at(
                    top_index,
                    where_(format!(
                        "scroll operations must be within [1, {}] (interaction_scroll_max_ops), got {operations}",
                        limits.max_scroll_ops
                    )),
                ));
            }
            if !(50..=5000).contains(delay_ms) {
                errors.push(InteractionError::at(
                    top_index,
                    where_(format!(
                        "scroll delay_ms must be within [50, 5000], got {delay_ms}"
                    )),
                ));
            }
        }
        Action::Click {
            selector,
            wait_after_ms,
        } => {
            validate_selector(selector, true, top_index, &where_, errors);
            if let Some(wait) = wait_after_ms
                && *wait > limits.max_click_wait_ms
            {
                errors.push(InteractionError::at(
                    top_index,
                    where_(format!(
                        "click wait_after_ms {wait} exceeds interaction_click_wait_max_ms ({})",
                        limits.max_click_wait_ms
                    )),
                ));
            }
        }
        Action::Rotate { choices } => {
            if choices.is_empty() {
                errors.push(InteractionError::at(
                    top_index,
                    where_("rotate must have at least 1 choice".to_string()),
                ));
            }
            if choices.len() > MAX_ROTATE_CHOICES {
                errors.push(InteractionError::at(
                    top_index,
                    where_(format!(
                        "rotate has {} choices; at most {MAX_ROTATE_CHOICES} are allowed",
                        choices.len()
                    )),
                ));
            }
            for (choice_index, choice) in choices.iter().enumerate() {
                let nested = format!("{context}, rotate choice {}", choice_index + 1);
                match choice {
                    Action::Rotate { .. } => errors.push(InteractionError::at(
                        top_index,
                        format!("rotate may not contain a nested rotate{nested}"),
                    )),
                    Action::EndSession => errors.push(InteractionError::at(
                        top_index,
                        format!(
                            "rotate may not contain end_session{nested}; end_session is structural and only valid as the final top-level action"
                        ),
                    )),
                    _ => validate_action(choice, limits, base_origin, top_index, &nested, errors),
                }
            }
        }
        Action::EndSession => {}
    }
}

/// Shared selector rules. When `is_click` is set, the click-only denylist
/// ([`CLICK_SELECTOR_DENYLIST`], [`CLICK_TYPE_SUBMIT_PATTERNS`]) applies too.
/// Wait-only selectors are *not* denylist-checked — the denylist exists to
/// prevent synthesising clicks on dangerous controls.
fn validate_selector(
    selector: &str,
    is_click: bool,
    top_index: usize,
    where_: &dyn Fn(String) -> String,
    errors: &mut Vec<InteractionError>,
) {
    let label = if is_click {
        "click selector"
    } else {
        "selector"
    };
    if selector.is_empty() {
        errors.push(InteractionError::at(
            top_index,
            where_(format!("{label} must not be empty")),
        ));
        return;
    }
    if selector.chars().count() > MAX_SELECTOR_LEN {
        errors.push(InteractionError::at(
            top_index,
            where_(format!(
                "{label} is too long ({} chars; max {MAX_SELECTOR_LEN})",
                selector.chars().count()
            )),
        ));
    }
    if selector.contains(['\n', '\r']) {
        errors.push(InteractionError::at(
            top_index,
            where_(format!("{label} must be a single line")),
        ));
    }
    for forbidden in ['{', '}', '`'] {
        if selector.contains(forbidden) {
            errors.push(InteractionError::at(
                top_index,
                where_(format!("{label} must not contain '{forbidden}'")),
            ));
        }
    }
    let lower = selector.to_ascii_lowercase();
    for forbidden in ["javascript:", "data:"] {
        if lower.contains(forbidden) {
            errors.push(InteractionError::at(
                top_index,
                where_(format!(
                    "{label} must not contain '{forbidden}' (case-insensitive)"
                )),
            ));
        }
    }
    if is_click {
        for needle in CLICK_SELECTOR_DENYLIST {
            if lower.contains(needle) {
                errors.push(InteractionError::at(
                    top_index,
                    where_(format!(
                        "click selector contains denylisted substring '{needle}' — clicks must not trigger \
                         payment, purchase, deletion, account, credential or submission flows; \
                         this action is rejected by design and cannot be overridden"
                    )),
                ));
            }
        }
        for pattern in CLICK_TYPE_SUBMIT_PATTERNS {
            if lower.contains(pattern) {
                errors.push(InteractionError::at(
                    top_index,
                    where_(format!(
                        "click selector matches denylisted pattern '{pattern}' — clicks must not submit forms; \
                         this action is rejected by design and cannot be overridden"
                    )),
                ));
            }
        }
    }
}

fn validate_navigate(
    url: &str,
    base_origin: Option<&Url>,
    top_index: usize,
    where_: &dyn Fn(String) -> String,
    errors: &mut Vec<InteractionError>,
) {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => {
            errors.push(InteractionError::at(
                top_index,
                where_("navigate requires absolute URL".to_string()),
            ));
            return;
        }
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        errors.push(InteractionError::at(
            top_index,
            where_(format!(
                "navigate requires an absolute http(s) URL, got scheme '{}'",
                parsed.scheme()
            )),
        ));
        return;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        errors.push(InteractionError::at(
            top_index,
            where_("navigate URL must not contain userinfo (user:password@host)".to_string()),
        ));
    }
    if parsed.host_str().is_none() {
        errors.push(InteractionError::at(
            top_index,
            where_("navigate URL must have a host".to_string()),
        ));
    }
    if let Some(base) = base_origin
        && !same_origin(&parsed, base)
    {
        errors.push(InteractionError::at(
            top_index,
            where_(format!(
                "cross-origin navigation rejected: '{}' is not the same origin as '{}' (scheme, host and port must all match)",
                parsed.origin().ascii_serialization(),
                base.origin().ascii_serialization()
            )),
        ));
    }
}

/// Same-origin = identical scheme, host and effective port (default ports
/// resolved). Fragments are allowed to differ; they do not affect origin.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme().eq_ignore_ascii_case(b.scheme())
        && a.host() == b.host()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn validate_wait_js(
    condition: &str,
    top_index: usize,
    where_: &dyn Fn(String) -> String,
    errors: &mut Vec<InteractionError>,
) {
    if condition.chars().count() > MAX_WAIT_JS_LEN {
        errors.push(InteractionError::at(
            top_index,
            where_(format!(
                "wait_js condition is too long ({} chars; max {MAX_WAIT_JS_LEN})",
                condition.chars().count()
            )),
        ));
    }
    let lower = condition.to_ascii_lowercase();
    for needle in WAIT_JS_DENYLIST {
        if lower.contains(&needle.to_ascii_lowercase()) {
            errors.push(InteractionError::at(
                top_index,
                where_(format!(
                    "wait_js condition contains denylisted pattern '{needle}' — conditions must not \
                     read page data (cookies), transmit data (fetch/XHR/sendBeacon/WebSocket) or evaluate \
                     dynamic code; this action is rejected by design"
                )),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interactions::actions::{OnError, ScrollDirection};

    fn limits() -> InteractionLimits {
        // Defaults: 50 actions, 10_000 ms click wait, 20 scroll ops, 300_000 ms.
        InteractionLimits::new(50, 10_000, 20, 300_000)
    }

    fn wait_duration(ms: u64) -> Action {
        Action::WaitDuration {
            ms,
            jitter_pct: Some(0.0),
        }
    }

    fn wait_selector(timeout_ms: u64) -> Action {
        Action::WaitSelector {
            selector: "main".to_string(),
            timeout_ms: Some(timeout_ms),
        }
    }

    fn click(selector: &str) -> Action {
        Action::Click {
            selector: selector.to_string(),
            wait_after_ms: None,
        }
    }

    fn navigate(url: &str) -> Action {
        Action::Navigate {
            url: url.to_string(),
        }
    }

    fn seq(actions: Vec<Action>) -> InteractionSequence {
        InteractionSequence {
            actions,
            on_error: OnError::Abort,
            variation_group_seed: None,
        }
    }

    fn base() -> Url {
        Url::parse("https://example.com/start/?q=1").unwrap()
    }

    fn messages(errors: &[InteractionError]) -> Vec<&str> {
        errors.iter().map(|e| e.message.as_str()).collect()
    }

    // --- passing fixtures -------------------------------------------------

    #[test]
    fn empty_sequence_is_valid_basic_mode() {
        assert!(validate_sequence(&seq(vec![]), &limits(), None).is_ok());
    }

    #[test]
    fn simple_valid_sequence_passes() {
        let s = seq(vec![
            navigate("https://example.com/"),
            Action::WaitDuration {
                ms: 1000,
                jitter_pct: None, // 20% default
            },
            Action::WaitSelector {
                selector: "article".to_string(),
                timeout_ms: Some(5000),
            },
            Action::Scroll {
                direction: ScrollDirection::Vertical,
                distance_px: 600,
                operations: 3,
                delay_ms: 400,
            },
            click("nav a.nutrition"),
            Action::EndSession,
        ]);
        assert!(validate_sequence(&s, &limits(), Some(&base())).is_ok());
    }

    #[test]
    fn rotate_with_mixed_choice_types_is_allowed() {
        let s = seq(vec![Action::Rotate {
            choices: vec![
                navigate("https://example.com/a"),
                Action::WaitDuration {
                    ms: 100,
                    jitter_pct: Some(25.0),
                },
            ],
        }]);
        assert!(validate_sequence(&s, &limits(), Some(&base())).is_ok());
    }

    #[test]
    fn navigate_same_origin_allowed_with_fragment_and_case_insensitive_host() {
        let s = seq(vec![navigate("HTTPS://EXAMPLE.COM/other#frag")]);
        assert!(validate_sequence(&s, &limits(), Some(&base())).is_ok());
    }

    #[test]
    fn navigate_default_port_matches_explicit() {
        let base = Url::parse("https://example.com:443/").unwrap();
        let s = seq(vec![navigate("https://example.com/other")]);
        assert!(validate_sequence(&s, &limits(), Some(&base)).is_ok());
    }

    #[test]
    fn boundaries_are_inclusive() {
        let s = seq(vec![Action::Scroll {
            direction: ScrollDirection::Horizontal,
            distance_px: 5000,
            operations: 20,
            delay_ms: 5000,
        }]);
        let lim = InteractionLimits::new(50, 10_000, 20, u64::MAX);
        assert!(validate_sequence(&s, &lim, None).is_ok());

        let click_at_limit = seq(vec![Action::Click {
            selector: "main".to_string(),
            wait_after_ms: Some(10_000),
        }]);
        assert!(validate_sequence(&click_at_limit, &limits(), None).is_ok());
    }

    // --- sequence-level rules ----------------------------------------------

    #[test]
    fn too_many_actions_rejected() {
        let actions: Vec<Action> = (0..51).map(|_| wait_duration(1)).collect();
        let s = seq(actions);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.action_index.is_none() && e.message.contains("too many actions (51"))
        );
    }

    #[test]
    fn rotate_counts_as_one_plus_full_weight_of_branches() {
        // 1 rotate + 3 inner waits + 1 click + 1 click = 6 actions.
        let s = seq(vec![
            Action::Rotate {
                choices: vec![wait_duration(1), wait_duration(1), wait_duration(1)],
            },
            click("main"),
            click("main"),
        ]);
        let lim = InteractionLimits::new(5, 10_000, 20, u64::MAX);
        let errors = validate_sequence(&s, &lim, None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("too many actions (6"))
        );
    }

    #[test]
    fn conservative_cost_exceeds_cap_with_exact_math() {
        // 6 actions * 10_000 ms per-action ceiling = 60_000 ms > 50_000 ms cap.
        let s = seq((0..6).map(|_| wait_selector(10_000)).collect());
        let lim = InteractionLimits::new(50, 10_000, 20, 50_000);
        let errors = validate_sequence(&s, &lim, None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("60000ms") && e.message.contains("50000ms")),
            "expected exact cap math in: {:?}",
            messages(&errors)
        );
    }

    #[test]
    fn conservative_cost_within_cap_is_accepted() {
        let s = seq((0..5).map(|_| wait_selector(10_000)).collect());
        let lim = InteractionLimits::new(50, 10_000, 20, 50_000);
        assert!(validate_sequence(&s, &lim, None).is_ok());
    }

    #[test]
    fn wait_duration_cost_uses_jitter_upper_bound() {
        // 100_000 ms with 50% jitter -> 150_000 ms conservative budget.
        let s = seq(vec![Action::WaitDuration {
            ms: 100_000,
            jitter_pct: Some(50.0),
        }]);
        let lim_ok = InteractionLimits::new(50, 10_000, 20, 150_000);
        assert!(validate_sequence(&s, &lim_ok, None).is_ok());

        let lim_tight = InteractionLimits::new(50, 10_000, 20, 149_999);
        let errors = validate_sequence(&s, &lim_tight, None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("150000ms") && e.message.contains("149999ms"))
        );
    }

    #[test]
    fn scroll_cost_is_operations_times_delay() {
        // 4 ops * 1000 ms = 4000 ms budget.
        let s = seq(vec![Action::Scroll {
            direction: ScrollDirection::Vertical,
            distance_px: 100,
            operations: 4,
            delay_ms: 1000,
        }]);
        let lim_tight = InteractionLimits::new(50, 10_000, 20, 3_999);
        assert!(validate_sequence(&s, &lim_tight, None).is_err());
        let lim_ok = InteractionLimits::new(50, 10_000, 20, 4_000);
        assert!(validate_sequence(&s, &lim_ok, None).is_ok());
    }

    #[test]
    fn rotate_branches_count_with_full_weight_for_budget() {
        // Budget = sum of ALL branches (conservative), not the max branch.
        let s = seq(vec![Action::Rotate {
            choices: vec![
                Action::WaitDuration {
                    ms: 20_000,
                    jitter_pct: Some(0.0),
                },
                Action::WaitDuration {
                    ms: 20_000,
                    jitter_pct: Some(0.0),
                },
            ],
        }]);
        let lim_tight = InteractionLimits::new(50, 10_000, 20, 39_999);
        let errors = validate_sequence(&s, &lim_tight, None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("40000ms") && e.message.contains("39999ms"))
        );
        let lim_ok = InteractionLimits::new(50, 10_000, 20, 40_000);
        assert!(validate_sequence(&s, &lim_ok, None).is_ok());
    }

    #[test]
    fn navigate_cap_is_four() {
        let s = seq((0..5)
            .map(|i| navigate(&format!("https://example.com/p{i}")))
            .collect());
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.action_index.is_none() && e.message.contains("at most 4"))
        );

        let s4 = seq((0..4)
            .map(|i| navigate(&format!("https://example.com/p{i}")))
            .collect());
        assert!(validate_sequence(&s4, &limits(), None).is_ok());
    }

    #[test]
    fn navigate_cap_counts_rotate_branches_with_full_weight() {
        let s = seq(vec![Action::Rotate {
            choices: vec![
                navigate("https://example.com/1"),
                navigate("https://example.com/2"),
                navigate("https://example.com/3"),
                navigate("https://example.com/4"),
                navigate("https://example.com/5"),
            ],
        }]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("at most 4")));
    }

    // --- rotate -------------------------------------------------------------

    #[test]
    fn rotate_requires_at_least_one_choice() {
        let s = seq(vec![Action::Rotate { choices: vec![] }]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.action_index == Some(0) && e.message.contains("at least 1 choice"))
        );
    }

    #[test]
    fn rotate_allows_at_most_eight_choices() {
        let eight: Vec<Action> = (0..8).map(|_| wait_duration(1)).collect();
        let nine: Vec<Action> = (0..9).map(|_| wait_duration(1)).collect();
        assert!(
            validate_sequence(
                &seq(vec![Action::Rotate { choices: eight }]),
                &limits(),
                None
            )
            .is_ok()
        );
        let errors = validate_sequence(
            &seq(vec![Action::Rotate { choices: nine }]),
            &limits(),
            None,
        )
        .unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("at most 8")));
    }

    #[test]
    fn rotate_may_not_nest() {
        let s = seq(vec![Action::Rotate {
            choices: vec![Action::Rotate {
                choices: vec![click("main")],
            }],
        }]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.action_index == Some(0) && e.message.contains("nested rotate"))
        );
    }

    #[test]
    fn rotate_may_not_contain_end_session() {
        let s = seq(vec![Action::Rotate {
            choices: vec![wait_duration(1), Action::EndSession],
        }]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.action_index == Some(0) && e.message.contains("end_session"))
        );
    }

    // --- end_session ---------------------------------------------------------

    #[test]
    fn end_session_as_final_action_is_ok() {
        let s = seq(vec![wait_duration(1), Action::EndSession]);
        assert!(validate_sequence(&s, &limits(), None).is_ok());
    }

    #[test]
    fn end_session_not_last_is_rejected() {
        let s = seq(vec![Action::EndSession, wait_duration(1)]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.action_index == Some(0) && e.message.contains("final action"))
        );
    }

    #[test]
    fn end_session_twice_is_rejected() {
        let s = seq(vec![Action::EndSession, Action::EndSession]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("at most one end_session"))
        );
        // ... and the non-final one is also flagged.
        assert!(
            errors
                .iter()
                .any(|e| e.action_index == Some(0) && e.message.contains("final action"))
        );
    }

    // --- navigate -------------------------------------------------------------

    #[test]
    fn navigate_relative_url_rejected_with_absolute_message() {
        for rel in ["/path/to/page", "example.com/no-scheme", "//example.com/x"] {
            let s = seq(vec![navigate(rel)]);
            let errors = validate_sequence(&s, &limits(), None).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|e| e.action_index == Some(0)
                        && e.message == "navigate requires absolute URL"),
                "{rel}: {:?}",
                messages(&errors)
            );
        }
    }

    #[test]
    fn navigate_non_http_schemes_rejected() {
        for bad in [
            "ftp://example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<b>x</b>",
        ] {
            let s = seq(vec![navigate(bad)]);
            let errors = validate_sequence(&s, &limits(), None).unwrap_err();
            assert!(
                errors.iter().any(|e| e.message.contains("scheme")),
                "{bad}: {:?}",
                messages(&errors)
            );
        }
    }

    #[test]
    fn navigate_userinfo_rejected() {
        let s = seq(vec![navigate("https://user:pass@example.com/")]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("userinfo")));
    }

    #[test]
    fn navigate_cross_origin_rejected() {
        for other in [
            "https://other.com/",         // different host
            "https://cdn.example.com/a",  // subdomain is not the same origin
            "http://example.com/",        // scheme mismatch
            "https://example.com:8443/x", // port mismatch
        ] {
            let s = seq(vec![navigate(other)]);
            let errors = validate_sequence(&s, &limits(), Some(&base())).unwrap_err();
            assert!(
                errors.iter().any(|e| e.message.contains("cross-origin")),
                "{other}: {:?}",
                messages(&errors)
            );
        }
    }

    #[test]
    fn navigate_same_origin_variants_allowed() {
        for good in [
            "https://example.com/",
            "https://example.com/start/?q=1#frag",
            "https://example.com:443/default-port",
            "https://EXAMPLE.COM/case-insensitive",
        ] {
            let s = seq(vec![navigate(good)]);
            assert!(
                validate_sequence(&s, &limits(), Some(&base())).is_ok(),
                "{good}"
            );
        }
    }

    // --- selectors (shared rules) -------------------------------------------

    #[test]
    fn selector_longer_than_200_chars_rejected() {
        let long = "a".repeat(201);
        let s = seq(vec![Action::WaitSelector {
            selector: long,
            timeout_ms: None,
        }]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("too long")));

        let exact = "a".repeat(200);
        let s = seq(vec![Action::WaitSelector {
            selector: exact,
            timeout_ms: None,
        }]);
        assert!(validate_sequence(&s, &limits(), None).is_ok());
    }

    #[test]
    fn selector_multiline_rejected() {
        for bad in ["div\np.span", "div\rp"] {
            let s = seq(vec![click(bad)]);
            let errors = validate_sequence(&s, &limits(), None).unwrap_err();
            assert!(errors.iter().any(|e| e.message.contains("single line")));
        }
    }

    #[test]
    fn selector_forbidden_chars_rejected() {
        for bad in ["div { color: red }", "div } span", "div`x`"] {
            let s = seq(vec![click(bad)]);
            let errors = validate_sequence(&s, &limits(), None).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|e| e.message.contains("must not contain")),
                "{bad}: {:?}",
                messages(&errors)
            );
        }
    }

    #[test]
    fn selector_javascript_and_data_urls_rejected() {
        for bad in [
            "a[href='javascript:alert(1)']",
            "a[href='JAVASCRIPT:alert(1)']",
            "a[href='data:text/html;base64,xx']",
            "a[href='DATA:x']",
        ] {
            let s = seq(vec![click(bad)]);
            let errors = validate_sequence(&s, &limits(), None).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|e| e.message.contains("javascript:") || e.message.contains("data:")),
                "{bad}: {:?}",
                messages(&errors)
            );
        }
    }

    #[test]
    fn selector_empty_rejected() {
        let s = seq(vec![click("")]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("must not be empty"))
        );
    }

    // --- click denylist (full table) ------------------------------------------

    #[test]
    fn click_denylist_rejects_every_substring() {
        // Every denylist entry is exercised; the substring is embedded in an
        // otherwise plausible selector.
        for needle in CLICK_SELECTOR_DENYLIST {
            let selector = format!("button.{needle}-action");
            let s = seq(vec![click(&selector)]);
            let errors = validate_sequence(&s, &limits(), None).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|e| e.action_index == Some(0) && e.message.contains(needle)),
                "denylist entry {needle:?} not rejected in {selector:?}: {:?}",
                messages(&errors)
            );
        }
        // The table is the contract: exactly these 17 substrings.
        assert_eq!(CLICK_SELECTOR_DENYLIST.len(), 17);
    }

    #[test]
    fn click_denylist_is_case_insensitive() {
        for bad in [
            ".PAY-NOW",
            "button.Checkout",
            "a.SUBMIT",
            "button.Password-Reset",
        ] {
            let s = seq(vec![click(bad)]);
            assert!(
                validate_sequence(&s, &limits(), None).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn click_type_submit_patterns_rejected() {
        for bad in [
            "input[type=submit]",
            "button[type=submit]",
            "input[type='submit']",
            "button[type=\"submit\"]",
        ] {
            let s = seq(vec![click(bad)]);
            let errors = validate_sequence(&s, &limits(), None).unwrap_err();
            assert!(
                errors.iter().any(|e| e.message.contains("submit")),
                "{bad}: {:?}",
                messages(&errors)
            );
        }
    }

    #[test]
    fn wait_selector_is_not_denylist_checked() {
        // The denylist guards synthesised clicks only; waiting on a payment
        // confirmation banner is legitimate.
        let s = seq(vec![Action::WaitSelector {
            selector: ".payment-confirmation-banner".to_string(),
            timeout_ms: Some(1000),
        }]);
        assert!(validate_sequence(&s, &limits(), None).is_ok());
    }

    #[test]
    fn click_wait_after_ms_bounded_by_config() {
        let ok = seq(vec![Action::Click {
            selector: "main a".to_string(),
            wait_after_ms: Some(10_000),
        }]);
        assert!(validate_sequence(&ok, &limits(), None).is_ok());

        let too_big = seq(vec![Action::Click {
            selector: "main a".to_string(),
            wait_after_ms: Some(10_001),
        }]);
        let errors = validate_sequence(&too_big, &limits(), None).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.action_index == Some(0) && e.message.contains("wait_after_ms"))
        );
    }

    // --- wait_js denylist (full table) -----------------------------------------

    #[test]
    fn wait_js_denylist_rejects_every_pattern() {
        for needle in WAIT_JS_DENYLIST {
            let condition = format!("window.__probe && {needle} 1");
            let s = seq(vec![Action::WaitJs {
                condition: condition.clone(),
                timeout_ms: None,
            }]);
            let errors = validate_sequence(&s, &limits(), None).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|e| e.action_index == Some(0) && e.message.contains(needle)),
                "wait_js pattern {needle:?} not rejected: {:?}",
                messages(&errors)
            );
        }
        assert_eq!(WAIT_JS_DENYLIST.len(), 7);
    }

    #[test]
    fn wait_js_document_cookie_rejected() {
        for bad in [
            "document.cookie.includes('session')",
            "document.cookie.length > 0",
        ] {
            let s = seq(vec![Action::WaitJs {
                condition: bad.to_string(),
                timeout_ms: None,
            }]);
            assert!(
                validate_sequence(&s, &limits(), None).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn wait_js_is_case_insensitive() {
        for bad in [
            "FETCH('https://example.com/x')",
            "Eval('1+1')",
            "WINDOW.XMLHTTPREQUEST",
        ] {
            let s = seq(vec![Action::WaitJs {
                condition: bad.to_string(),
                timeout_ms: None,
            }]);
            assert!(
                validate_sequence(&s, &limits(), None).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn wait_js_longer_than_500_chars_rejected() {
        let long = format!("document.title.length > 0 // {}", "x".repeat(472));
        assert_eq!(long.chars().count(), 501);
        let s = seq(vec![Action::WaitJs {
            condition: long,
            timeout_ms: None,
        }]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("too long")));

        // "document.title.length > 0 // " is 29 chars; exactly 500 total is
        // accepted, 501 is rejected.
        let exact = format!("document.title.length > 0 // {}", "x".repeat(471));
        assert_eq!(exact.chars().count(), 500);
        let s = seq(vec![Action::WaitJs {
            condition: exact,
            timeout_ms: None,
        }]);
        assert!(validate_sequence(&s, &limits(), None).is_ok());
    }

    #[test]
    fn wait_js_clean_condition_passes() {
        let s = seq(vec![Action::WaitJs {
            condition: "document.querySelectorAll('.item').length > 3".to_string(),
            timeout_ms: Some(5000),
        }]);
        assert!(validate_sequence(&s, &limits(), None).is_ok());
    }

    // --- scroll bounds ----------------------------------------------------------

    #[test]
    fn scroll_distance_bounds() {
        for (distance_px, ok) in [
            (0, false),
            (1, true),
            (5000, true),
            (5001, false),
            (-1, false),
        ] {
            let s = seq(vec![Action::Scroll {
                direction: ScrollDirection::Vertical,
                distance_px,
                operations: 1,
                delay_ms: 100,
            }]);
            assert_eq!(
                validate_sequence(&s, &limits(), None).is_ok(),
                ok,
                "distance_px {distance_px}"
            );
        }
    }

    #[test]
    fn scroll_operations_bounds() {
        for (operations, ok) in [(0, false), (1, true), (20, true), (21, false)] {
            let s = seq(vec![Action::Scroll {
                direction: ScrollDirection::Vertical,
                distance_px: 100,
                operations,
                delay_ms: 100,
            }]);
            assert_eq!(
                validate_sequence(&s, &limits(), None).is_ok(),
                ok,
                "operations {operations}"
            );
        }
    }

    #[test]
    fn scroll_operations_bounded_by_custom_limit() {
        let lim = InteractionLimits::new(50, 10_000, 5, u64::MAX);
        let s = seq(vec![Action::Scroll {
            direction: ScrollDirection::Vertical,
            distance_px: 100,
            operations: 6,
            delay_ms: 100,
        }]);
        assert!(validate_sequence(&s, &lim, None).is_err());
    }

    #[test]
    fn scroll_delay_bounds() {
        for (delay_ms, ok) in [(49, false), (50, true), (5000, true), (5001, false)] {
            let s = seq(vec![Action::Scroll {
                direction: ScrollDirection::Vertical,
                distance_px: 100,
                operations: 1,
                delay_ms,
            }]);
            assert_eq!(
                validate_sequence(&s, &limits(), None).is_ok(),
                ok,
                "delay_ms {delay_ms}"
            );
        }
    }

    // --- jitter ------------------------------------------------------------------

    #[test]
    fn wait_duration_jitter_out_of_range_rejected() {
        for bad in [-1.0, 100.5, 200.0, f64::INFINITY, f64::NAN] {
            let s = seq(vec![Action::WaitDuration {
                ms: 100,
                jitter_pct: Some(bad),
            }]);
            assert!(
                validate_sequence(&s, &limits(), None).is_err(),
                "jitter {bad} must be rejected"
            );
        }
        for good in [0.0, 20.0, 100.0] {
            let s = seq(vec![Action::WaitDuration {
                ms: 100,
                jitter_pct: Some(good),
            }]);
            assert!(validate_sequence(&s, &limits(), None).is_ok());
        }
    }

    // --- aggregation & display ---------------------------------------------------

    #[test]
    fn validator_collects_all_errors_not_fail_fast() {
        // Three independent violations in one sequence — all must be reported.
        let s = seq(vec![
            navigate("relative/path"), // 0: navigate absolute
            Action::WaitJs {
                condition: "document.cookie".to_string(), // 1: wait_js denylist
                timeout_ms: None,
            },
            click("pay"), // 2: click denylist ("pay")
        ]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        assert!(errors.len() >= 3, "expected >= 3 errors: {errors:?}");
        assert!(errors.iter().any(|e| e.action_index == Some(0)));
        assert!(errors.iter().any(|e| e.action_index == Some(1)));
        assert!(errors.iter().any(|e| e.action_index == Some(2)));
    }

    #[test]
    fn rotate_nested_errors_report_top_level_index_with_branch_context() {
        let s = seq(vec![
            wait_duration(1),
            Action::Rotate {
                choices: vec![click("button.pay-now")],
            },
        ]);
        let errors = validate_sequence(&s, &limits(), None).unwrap_err();
        let nested = errors
            .iter()
            .find(|e| e.message.contains("rotate choice 1"))
            .expect("branch context in message");
        assert_eq!(nested.action_index, Some(1));
    }

    #[test]
    fn interaction_error_display_includes_index_and_message() {
        let e = InteractionError::at(3, "something broke");
        assert_eq!(e.to_string(), "action 3: something broke");
        let e = InteractionError::sequence("global thing");
        assert_eq!(e.to_string(), "sequence: global thing");
    }
}
