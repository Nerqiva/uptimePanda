//! Interval jitter — uniform random delays between monitoring cycles.
//!
//! Scheduling randomness exists to spread out visits and avoid lockstep
//! polling patterns. It does **not** need cryptographic strength: an
//! ordinary RNG (`rand::rng()`, the thread-local thread-safe generator)
//! is sufficient. No CSPRNG is used or required for scheduling.
//!
//! All functions here are pure (no I/O, no database) so they can be
//! exhaustively unit-tested.

use rand::RngExt;
use rand::rng;

/// Jitter helpers grouped as an empty-namespace struct. Everything is a
/// static method; there is no state to hold.
///
/// Documented in the module header: ordinary RNG is sufficient —
/// no CSPRNG for scheduling.
pub struct Jitter;

impl Jitter {
    /// Uniform random interval in `[min_s, max_s]` **inclusive**.
    ///
    /// `min_s == max_s` yields exactly that value (fixed interval mode).
    /// Panics if `min_s > max_s` — call sites must validate bounds
    /// (the website row's `min_interval_seconds <= max_interval_seconds`
    /// CHECK constraint plus the application's own input validation
    /// guarantee this).
    pub fn next_interval(min_s: i64, max_s: i64) -> i64 {
        assert!(
            min_s <= max_s,
            "next_interval: min_s ({min_s}) must be <= max_s ({max_s})"
        );
        if min_s == max_s {
            return min_s;
        }
        // Inclusive upper bound — `random_range(a..=b)` with i64 bounds.
        rng().random_range(min_s..=max_s)
    }
}

/// Free-function form of [`Jitter::next_interval`] for call sites that
/// prefer it.
pub fn next_interval(min_s: i64, max_s: i64) -> i64 {
    Jitter::next_interval(min_s, max_s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DRAWS: usize = 10_000;

    fn assert_bounds(min_s: i64, max_s: i64) {
        for _ in 0..DRAWS {
            let v = next_interval(min_s, max_s);
            assert!(
                (min_s..=max_s).contains(&v),
                "draw {v} out of [{min_s}, {max_s}]"
            );
        }
    }

    #[test]
    fn bounds_hold_across_ranges() {
        assert_bounds(480, 780);
        assert_bounds(1, 2);
        assert_bounds(30, 86_400);
        assert_bounds(0, 1);
    }

    #[test]
    fn min_equals_max_is_exact() {
        for _ in 0..1_000 {
            assert_eq!(next_interval(480, 480), 480);
            assert_eq!(next_interval(0, 0), 0);
            assert_eq!(next_interval(-5, -5), -5);
        }
    }

    #[test]
    #[should_panic(expected = "min_s")]
    fn inverted_bounds_panic() {
        let _ = next_interval(10, 5);
    }
}
