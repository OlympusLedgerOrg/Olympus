//! Integration tests for `olympus_matcher`.
//!
//! Uses the pure-Rust `CoreMatcher` so that tests run with `cargo test`
//! without requiring a Python interpreter to be linked.
//!
//! Covers:
//! - Property tests (arbitrary inputs never panic, linear-time guarantee)
//! - Unit tests (API correctness)

#[cfg(test)]
mod tests {
    use olympus_matcher::core::CoreMatcher;

    // ── unit tests ────────────────────────────────────────────────────────────

    #[test]
    fn empty_matcher_returns_none() {
        let m = CoreMatcher::new();
        assert!(m.match_first("anything").is_none());
    }

    #[test]
    fn match_all_empty_returns_empty_vec() {
        let m = CoreMatcher::new();
        assert!(m.match_all("anything").is_empty());
    }

    #[test]
    fn add_invalid_raw_pattern_raises_error() {
        let mut m = CoreMatcher::new();
        // An unmatched `(` is an invalid regex.
        let err = m.add_raw_pattern("bad", "(unclosed").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("(unclosed"), "expected pattern in error: {msg}");
    }

    #[test]
    fn add_invalid_adl_pattern_raises_error() {
        let mut m = CoreMatcher::new();
        // Empty string is not a valid ADL pattern.
        let err = m.add_pattern("bad", "").unwrap_err();
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn match_all_returns_one_result_per_matching_pattern() {
        let mut m = CoreMatcher::new();
        m.add_raw_pattern("alpha", r"\d+").unwrap();
        m.add_raw_pattern("beta", r"hello").unwrap();
        m.add_raw_pattern("gamma", r"world").unwrap();

        // "hello 42" matches alpha and beta but not gamma
        let results = m.match_all("hello 42");
        let names: Vec<&str> = results.iter().map(|r| r.pattern.as_str()).collect();
        assert!(names.contains(&"alpha"), "expected alpha in {names:?}");
        assert!(names.contains(&"beta"), "expected beta in {names:?}");
        assert!(!names.contains(&"gamma"), "gamma should not match: {names:?}");
    }

    #[test]
    fn match_first_returns_first_loaded_pattern() {
        let mut m = CoreMatcher::new();
        m.add_raw_pattern("first", r"a").unwrap();
        m.add_raw_pattern("second", r"a").unwrap();

        let result = m.match_first("a").unwrap();
        assert_eq!(result.pattern, "first");
    }

    #[test]
    fn pattern_names_returns_insertion_order() {
        let mut m = CoreMatcher::new();
        m.add_raw_pattern("z", r"z").unwrap();
        m.add_raw_pattern("a", r"a").unwrap();
        m.add_raw_pattern("m", r"m").unwrap();

        assert_eq!(m.pattern_names(), vec!["z", "a", "m"]);
    }

    #[test]
    fn match_result_fields_accessible() {
        let mut m = CoreMatcher::new();
        m.add_raw_pattern("num", r"(\d+)").unwrap();

        let result = m.match_first("abc 123 def").unwrap();
        assert!(result.matched);
        assert_eq!(result.pattern, "num");
        assert!(result.span.is_some());
        assert!(!result.captures.is_empty());
    }

    #[test]
    fn adl_literal_matches_itself() {
        let mut m = CoreMatcher::new();
        m.add_pattern("marker", r#""[REDACTED]""#).unwrap();
        let result = m.match_first("document [REDACTED] end");
        assert!(result.is_some(), "ADL literal should match its content");
    }

    #[test]
    fn adl_glob_matches_extension() {
        let mut m = CoreMatcher::new();
        m.add_pattern("doc_ref", "*.pdf").unwrap();
        assert!(m.match_first("report.pdf").is_some());
        assert!(m.match_first("report.txt").is_none());
    }

    // ── property tests ────────────────────────────────────────────────────────
    //
    // We use hand-rolled fuzz loops instead of proptest to keep the
    // test executable self-contained without a proptest runner setup.

    /// Arbitrary input strings never cause match_first to panic.
    #[test]
    fn match_first_never_panics_on_arbitrary_input() {
        let mut m = CoreMatcher::new();
        m.add_raw_pattern("p1", r"\w+").unwrap();
        m.add_pattern("p2", r#""hello""#).unwrap();

        let inputs: &[&str] = &[
            "",
            "a",
            "hello world",
            "\0\x01\x02",
            &"a".repeat(10_000),
            &"🦀".repeat(1_000),
            "SELECT * FROM users; DROP TABLE users;--",
            "<script>alert('xss')</script>",
        ];

        for input in inputs {
            let _ = m.match_first(input);
        }
    }

    /// Arbitrary input strings never cause match_all to panic.
    #[test]
    fn match_all_never_panics_on_arbitrary_input() {
        let mut m = CoreMatcher::new();
        m.add_raw_pattern("p1", r"\d+").unwrap();
        m.add_raw_pattern("p2", r"[a-z]+").unwrap();

        let inputs: &[&str] = &[
            "",
            "abc 123",
            &"x".repeat(100_000),
            &"1".repeat(100_000),
        ];

        for input in inputs {
            let _ = m.match_all(input);
        }
    }

    /// Demonstrate linear-time behaviour: matching a 100k-char string
    /// should complete well within any reasonable deadline (the test just
    /// asserts it does not panic / hang).
    #[test]
    fn long_input_completes_without_panic() {
        let mut m = CoreMatcher::new();
        // A pattern that could catastrophically backtrack in a PCRE engine.
        // `regex` crate uses DFA — guaranteed linear time.
        m.add_raw_pattern("redos_probe", r"(a+)+b").unwrap();

        let long_input = "a".repeat(100_000);
        // Should return quickly (no match) without hanging.
        let result = m.match_first(&long_input);
        assert!(result.is_none());
    }

    // ── linear-time regression guard ──────────────────────────────────────

    /// Regression guard: assert that matching time scales linearly with
    /// input size rather than exponentially.
    ///
    /// Measures wall-clock time for the `(a+)+b` ReDoS probe at two input
    /// sizes (SMALL_N and LARGE_N, a 10× increase).  For linear-time
    /// matching the ratio `t_large / t_small` should stay close to the
    /// size ratio.  We allow up to MAX_RATIO× to absorb measurement noise,
    /// JIT warm-up, and cache effects.  Catastrophic backtracking in a PCRE
    /// engine would produce a ratio >> 1000× for these sizes.
    #[test]
    fn redos_linear_time_scaling() {
        use std::time::Instant;

        const SMALL_N: usize = 10_000;
        const LARGE_N: usize = 100_000;
        // A 10× size jump should not produce more than 20× runtime.
        // True linear is ~10×; we allow 2× headroom for noise.
        const MAX_RATIO: f64 = 20.0;
        // How many iterations to average out jitter.
        const ITERS: u32 = 5;

        let mut m = CoreMatcher::new();
        m.add_raw_pattern("redos_probe", r"(a+)+b").unwrap();

        let small_input = "a".repeat(SMALL_N);
        let large_input = "a".repeat(LARGE_N);

        // Warm up.
        let _ = m.match_first(&small_input);
        let _ = m.match_first(&large_input);

        let t_small = {
            let start = Instant::now();
            for _ in 0..ITERS {
                let _ = m.match_first(&small_input);
            }
            start.elapsed()
        };

        let t_large = {
            let start = Instant::now();
            for _ in 0..ITERS {
                let _ = m.match_first(&large_input);
            }
            start.elapsed()
        };

        // Guard against division by zero when t_small is essentially instant.
        let ratio = t_large.as_secs_f64() / t_small.as_secs_f64().max(1e-12);

        assert!(
            ratio < MAX_RATIO,
            "Matching time does not scale linearly! \
             {SMALL_N}-char: {t_small:?}, {LARGE_N}-char: {t_large:?}, \
             ratio: {ratio:.1}× (max allowed: {MAX_RATIO}×). \
             This indicates non-linear (possibly exponential) behaviour."
        );
    }

    /// Hard timeout guard: matching the ReDoS probe on a 100k-char input
    /// must complete within 100 ms total across ITERS iterations.
    /// Catastrophic backtracking would take minutes/hours on this input.
    #[test]
    fn redos_hard_timeout() {
        use std::time::{Duration, Instant};

        const INPUT_LEN: usize = 100_000;
        const ITERS: u32 = 10;
        const MAX_TOTAL: Duration = Duration::from_millis(100);

        let mut m = CoreMatcher::new();
        m.add_raw_pattern("redos_probe", r"(a+)+b").unwrap();

        let input = "a".repeat(INPUT_LEN);

        // Warm up.
        let _ = m.match_first(&input);

        let start = Instant::now();
        for _ in 0..ITERS {
            let _ = m.match_first(&input);
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed < MAX_TOTAL,
            "ReDoS probe on {INPUT_LEN}-char input exceeded hard timeout! \
             {ITERS} iterations took {elapsed:?} (limit: {MAX_TOTAL:?}). \
             Matching may not be running in linear time."
        );
    }
}
