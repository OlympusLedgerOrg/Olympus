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
}
