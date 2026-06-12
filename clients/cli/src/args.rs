//! Tiny zero-dependency argument parser.
//!
//! Supports `--key value`, `--key=value`, and bare boolean `--flag`. Flags named
//! in [`BOOL_FLAGS`] never consume a following token, so a boolean flag placed
//! immediately before a positional is unambiguous. This is deliberately minimal
//! — the CLI has a small, fixed option surface and avoids pulling a full
//! arg-parsing crate so the offline core builds with no extra dependencies.

use std::collections::{HashMap, HashSet};

/// Flags that are always boolean (presence-only): they never swallow the next
/// token as a value. Keep in sync with the boolean options documented per
/// command.
pub const BOOL_FLAGS: &[&str] = &["shard-from-subdir"];

/// Parsed arguments: value flags, boolean flags, and positionals.
pub struct Args {
    values: HashMap<String, String>,
    flags: HashSet<String>,
    positional: Vec<String>,
}

impl Args {
    /// Parse argument tokens (excluding the program name and subcommand).
    pub fn parse<I: IntoIterator<Item = String>>(tokens: I) -> Self {
        let toks: Vec<String> = tokens.into_iter().collect();
        let mut values = HashMap::new();
        let mut flags = HashSet::new();
        let mut positional = Vec::new();
        let mut i = 0;
        while i < toks.len() {
            let t = &toks[i];
            if let Some(rest) = t.strip_prefix("--") {
                if let Some((k, v)) = rest.split_once('=') {
                    // Treat `--key=` (empty RHS) as absent, not present-but-empty,
                    // so `req()` reports it missing rather than yielding "".
                    if !v.is_empty() {
                        values.insert(k.to_string(), v.to_string());
                    }
                    i += 1;
                } else if BOOL_FLAGS.contains(&rest) {
                    flags.insert(rest.to_string());
                    i += 1;
                } else if i + 1 < toks.len() && !toks[i + 1].starts_with("--") {
                    // Same rule for `--key ""`: consume the token but don't record
                    // an empty value.
                    if !toks[i + 1].is_empty() {
                        values.insert(rest.to_string(), toks[i + 1].clone());
                    }
                    i += 2;
                } else {
                    flags.insert(rest.to_string());
                    i += 1;
                }
            } else {
                positional.push(t.clone());
                i += 1;
            }
        }
        Self {
            values,
            flags,
            positional,
        }
    }

    /// A required value flag, or an error message naming it.
    pub fn req(&self, key: &str) -> Result<&str, String> {
        self.values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("missing required --{key}"))
    }

    /// An optional value flag.
    pub fn opt(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// A value flag with a default.
    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.opt(key).unwrap_or(default)
    }

    /// Whether a boolean flag was present.
    pub fn has(&self, key: &str) -> bool {
        self.flags.contains(key)
    }

    /// Positional arguments, in order.
    pub fn positional(&self) -> &[String] {
        &self.positional
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Args {
        Args::parse(s.iter().map(|x| x.to_string()))
    }

    #[test]
    fn parses_values_flags_and_positionals() {
        let a = args(&[
            "--data",
            "/tmp/x",
            "--version=3",
            "--shard-from-subdir",
            "file.txt",
        ]);
        assert_eq!(a.req("data").unwrap(), "/tmp/x");
        assert_eq!(a.req("version").unwrap(), "3");
        assert!(a.has("shard-from-subdir"));
        assert_eq!(a.positional(), ["file.txt"]);
        assert!(a.req("missing").is_err());
        assert_eq!(a.get_or("shard", "files"), "files");
    }

    #[test]
    fn empty_value_is_treated_as_absent() {
        // `--out=` and `--out ""` must not register a present-but-empty value.
        let a = args(&["--out="]);
        assert!(a.req("out").is_err());
        let b = args(&["--out", ""]);
        assert!(b.req("out").is_err());
    }

    #[test]
    fn known_bool_flag_does_not_swallow_next_token() {
        // A registered boolean flag stays boolean even right before a positional.
        let a = args(&["--shard-from-subdir", "input"]);
        assert!(a.has("shard-from-subdir"));
        assert_eq!(a.positional(), ["input"]);
    }

    #[test]
    fn unknown_flag_before_value_consumes_it() {
        // Non-boolean flags take the following token as their value.
        let a = args(&["--out", "file.json"]);
        assert_eq!(a.opt("out"), Some("file.json"));
    }
}
