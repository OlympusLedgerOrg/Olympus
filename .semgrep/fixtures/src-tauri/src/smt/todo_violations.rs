// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0
//
// Synthetic violations for the `crypto-todo-fixme` rule (../../../../olympus-rules.yml,
// relative to this file's real location under .semgrep/fixtures/). Placed
// under src-tauri/src/smt/ (mirrored inside the fixtures tree) because that
// rule is scoped by `paths.include` to specific crypto-hot-path directories
// -- a fixture outside one of those globs would never be scanned by it at
// all, silently passing regardless of whether the pattern is right. See
// smt_write_violations.rs (two levels up) for the general fixture
// convention.

// TODO: line comment marker
//! TODO: inner doc comment marker
/// TODO: outer doc comment marker
/* TODO: block comment marker */
// FIXME: line comment marker
// XXX: line comment marker

fn ok() {}
