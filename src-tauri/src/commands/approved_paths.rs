// SPDX-License-Identifier: Apache-2.0

//! Session allowlist for paths the Tauri IPC layer may read (audit E-P2-1).
//!
//! `hash_file_for_manifest`, `describe_by_path`, `redact_by_path` and
//! `read_file_for_render` each take a path string from the renderer. The
//! renderer is the app's own trust domain, but a compromised webview (XSS via
//! document metadata, a malicious devtools extension) should not turn those
//! commands into an arbitrary-file-read gadget that exfiltrates a private key
//! or a document outside the ledger.
//!
//! A path is admitted only after the *native* side observed the user choose it:
//! a dialog-picker callback or an OS drag-drop event. There is deliberately no
//! `approve` IPC command, so the renderer cannot expand its own allowlist.
//!
//! Approve and check both canonicalise, so `..`, a relative path, or a symlink
//! whose target moved cannot match an approved entry unless it resolves to the
//! same file the operator picked.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Bounded so a long session (or an operator dropping a directory of thousands
/// of files) cannot grow the allowlist without limit. Entries are evicted
/// oldest-first; re-picking a file re-admits it.
const MAX_APPROVED_PATHS: usize = 256;

#[derive(Default)]
pub(crate) struct ApprovedPaths {
    inner: Mutex<ApprovedPathsInner>,
}

#[derive(Default)]
struct ApprovedPathsInner {
    order: VecDeque<PathBuf>,
    set: HashSet<PathBuf>,
}

impl ApprovedPaths {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record a path the native layer just received from a user action.
    pub(crate) fn approve(&self, path: impl AsRef<Path>) {
        let Ok(canonical) = std::fs::canonicalize(path.as_ref()) else {
            // A path that does not resolve now cannot be read later either.
            return;
        };
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if !inner.set.insert(canonical.clone()) {
            return;
        }
        inner.order.push_back(canonical);
        while inner.order.len() > MAX_APPROVED_PATHS {
            if let Some(evicted) = inner.order.pop_front() {
                inner.set.remove(&evicted);
            }
        }
    }

    /// Canonicalise `path` and return it only if the user approved it.
    pub(crate) fn require(&self, path: &str) -> Result<PathBuf, String> {
        let canonical = std::fs::canonicalize(path).map_err(|e| format!("{path}: {e}"))?;
        let approved = self
            .inner
            .lock()
            .map(|inner| inner.set.contains(&canonical))
            .unwrap_or(false);
        if approved {
            Ok(canonical)
        } else {
            Err(format!(
                "{path} was not chosen through a native picker or drop; refusing to read it"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approved_file(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, b"fixture").unwrap();
        path
    }

    #[test]
    fn approves_only_paths_the_native_layer_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let allowed = approved_file(&dir, "allowed.pdf");
        let denied = approved_file(&dir, "denied.pdf");

        let registry = ApprovedPaths::new();
        registry.approve(&allowed);

        assert_eq!(
            registry.require(allowed.to_str().unwrap()).unwrap(),
            std::fs::canonicalize(&allowed).unwrap()
        );
        let error = registry.require(denied.to_str().unwrap()).unwrap_err();
        assert!(error.contains("native picker or drop"), "{error}");
    }

    #[test]
    fn a_relative_or_dotdot_alias_resolves_to_the_approved_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = approved_file(&dir, "document.pdf");
        let nested = dir.path().join("sub");
        std::fs::create_dir(&nested).unwrap();

        let registry = ApprovedPaths::new();
        registry.approve(&file);

        // Same inode through a different spelling: allowed.
        let alias = nested.join("..").join("document.pdf");
        assert!(registry.require(alias.to_str().unwrap()).is_ok());

        // A path that does not resolve is an error, not an implicit deny that
        // later matches something else.
        assert!(registry
            .require(dir.path().join("missing.pdf").to_str().unwrap())
            .is_err());
    }

    #[test]
    fn the_allowlist_is_bounded_and_evicts_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let registry = ApprovedPaths::new();
        let first = approved_file(&dir, "first.pdf");
        registry.approve(&first);

        for i in 0..MAX_APPROVED_PATHS {
            registry.approve(approved_file(&dir, &format!("f{i}.pdf")));
        }

        assert!(registry.require(first.to_str().unwrap()).is_err());
        let recent = dir.path().join(format!("f{}.pdf", MAX_APPROVED_PATHS - 1));
        assert!(registry.require(recent.to_str().unwrap()).is_ok());
    }
}
