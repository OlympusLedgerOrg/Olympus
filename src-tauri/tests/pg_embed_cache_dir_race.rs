// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Concurrent first-use of the shared pg_embed binary cache.
//!
//! `PgEmbed::new` walks the shared cache tree under the user cache directory
//! through `pg_access::ensure_private_directory`, creating any missing
//! ancestor. When several pg_embed processes reach a *cold* cache at once —
//! which is exactly what CI does, since `cargo nextest` runs the
//! embedded-Postgres test binaries concurrently on a runner that always starts
//! with an empty cache — they all walk the same missing ancestors. Exactly one
//! wins each `create`; the losers get `EEXIST` for a directory that now exists
//! and satisfies every privacy check.
//!
//! Losing that race must not be an error. An *ensure* function's postcondition
//! is "the directory exists and is private", and a loser observes exactly that.
//! Treating `EEXIST` as fatal surfaced as
//! `DirCreationError("File exists (os error 17)")` aborting embedded startup.
//!
//! There is a second, Windows-only way to lose the same race, and this test
//! covers it too. Hardening a level calls `SetSecurityInfo`, which propagates
//! the inheritable ACE down the tree; a descendant another walk protected in
//! that same instant can be written back auto-inherited, clearing
//! `SE_DACL_PROTECTED`. The walk that had just set it reads back
//! `control = 0x8404` and reports `InvalidPgPackage` for a directory that is
//! still current-user-only. `ensure_private_directory` re-asserts the DACL until
//! it holds, which is why this test races the whole walk repeatedly rather than
//! once — see `ROUNDS`.
//!
//! This test lives here rather than in `pg-embed-local/src/pg_access.rs`
//! because the vendored crate is excluded from the workspace (`cargo test -p
//! pg-embed` refuses: "requires dev-dependencies and is not a member of the
//! workspace") and CI never runs its test suite. `ensure_private_directory` is
//! `pub`, so the guard belongs in a binary CI does run. It is deliberately
//! DB-free and sub-second: no cluster, no port, no `pg_embed` harness — so it
//! stays out of `scripts/embedded-postgres-tests.sh` and runs in the ordinary
//! parallel job.
//!
//! On forcing the race: the `AlreadyExists` branch needs the directory to
//! appear between `symlink_metadata` and `create`, a window only a real
//! concurrent walk opens. Making it deterministic would mean adding a test-only
//! injection seam to a security-sensitive filesystem walk — a permanent hook in
//! the hardening path to pin one branch — which costs more than it buys. The
//! barrier below is the honest alternative: 16 racers hit the window reliably
//! (4 of 16 failed against the unfixed code), and the walk's postcondition is
//! asserted afterwards, so a regression that skipped validation on that branch
//! would surface as a non-private tree.

use pg_embed::pg_access::ensure_private_directory;
use std::sync::{Arc, Barrier};

/// Enough racers that the create window is hit reliably on any runner. Real
/// contention is bounded by the number of concurrent pg_embed test binaries.
const RACERS: usize = 16;

/// Fresh cold-cache races per run. One round hits the window often but not
/// every time — the DACL-clobber this guards against reproduced in roughly one
/// run in eight — so a single round lets a regression through most of the time.
/// Rounds are independent (each gets its own temp tree) and the whole test still
/// finishes in well under a second.
const ROUNDS: usize = 24;

#[test]
fn concurrent_first_creation_of_the_cache_tree_never_fails() {
    for _ in 0..ROUNDS {
        one_cold_cache_race();
    }
}

fn one_cold_cache_race() {
    let temp = tempfile::tempdir().expect("temp dir");
    // Mirrors the real shape: `{cache}/pg-embed/{os}/{arch}/{version}`, so each
    // racer has several consecutive chances to lose a create.
    let target = temp.path().join("pg-embed/linux/amd64/15.16.0");
    let barrier = Arc::new(Barrier::new(RACERS));

    let racers: Vec<_> = (0..RACERS)
        .map(|_| {
            let target = target.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                // Release every racer into the walk at the same instant.
                barrier.wait();
                ensure_private_directory(&target).map(|_guard| ())
            })
        })
        .collect();

    let failures: Vec<_> = racers
        .into_iter()
        .map(|racer| racer.join().expect("racer thread did not panic"))
        .filter_map(Result::err)
        .collect();

    assert!(
        failures.is_empty(),
        "{} of {RACERS} concurrent walks failed; losing a create race must be a \
         no-op, not an error: {failures:?}",
        failures.len()
    );
    assert!(
        target.is_dir(),
        "the contended directory must exist once every racer has returned"
    );

    // The racers that lost took the `AlreadyExists` branch, so assert the
    // postcondition they are responsible for upholding: every level of the
    // contended tree is private. This is the only place that branch is
    // exercised — see the module note on why it is not forced deterministically.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let mut level = target.as_path();
        loop {
            let metadata = std::fs::symlink_metadata(level).expect("contended level metadata");
            assert!(metadata.is_dir(), "{} must be a directory", level.display());
            assert_eq!(
                metadata.permissions().mode() & 0o077,
                0,
                "{} must not be group/world accessible after a contended walk",
                level.display()
            );
            assert_eq!(
                metadata.uid(),
                unsafe { libc::geteuid() },
                "{} must be owned by this account",
                level.display()
            );
            match level.parent() {
                Some(parent) if parent.starts_with(temp.path()) && parent != temp.path() => {
                    level = parent;
                }
                _ => break,
            }
        }
    }
}

/// The adjacent, uncontended contract: a directory that is simply *already
/// there* when the walk reaches it.
///
/// Note this exercises the pre-existing (`Ok`) branch, **not** the
/// `AlreadyExists` branch changed by this commit — the target exists before
/// the call, so `symlink_metadata` succeeds and no `create` is attempted. It is
/// here because the fix makes losers converge on this same
/// already-there-when-I-looked situation, so the guarantee for it is worth
/// pinning; the contended branch itself is covered by the assertions in the
/// race test above.
///
/// For a directory owned by this account the contract is repair, not refusal:
/// `ensure_private_directory` hardens it in place and returns success. Refusal
/// is reserved for what it cannot make safe — a symlink, or an entry owned by
/// another account — which the walk rejects via `O_NOFOLLOW` and its owner
/// check.
#[test]
fn a_pre_existing_over_permissive_directory_is_hardened_before_use() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("temp dir");
        let target = temp.path().join("cache");
        std::fs::create_dir(&target).expect("create target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o777))
            .expect("widen permissions");

        // The target is hardened in place when it is owned by this account, so
        // assert the outcome is a private directory rather than an error.
        ensure_private_directory(&target).expect("owned target is hardened in place");
        let mode = std::fs::metadata(&target)
            .expect("target metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "target must not stay group/world accessible (mode {mode:o})"
        );
    }
}
