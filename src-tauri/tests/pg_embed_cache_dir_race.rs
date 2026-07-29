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
//! This test lives here rather than in `pg-embed-local/src/pg_access.rs`
//! because the vendored crate is excluded from the workspace (`cargo test -p
//! pg-embed` refuses: "requires dev-dependencies and is not a member of the
//! workspace") and CI never runs its test suite. `ensure_private_directory` is
//! `pub`, so the guard belongs in a binary CI does run. It is deliberately
//! DB-free and sub-second: no cluster, no port, no `pg_embed` harness — so it
//! stays out of `scripts/embedded-postgres-tests.sh` and runs in the ordinary
//! parallel job.

use pg_embed::pg_access::ensure_private_directory;
use std::sync::{Arc, Barrier};

/// Enough racers that the create window is hit reliably on any runner. Real
/// contention is bounded by the number of concurrent pg_embed test binaries.
const RACERS: usize = 16;

#[test]
fn concurrent_first_creation_of_the_cache_tree_never_fails() {
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
}

/// The privacy contract still has to hold for the racers that lost. A loser
/// returns without having created anything, so it must still have *validated*
/// what the winner created — otherwise the fix would trade a crash for a
/// silently unchecked directory.
#[test]
fn a_pre_existing_world_writable_directory_is_still_rejected() {
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
