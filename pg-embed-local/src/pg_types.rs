use std::cell::Cell;

/// Synchronous pg_ctl command type retained for pg-embed 1.0 source
/// compatibility.
///
/// Olympus lifecycle code never executes this type; exact-process shutdown is
/// available through [`crate::postgres::PgEmbed::stop_db_sync`].
#[deprecated(note = "use PgEmbed::stop_db_sync for retained-authority shutdown")]
pub type PgCommandSync = Box<Cell<std::process::Command>>;
