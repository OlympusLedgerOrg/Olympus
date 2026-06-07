-- Email case-insensitive uniqueness (audit: email case uniqueness).
--
-- Migration 0010 created `ix_users_email` as a UNIQUE index over the raw
-- `email` column, so `Alice@Example.com` and `alice@example.com` could both be
-- registered as distinct accounts — a split-brain where login, recovery, and
-- the duplicate-email guard all keyed off the exact stored casing. Email
-- addresses are treated case-insensitively in practice, so two casings of the
-- same address must collapse to one account.
--
-- The application now normalises every email to trimmed lowercase at all
-- boundaries (register / admin-create / login / reissue / self-delete /
-- recovery — see `api/user_auth`). This index enforces the same invariant at
-- the storage tier as defence in depth and to cover any legacy rows: it is a
-- functional UNIQUE index over `LOWER(email)`, so casings can no longer
-- coexist regardless of how a row was written.
--
-- NOTE: if a pre-existing database already contains two rows whose emails
-- differ only by case, creating this index fails (by design) — the operator
-- must merge/remove the duplicate before upgrading. This is expected for the
-- single-operator desktop deployment where such collisions are not produced by
-- the normalising application code.

DROP INDEX IF EXISTS ix_users_email;

CREATE UNIQUE INDEX ix_users_email_lower ON users (LOWER(email));
