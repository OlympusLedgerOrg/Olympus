-- unique index on doc_commits.doc_hash (alembic: d4e5f6a7b8c9)

CREATE UNIQUE INDEX IF NOT EXISTS ix_doc_commits_doc_hash_unique ON doc_commits (doc_hash);
