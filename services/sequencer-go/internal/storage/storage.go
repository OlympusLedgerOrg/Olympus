// Package storage provides PostgreSQL persistence for the sequencer
package storage

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// nodeRehashGate is the BLAKE3 domain-separated gate value required
// before any ON CONFLICT DO UPDATE on smt_nodes. Must match
// _NODE_REHASH_GATE in storage/postgres.py.
const nodeRehashGate = "003e82539d8e3b45c15db1f909bf8ea9fc1eb26629bf483f52eba91c8fc48f1b"

// PostgresStorage handles persistent storage for SMT nodes and roots
type PostgresStorage struct {
	db *sql.DB
}

// NewPostgresStorage creates a new Postgres storage instance
func NewPostgresStorage(ctx context.Context, connStr string) (*PostgresStorage, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PostgresStorage{db: db}, nil
}

// Close closes the database connection
func (s *PostgresStorage) Close() error {
	return s.db.Close()
}

// StoreRoot persists a new root hash to the database
func (s *PostgresStorage) StoreRoot(ctx context.Context, root []byte, treeSize uint64, signature []byte) error {
	query := `
		INSERT INTO cdhs_smf_roots (root_hash, tree_size, signature, created_at)
		VALUES ($1, $2, $3, NOW())
	`

	_, err := s.db.ExecContext(ctx, query, root, treeSize, signature)
	if err != nil {
		return fmt.Errorf("failed to store root: %w", err)
	}

	return nil
}

// StoreNodeDelta persists a single SMT node delta to the database within its own transaction.
// For batch operations, prefer StoreLeafAndDeltas which wraps all deltas + root in one transaction.
func (s *PostgresStorage) StoreNodeDelta(ctx context.Context, path []byte, level uint32, hash []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := setRehashGate(ctx, tx); err != nil {
		return err
	}

	if err := storeNodeDeltaInTx(ctx, tx, path, level, hash); err != nil {
		return err
	}

	return tx.Commit()
}

// storeNodeDeltaInTx persists a single SMT node delta within an existing transaction.
// Precondition: the caller must have called setRehashGate() on the transaction first;
// otherwise the ON CONFLICT DO UPDATE will be rejected by the Postgres trigger.
func storeNodeDeltaInTx(ctx context.Context, tx *sql.Tx, path []byte, level uint32, hash []byte) error {
	query := `
		INSERT INTO cdhs_smf_nodes (path, level, hash, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (path, level)
		DO UPDATE SET hash = EXCLUDED.hash, created_at = NOW()
	`
	if _, err := tx.ExecContext(ctx, query, path, level, hash); err != nil {
		return fmt.Errorf("store node delta: %w", err)
	}

	return nil
}

// setRehashGate sets the session variable required for ON CONFLICT DO UPDATE.
// Must be called once per transaction before any storeNodeDeltaInTx calls.
func setRehashGate(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx,
		"SET LOCAL olympus.allow_node_rehash = $1", nodeRehashGate,
	); err != nil {
		return fmt.Errorf("set rehash gate: %w", err)
	}
	return nil
}

// LeafEntry represents a single stored leaf for startup replay.
type LeafEntry struct {
	Key       []byte
	ValueHash []byte
}

// SmtDelta represents a single SMT node delta for batch storage.
type SmtDelta struct {
	Path  []byte
	Level uint32
	Hash  []byte
}

// StoreLeafAndDeltas atomically persists all node deltas, the leaf entry, and
// the new root within a single database transaction. This prevents partial SMT
// state on crash (C-3 in security audit).
func (s *PostgresStorage) StoreLeafAndDeltas(ctx context.Context, deltas []SmtDelta, root []byte, treeSize uint64, signature []byte, leaf LeafEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Set the rehash gate once for the entire transaction (not per-delta)
	if err := setRehashGate(ctx, tx); err != nil {
		return err
	}

	// Persist all node deltas within the same transaction
	for _, delta := range deltas {
		if err := storeNodeDeltaInTx(ctx, tx, delta.Path, delta.Level, delta.Hash); err != nil {
			return fmt.Errorf("store delta at level %d: %w", delta.Level, err)
		}
	}

	// Persist the leaf entry for startup replay
	leafQuery := `
		INSERT INTO cdhs_smf_leaves (key, value_hash, created_at)
		VALUES ($1, $2, NOW())
	`
	if _, err := tx.ExecContext(ctx, leafQuery, leaf.Key, leaf.ValueHash); err != nil {
		return fmt.Errorf("store leaf: %w", err)
	}

	// Persist the signed root within the same transaction
	rootQuery := `
		INSERT INTO cdhs_smf_roots (root_hash, tree_size, signature, created_at)
		VALUES ($1, $2, $3, NOW())
	`
	if _, err := tx.ExecContext(ctx, rootQuery, root, treeSize, signature); err != nil {
		return fmt.Errorf("store root: %w", err)
	}

	return tx.Commit()
}

// BatchLeaf groups a leaf entry with its SMT node deltas for atomic batch storage.
type BatchLeaf struct {
	Leaf   LeafEntry
	Deltas []SmtDelta
}

// StoreLeafAndDeltasBatch atomically persists all leaves, their node deltas,
// and the final root in a single transaction. All leaves share the post-batch
// root — only one root row is written regardless of batch size.
func (s *PostgresStorage) StoreLeafAndDeltasBatch(
	ctx context.Context,
	batch []BatchLeaf,
	root []byte,
	treeSize uint64,
	signature []byte,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := setRehashGate(ctx, tx); err != nil {
		return err
	}

	for _, bl := range batch {
		for _, delta := range bl.Deltas {
			if err := storeNodeDeltaInTx(ctx, tx, delta.Path, delta.Level, delta.Hash); err != nil {
				return fmt.Errorf("store delta at level %d: %w", delta.Level, err)
			}
		}
		leafQuery := `INSERT INTO cdhs_smf_leaves (key, value_hash, created_at) VALUES ($1, $2, NOW())`
		if _, err := tx.ExecContext(ctx, leafQuery, bl.Leaf.Key, bl.Leaf.ValueHash); err != nil {
			return fmt.Errorf("store leaf: %w", err)
		}
	}

	rootQuery := `INSERT INTO cdhs_smf_roots (root_hash, tree_size, signature, created_at) VALUES ($1, $2, $3, NOW())`
	if _, err := tx.ExecContext(ctx, rootQuery, root, treeSize, signature); err != nil {
		return fmt.Errorf("store root: %w", err)
	}

	return tx.Commit()
}

// GetLatestRoot retrieves the most recent root hash by tree size.
//
// Ordering by `tree_size DESC` (not `created_at`) is intentional: tree size
// is a monotonic, append-only counter assigned by the sequencer, so it is
// the authoritative notion of "latest" even if `created_at` clocks jump or
// rows are inserted out of order during replay/migration. Ties on tree_size
// are broken by `id DESC` so the most recently inserted row at that size
// wins (which can happen during a re-sign with new context).
func (s *PostgresStorage) GetLatestRoot(ctx context.Context) ([]byte, uint64, error) {
	query := `
		SELECT root_hash, tree_size
		FROM cdhs_smf_roots
		ORDER BY tree_size DESC, id DESC
		LIMIT 1
	`

	var root []byte
	var treeSize uint64

	err := s.db.QueryRowContext(ctx, query).Scan(&root, &treeSize)
	if err != nil {
		if err == sql.ErrNoRows {
			// Empty tree - return zeros
			return make([]byte, 32), 0, nil
		}
		return nil, 0, fmt.Errorf("failed to get latest root: %w", err)
	}

	return root, treeSize, nil
}

// InitSchema creates the necessary database tables
func (s *PostgresStorage) InitSchema(ctx context.Context) error {
	schema := `
		-- Note: schema change from TIMESTAMP → TIMESTAMPTZ.
		-- Existing dev databases require: ALTER TABLE cdhs_smf_roots ALTER COLUMN created_at TYPE TIMESTAMPTZ;
		--
		-- Schema invariants (enforced at the DB layer so a buggy or compromised
		-- sequencer cannot persist a half-formed signed root):
		--   * signature is NOT NULL  — every signed-root row must carry a real
		--     Ed25519 signature; a NULL signature would silently make the row
		--     unverifiable.
		--   * signature is UNIQUE    — Ed25519 signatures over distinct
		--     (root, tree_size, context) inputs are overwhelmingly unique;
		--     a duplicate signature indicates either a bug, a key reuse on the
		--     same input, or replay, all of which we want to surface as a
		--     constraint violation rather than persist silently.
		--   * length CHECK on signature (64 B) and root_hash (32 B) blocks
		--     truncated/oversized values from ever landing in the table.
		CREATE TABLE IF NOT EXISTS cdhs_smf_roots (
			id SERIAL PRIMARY KEY,
			root_hash BYTEA NOT NULL,
			tree_size BIGINT NOT NULL,
			signature BYTEA NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_cdhs_smf_roots_tree_size UNIQUE (tree_size),
			CONSTRAINT cdhs_smf_roots_signature_unique UNIQUE (signature),
			CONSTRAINT cdhs_smf_roots_signature_len CHECK (octet_length(signature) = 64),
			CONSTRAINT cdhs_smf_roots_root_hash_len CHECK (octet_length(root_hash) = 32),
			CONSTRAINT cdhs_smf_roots_tree_size_nonneg CHECK (tree_size >= 0)
		);

		CREATE INDEX IF NOT EXISTS idx_cdhs_smf_roots_tree_size
			ON cdhs_smf_roots(tree_size DESC);

		CREATE INDEX IF NOT EXISTS idx_cdhs_smf_roots_created_at
			ON cdhs_smf_roots(created_at DESC);

		-- Note: schema change from TIMESTAMP → TIMESTAMPTZ.
		-- Existing dev databases require: ALTER TABLE cdhs_smf_nodes ALTER COLUMN created_at TYPE TIMESTAMPTZ;
		CREATE TABLE IF NOT EXISTS cdhs_smf_nodes (
			path BYTEA NOT NULL,
			level INTEGER NOT NULL,
			hash BYTEA NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (path, level)
		);

		CREATE INDEX IF NOT EXISTS idx_cdhs_smf_nodes_level
			ON cdhs_smf_nodes(level);

		-- Leaf entries in insertion order, used for startup replay.
		CREATE TABLE IF NOT EXISTS cdhs_smf_leaves (
			id SERIAL PRIMARY KEY,
			key BYTEA NOT NULL,
			value_hash BYTEA NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`

	_, err := s.db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	return nil
}

// SignedRoot holds a root hash, its tree size, and the Ed25519 signature.
type SignedRoot struct {
	RootHash  []byte
	TreeSize  uint64
	Signature []byte
}

// GetRootByTreeSize retrieves the signed root at the given tree size.
// Returns sql.ErrNoRows if no root exists at that size.
func (s *PostgresStorage) GetRootByTreeSize(ctx context.Context, treeSize uint64) (*SignedRoot, error) {
	query := `
		SELECT root_hash, tree_size, signature
		FROM cdhs_smf_roots
		WHERE tree_size = $1
		ORDER BY created_at DESC
		LIMIT 1
	`

	var sr SignedRoot
	err := s.db.QueryRowContext(ctx, query, treeSize).Scan(&sr.RootHash, &sr.TreeSize, &sr.Signature)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// GetLeaves retrieves all leaf entries in insertion order (oldest first) for
// startup replay. Corresponds to the cdhs_smf_leaves table.
func (s *PostgresStorage) GetLeaves(ctx context.Context) ([]LeafEntry, error) {
	query := `
		SELECT key, value_hash
		FROM cdhs_smf_leaves
		ORDER BY id ASC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query leaves: %w", err)
	}
	defer rows.Close()

	var leaves []LeafEntry
	for rows.Next() {
		var e LeafEntry
		if err := rows.Scan(&e.Key, &e.ValueHash); err != nil {
			return nil, fmt.Errorf("scan leaf row: %w", err)
		}
		leaves = append(leaves, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate leaf rows: %w", err)
	}

	return leaves, nil
}
