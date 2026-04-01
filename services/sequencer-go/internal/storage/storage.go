// Package storage provides PostgreSQL persistence for the sequencer
package storage

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

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

// StoreNodeDelta persists SMT node deltas to the database
func (s *PostgresStorage) StoreNodeDelta(ctx context.Context, path []byte, level uint32, hash []byte) error {
	query := `
		INSERT INTO cdhs_smf_nodes (path, level, hash, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (path, level) DO UPDATE SET hash = EXCLUDED.hash, created_at = NOW()
	`

	_, err := s.db.ExecContext(ctx, query, path, level, hash)
	if err != nil {
		return fmt.Errorf("failed to store node delta: %w", err)
	}

	return nil
}

// GetLatestRoot retrieves the most recent root hash
func (s *PostgresStorage) GetLatestRoot(ctx context.Context) ([]byte, uint64, error) {
	query := `
		SELECT root_hash, tree_size
		FROM cdhs_smf_roots
		ORDER BY created_at DESC
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
		CREATE TABLE IF NOT EXISTS cdhs_smf_roots (
			id SERIAL PRIMARY KEY,
			root_hash BYTEA NOT NULL,
			tree_size BIGINT NOT NULL,
			signature BYTEA,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

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
	`

	_, err := s.db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	return nil
}
