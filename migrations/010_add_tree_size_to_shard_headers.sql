-- Add tree_size column to shard_headers to store Merkle leaf count at commit time

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'shard_headers' AND column_name = 'tree_size'
    ) THEN
        ALTER TABLE shard_headers
            ADD COLUMN tree_size BIGINT NOT NULL DEFAULT 0;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'shard_headers' AND constraint_name = 'shard_headers_tree_size_non_negative'
    ) THEN
        ALTER TABLE shard_headers
            ADD CONSTRAINT shard_headers_tree_size_non_negative CHECK (tree_size >= 0);
    END IF;
END $$;
