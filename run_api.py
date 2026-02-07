#!/usr/bin/env python3
"""
Run the Olympus Public Audit API server.

Usage:
    python run_api.py [--host HOST] [--port PORT]

Environment variables:
    DATABASE_URL: Postgres connection string (recommended, uses default if not set)
"""

import os

import uvicorn

from api.app import app


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run Olympus Public Audit API")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")

    args = parser.parse_args()

    # Get database URL for display (uses default if not set)
    DEFAULT_DATABASE_URL = "postgresql://olympus:olympus@localhost:5432/olympus"
    database_url = os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)

    print(f"Starting Olympus Public Audit API on {args.host}:{args.port}")
    print(f"Database: {database_url}")
    if "DATABASE_URL" not in os.environ:
        print("  (using default; set DATABASE_URL to configure)")
    print("\nEndpoints:")
    print("  GET  /         - API info")
    print("  GET  /health   - Health check (always works)")
    print("  GET  /shards   - List shards (requires DB)")
    print("  GET  /shards/{shard_id}/header/latest  (requires DB)")
    print("  GET  /shards/{shard_id}/proof          (requires DB)")
    print("  GET  /ledger/{shard_id}/tail           (requires DB)")
    print("\nNote: DB endpoints return 503 if database is not available.")
    print("Press CTRL+C to stop\n")

    uvicorn.run(app, host=args.host, port=args.port)
