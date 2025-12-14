#!/usr/bin/env python3
"""
Run the Olympus Public Audit API server.

Usage:
    python run_api.py [--host HOST] [--port PORT]

Environment variables:
    DATABASE_URL: Postgres connection string (required)
"""

import os
import sys

# Check for required environment variable
if 'DATABASE_URL' not in os.environ:
    print("Error: DATABASE_URL environment variable is required", file=sys.stderr)
    print("Example: export DATABASE_URL='postgresql://user:pass@localhost:5432/olympus'", file=sys.stderr)
    sys.exit(1)

import uvicorn

from api.app import app

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run Olympus Public Audit API")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")

    args = parser.parse_args()

    print(f"Starting Olympus Public Audit API on {args.host}:{args.port}")
    print(f"Database: {os.environ['DATABASE_URL']}")
    print("\nEndpoints:")
    print("  GET  /")
    print("  GET  /health")
    print("  GET  /shards")
    print("  GET  /shards/{shard_id}/header/latest")
    print("  GET  /shards/{shard_id}/proof")
    print("  GET  /ledger/{shard_id}/tail")
    print("\nPress CTRL+C to stop\n")

    uvicorn.run(app, host=args.host, port=args.port)
