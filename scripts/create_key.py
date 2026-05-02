#!/usr/bin/env python3
"""
Generate an Olympus API key and print the env-var JSON entry.

Usage:
    python scripts/create_key.py --name alice --scopes ingest,verify --expires 2027-01-01
    python scripts/create_key.py --name alice --patch-env .env
    python scripts/create_key.py --name alice --reload http://localhost:8090 --admin-key <key>
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


_DOMAIN_PREFIX = b"OLY:LEGACY-BYTES:V1"

try:
    import blake3 as _blake3

    def _hash(raw: bytes) -> str:
        return _blake3.blake3(_DOMAIN_PREFIX + raw).digest().hex()

except ImportError:
    print("ERROR: blake3 package not installed. Run: pip install blake3", file=sys.stderr)
    sys.exit(1)


VALID_SCOPES = {"read", "write", "ingest", "commit", "verify", "admin"}
DEFAULT_SCOPES = ["ingest", "verify"]


def _parse_scopes(raw: str) -> list[str]:
    scopes = [s.strip() for s in raw.split(",") if s.strip()]
    unknown = set(scopes) - VALID_SCOPES
    if unknown:
        print(f"ERROR: unknown scopes: {', '.join(sorted(unknown))}", file=sys.stderr)
        print(f"       valid: {', '.join(sorted(VALID_SCOPES))}", file=sys.stderr)
        sys.exit(1)
    return scopes


def _parse_expires(raw: str) -> str:
    try:
        dt = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        print(f"ERROR: --expires must be YYYY-MM-DD, got: {raw!r}", file=sys.stderr)
        raise SystemExit(1)


def generate(name: str, scopes: list[str], expires: str) -> tuple[str, dict]:
    raw_key = secrets.token_hex(32)  # 256 bits
    key_hash = _hash(raw_key.encode())
    entry = {
        "key_hash": key_hash,
        "key_id": name,
        "scopes": scopes,
        "expires_at": expires,
    }
    return raw_key, entry


def patch_env(env_path: str, entry: dict) -> None:
    if not os.path.exists(env_path):
        print(f"ERROR: .env file not found: {env_path}", file=sys.stderr)
        sys.exit(1)

    with open(env_path) as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if line.startswith("OLYMPUS_API_KEYS_JSON="):
            existing_json = line.split("=", 1)[1].strip().strip("'\"")
            try:
                existing = json.loads(existing_json) if existing_json else []
            except json.JSONDecodeError:
                existing = []
            existing.append(entry)
            lines[i] = f"OLYMPUS_API_KEYS_JSON={json.dumps(existing)}\n"
            with open(env_path, "w") as f:
                f.writelines(lines)
            print(f"[ok] Patched {env_path}")
            return

    # Key not found — append
    with open(env_path, "a") as f:
        f.write(f"\nOLYMPUS_API_KEYS_JSON={json.dumps([entry])}\n")
    print(f"[ok] Appended OLYMPUS_API_KEYS_JSON to {env_path}")


def reload_via_api(base_url: str, admin_key: str) -> None:
    url = f"{base_url.rstrip('/')}/key/admin/reload-keys"
    req = urllib.request.Request(
        url,
        method="POST",
        headers={"X-Admin-Key": admin_key, "Content-Length": "0"},
        data=b"",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            print(f"[ok] Keys reloaded — {body.get('key_count', '?')} active key(s)")
    except urllib.error.HTTPError as e:
        print(f"ERROR: reload failed HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
    except Exception as e:
        print(f"ERROR: reload request failed: {e}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an Olympus API key")
    parser.add_argument(
        "--name", required=True, help="Human-readable key ID (e.g. alice, org-acme)"
    )
    parser.add_argument(
        "--scopes",
        default=",".join(DEFAULT_SCOPES),
        help=f"Comma-separated scopes. Default: {','.join(DEFAULT_SCOPES)}. Valid: {','.join(sorted(VALID_SCOPES))}",
    )
    parser.add_argument(
        "--expires", default="2099-01-01", help="Expiry date YYYY-MM-DD (default: 2099-01-01)"
    )
    parser.add_argument(
        "--patch-env", metavar="ENV_FILE", help="Patch an .env file with the new key entry"
    )
    parser.add_argument(
        "--reload", metavar="BASE_URL", help="Call /key/admin/reload-keys after patching"
    )
    parser.add_argument(
        "--admin-key", metavar="KEY", help="OLYMPUS_ADMIN_KEY value (required with --reload)"
    )
    args = parser.parse_args()

    scopes = _parse_scopes(args.scopes)
    expires = _parse_expires(args.expires)

    raw_key, entry = generate(args.name, scopes, expires)

    print()
    print("=" * 60)
    print(f"  KEY ID  : {entry['key_id']}")
    print(f"  SCOPES  : {', '.join(entry['scopes'])}")
    print(f"  EXPIRES : {entry['expires_at']}")
    print("=" * 60)
    print()
    print("RAW KEY (give this to the user — store it now, it won't be shown again):")
    print()
    print(f"  {raw_key}")
    print()
    print("JSON ENTRY (add this to OLYMPUS_API_KEYS_JSON in your .env):")
    print()
    print(f"  {json.dumps(entry)}")
    print()

    if args.patch_env:
        patch_env(args.patch_env, entry)

    if args.reload:
        if not args.admin_key:
            print("ERROR: --admin-key is required with --reload", file=sys.stderr)
            sys.exit(1)
        reload_via_api(args.reload, args.admin_key)

    print()


if __name__ == "__main__":
    main()
