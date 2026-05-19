#!/usr/bin/env python3
"""Generate Ed25519 signing keys for Olympus accounts.

This tool runs locally and never contacts the Olympus API. Register the emitted
public key with ``POST /key/signing``. Keep the private key outside the database.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import nacl.encoding
import nacl.signing


def generate_keypair() -> tuple[str, str]:
    signing_key = nacl.signing.SigningKey.generate()
    private_key = signing_key.encode(nacl.encoding.HexEncoder).decode("ascii")
    public_key = signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode("ascii")
    return private_key, public_key


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an Olympus Ed25519 signing keypair")
    parser.add_argument("--label", default="default", help="Human-readable key label")
    parser.add_argument(
        "--purpose",
        default="dataset",
        choices=["dataset", "witness", "federation", "operator"],
        help="Intended signing-key purpose",
    )
    parser.add_argument(
        "--output-prefix",
        default="",
        help="Optional path prefix; writes <prefix>.priv and <prefix>.pub",
    )
    parser.add_argument("--overwrite", action="store_true", help="Overwrite output files")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()

    private_key, public_key = generate_keypair()

    if args.output_prefix:
        priv_path = Path(f"{args.output_prefix}.priv")
        pub_path = Path(f"{args.output_prefix}.pub")
        if not args.overwrite and (priv_path.exists() or pub_path.exists()):
            print("ERROR: output file exists; pass --overwrite to replace", file=sys.stderr)
            return 1
        priv_path.write_text(private_key + "\n", encoding="ascii")
        # Restrict the private-key file to owner-only.  Without an explicit
        # chmod the file inherits the process umask, which on shared systems
        # can leave it world-readable.  On Windows os.chmod is a near-no-op,
        # but the call is still safe.
        try:
            os.chmod(priv_path, 0o600)
        except OSError:
            # Filesystem doesn't support POSIX modes — surface but don't fail.
            print(
                f"WARNING: could not set 0600 permissions on {priv_path}; "
                "verify the file is not world-readable.",
                file=sys.stderr,
            )
        pub_path.write_text(public_key + "\n", encoding="ascii")

    payload = {
        "label": args.label,
        "purpose": args.purpose,
        "public_key": public_key,
        "private_key": private_key,
        "registration_hint": {
            "endpoint": "POST /key/signing",
            "body": {
                "public_key": public_key,
                "label": args.label,
                "purpose": args.purpose,
                "proof_signature": "<sign signing_key_binding_payload with private_key>",
            },
        },
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print("Ed25519 signing key generated locally.")
        print("Private key (store securely; never send to Olympus):")
        print(private_key)
        print("Public key (register with Olympus):")
        print(public_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
