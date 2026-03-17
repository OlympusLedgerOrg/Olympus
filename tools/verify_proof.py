#!/usr/bin/env python3
"""
Olympus proof verifier CLI.

Hits the local Olympus FOIA API and pretty-prints the Merkle proof and
verification result.

Usage:
    python tools/verify_proof.py --commit_id 0xc7d4a2f8e1b3095d
    python tools/verify_proof.py --request_id OLY-0041
    python tools/verify_proof.py --doc_hash sha256:4a3f9c2b...

Exit codes:
    0 — verified
    1 — not found
    2 — verification failed
"""

from __future__ import annotations

import httpx
import typer


app = typer.Typer(help="Verify Olympus ledger proofs from the command line.")

BASE_URL = "http://localhost:8000"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _print_proof(data: dict) -> None:
    """Pretty-print a proof response."""
    verified = data.get("verified", False)
    colour = GREEN if verified else RED
    status_label = "✔ VERIFIED" if verified else "✘ NOT VERIFIED"
    typer.echo(f"\n{colour}{BOLD}{status_label}{RESET}\n")

    commit = data.get("commit")
    if commit:
        typer.echo(f"  Commit ID   : {commit.get('commit_id', 'N/A')}")
        typer.echo(f"  Doc Hash    : {commit.get('doc_hash', 'N/A')}")
        typer.echo(f"  Shard       : {commit.get('shard_id', 'N/A')}")
        typer.echo(f"  Epoch       : {commit.get('epoch', 'N/A')}")
        typer.echo(f"  Merkle Root : {commit.get('merkle_root', 'N/A')}")

    merkle_proof = data.get("merkle_proof")
    if merkle_proof:
        typer.echo(f"\n  {BOLD}Merkle Proof Path{RESET} ({len(merkle_proof)} steps):")
        for i, step in enumerate(merkle_proof):
            typer.echo(f"    [{i}] {step.get('direction', '?'):5s}  {step.get('hash', 'N/A')}")
    else:
        typer.echo("\n  Merkle Proof : (empty tree or single node)")

    zk = data.get("zk_proof")
    if zk:
        typer.echo(f"\n  {BOLD}ZK Proof{RESET} [{zk.get('protocol', '?')} / {zk.get('curve', '?')}]:")
        typer.echo(f"    Verified    : {zk.get('verified', '?')}")
        typer.echo(f"    Note        : {zk.get('note', '')}")

    typer.echo("")


@app.command()
def verify(
    commit_id: str | None = typer.Option(None, "--commit_id", help="Hex commit identifier."),
    request_id: str | None = typer.Option(None, "--request_id", help="Display ID, e.g. OLY-0041."),
    doc_hash: str | None = typer.Option(None, "--doc_hash", help="SHA-256 hex (optionally sha256:-prefixed)."),
    base_url: str = typer.Option(BASE_URL, "--url", help="Base URL of the Olympus API."),
) -> None:
    """Verify an Olympus ledger proof.

    At least one of --commit_id, --request_id, or --doc_hash must be supplied.
    Exit codes: 0 = verified, 1 = not found, 2 = verification failed.
    """
    if not any([commit_id, request_id, doc_hash]):
        typer.echo(
            f"{RED}Error: provide at least one of --commit_id, --request_id, or --doc_hash.{RESET}",
            err=True,
        )
        raise typer.Exit(code=1)

    client = httpx.Client(base_url=base_url, timeout=10.0)

    try:
        if request_id:
            # Fetch request and extract commit_hash, then verify by doc_hash
            resp = client.get(f"/requests/{request_id}")
            if resp.status_code == 404:
                typer.echo(f"{RED}Request {request_id!r} not found.{RESET}", err=True)
                raise typer.Exit(code=1)
            resp.raise_for_status()
            req_data = resp.json()
            lookup_hash = req_data.get("commit_hash")
            if not lookup_hash:
                typer.echo(f"{RED}Request has no commit_hash.{RESET}", err=True)
                raise typer.Exit(code=2)
            verify_resp = client.post("/doc/verify", json={"doc_hash": lookup_hash})

        elif commit_id:
            verify_resp = client.post("/doc/verify", json={"commit_id": commit_id})

        else:
            # Strip optional sha256: prefix
            raw_hash = doc_hash.removeprefix("sha256:") if doc_hash else ""
            verify_resp = client.post("/doc/verify", json={"doc_hash": raw_hash})

        if verify_resp.status_code == 404:
            typer.echo(f"{RED}Not found.{RESET}", err=True)
            raise typer.Exit(code=1)
        verify_resp.raise_for_status()
        data = verify_resp.json()

    except httpx.ConnectError:
        typer.echo(
            f"{RED}Cannot connect to {base_url!r}. Is the API running?{RESET}", err=True
        )
        raise typer.Exit(code=1)
    except httpx.HTTPStatusError as exc:
        typer.echo(f"{RED}API error: {exc.response.status_code}{RESET}", err=True)
        raise typer.Exit(code=2)

    _print_proof(data)

    if not data.get("verified", False):
        raise typer.Exit(code=2)

    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
