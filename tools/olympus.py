#!/usr/bin/env python3
"""Olympus protocol CLI."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from typing import NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from typing_extensions import Annotated

sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.canonical import canonicalize_document, document_to_bytes
from protocol.federation import FederationRegistry
from protocol.hashes import blake3_hash, hash_bytes

# ---------------------------------------------------------------------------
# Console + global state
# ---------------------------------------------------------------------------

out = Console()
err = Console(stderr=True)


@dataclass
class _State:
    api_url: str = "http://localhost:8000"
    api_key: str = ""
    json_out: bool = False
    quiet: bool = False


_S = _State()

# ---------------------------------------------------------------------------
# App + sub-apps
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="olympus",
    help="Olympus protocol CLI",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
)
shard_app = typer.Typer(help="Shard inspection", no_args_is_help=True)
node_app = typer.Typer(help="Node management", no_args_is_help=True)
fed_app = typer.Typer(help="Federation tools", no_args_is_help=True)

app.add_typer(shard_app, name="shard")
app.add_typer(node_app, name="node")
app.add_typer(fed_app, name="federation")


@app.callback()
def _global(
    api_url: Annotated[
        str,
        typer.Option(envvar="OLYMPUS_API_URL", help="API base URL", show_default="http://localhost:8000"),
    ] = "http://localhost:8000",
    api_key: Annotated[
        str,
        typer.Option(envvar="OLYMPUS_API_KEY", help="API key"),
    ] = "",
    json_out: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress non-error output"),
    ] = False,
) -> None:
    _S.api_url = api_url.rstrip("/")
    _S.api_key = api_key
    _S.json_out = json_out
    _S.quiet = quiet


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _die(msg: str) -> NoReturn:
    err.print(f"[bold red]error:[/] {msg}")
    raise typer.Exit(1)


def _request(path: str, *, method: str = "GET", payload: dict | None = None) -> dict | list:
    url = f"{_S.api_url}{path}"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if _S.api_key:
        headers["X-API-Key"] = _S.api_key
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        _die(f"HTTP {exc.code} from {url}: {body[:300]}")
    except URLError as exc:
        _die(f"Cannot reach {_S.api_url}: {exc.reason}")
    except json.JSONDecodeError:
        _die(f"Invalid JSON from {url}")


def _blake3_hex(data: bytes) -> str:
    return blake3_hash([data]).hex()


def _validate_url(url: str, name: str = "url") -> str:
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        _die(f"{name} must use http or https")
    if not p.netloc:
        _die(f"{name} must include a hostname")
    return url


def _emit(data: dict | list) -> None:
    out.print_json(json.dumps(data))


def _kv_table() -> Table:
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("k", style="dim")
    t.add_column("v")
    return t


def _reg_path(override: str) -> Path:
    return (
        Path(override)
        if override
        else Path(__file__).resolve().parent.parent / "examples" / "federation_registry.json"
    )


def _unwrap_list(result: dict | list) -> list:
    """Handle both raw-list and {value: [...]} envelope responses."""
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        for key in ("value", "shards", "results", "items"):
            if key in result and isinstance(result[key], list):
                return result[key]
    return []


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@app.command()
def status() -> None:
    """Check the health of the Olympus API."""
    result = _request("/health")
    assert isinstance(result, dict)

    if _S.json_out:
        _emit(result)
        return
    if _S.quiet:
        raise typer.Exit(0 if result.get("status") == "ok" else 1)

    db = result.get("database", "unknown")
    seq = result.get("sequencer", "unknown")
    overall = result.get("status", "unknown")

    t = _kv_table()
    t.add_row("status", f"[{'green' if overall == 'ok' else 'red'}]{overall}[/]")
    t.add_row("version", result.get("version", "—"))
    t.add_row("database", f"[{'green' if db == 'connected' else 'red'}]{db}[/]")
    t.add_row("db check", "[green]ok[/]" if result.get("db_check") else "[red]fail[/]")
    t.add_row("sequencer", f"[{'yellow' if seq == 'disabled' else 'green'}]{seq}[/]")

    out.print(Panel(t, title="[bold]Olympus[/]", border_style="blue"))


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------


@app.command()
def ingest(
    file: Annotated[Path, typer.Argument(help="File to commit", exists=True)],
    namespace: Annotated[str, typer.Option(help="Ledger namespace")] = "default",
    id: Annotated[str, typer.Option("--id", help="Artifact ID (defaults to filename)")] = "",
    source_url: Annotated[str, typer.Option(help="Source URL for the artifact")] = "",
    raw_pdf: Annotated[Optional[Path], typer.Option(help="Raw PDF to anchor alongside")] = None,
    proof: Annotated[bool, typer.Option("--proof", help="Fetch proof bundle after commit")] = False,
    verify: Annotated[bool, typer.Option("--verify", help="Verify the committed hash")] = False,
) -> None:
    """Commit a file to the Olympus ledger."""
    artifact_id = id or file.name
    artifact_hash = _blake3_hex(file.read_bytes())

    payload: dict = {"artifact_hash": artifact_hash, "namespace": namespace, "id": artifact_id}
    if source_url:
        payload["source_url"] = _validate_url(source_url, "source_url")

    raw_pdf_hash: str | None = None
    if raw_pdf:
        raw_pdf_hash = _blake3_hex(raw_pdf.read_bytes())
        payload["raw_pdf_hash"] = raw_pdf_hash

    commit = _request("/ingest/commit", method="POST", payload=payload)
    assert isinstance(commit, dict)
    proof_id = commit.get("proof_id", "")
    if not proof_id:
        _die("API returned no proof_id")

    output: dict = {
        "file": str(file),
        "artifact_hash": artifact_hash,
        "proof_id": proof_id,
        "commit": commit,
    }
    if raw_pdf_hash:
        output["raw_pdf_hash"] = raw_pdf_hash
    if proof:
        output["proof"] = _request(f"/ingest/records/{proof_id}/proof")
    if verify:
        output["verification"] = _request(f"/ingest/records/hash/{artifact_hash}/verify")

    if _S.json_out:
        _emit(output)
        return
    if _S.quiet:
        out.print(proof_id)
        return

    t = _kv_table()
    t.add_row("file", str(file))
    t.add_row("proof id", f"[bold cyan]{proof_id}[/]")
    t.add_row("blake3", artifact_hash)
    if raw_pdf_hash:
        t.add_row("pdf blake3", raw_pdf_hash)
    if source_url:
        t.add_row("source", source_url)
    ledger_hash = commit.get("ledger_entry_hash", "")
    if ledger_hash:
        t.add_row("ledger hash", str(ledger_hash))
    poseidon = commit.get("poseidon_root", "")
    if poseidon:
        t.add_row("poseidon root", str(poseidon))
    if proof:
        t.add_row("proof bundle", "[green]fetched[/]")
    if verify:
        v = output.get("verification")
        valid = isinstance(v, dict) and v.get("merkle_proof_valid", False)
        t.add_row("verified", "[green]yes[/]" if valid else "[red]no[/]")

    out.print(Panel(t, title="[bold green]Ingested[/]", border_style="green"))


# ---------------------------------------------------------------------------
# records  (batch ingest via /ingest/records)
# ---------------------------------------------------------------------------


@app.command()
def records(
    file: Annotated[
        Optional[Path],
        typer.Argument(help="JSON file with records array (or pipe to stdin)"),
    ] = None,
    shard_id: Annotated[str, typer.Option(help="Default shard ID")] = "default",
    record_type: Annotated[str, typer.Option(help="Default record type label")] = "document",
) -> None:
    """Batch-ingest records via [cyan]/ingest/records[/].

    Input: a JSON array of objects with optional keys
    [dim]shard_id, record_type, record_id, version, content[/].
    Pipe raw JSON or pass a file path.
    """
    if file:
        raw = file.read_text(encoding="utf-8-sig")
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        _die("provide a file argument or pipe JSON to stdin")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        _die(f"invalid JSON: {exc}")

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        _die("input must be a JSON array")

    batch = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            _die(f"item {i} is not a JSON object")
        batch.append(
            {
                "shard_id": item.pop("shard_id", shard_id),
                "record_type": item.pop("record_type", record_type),
                "record_id": item.pop("record_id", f"record-{i}"),
                "version": item.pop("version", 1),
                "content": item.get("content", item),
            }
        )

    result = _request("/ingest/records", method="POST", payload={"records": batch})
    assert isinstance(result, dict)

    if _S.json_out:
        _emit(result)
        return

    t = _kv_table()
    t.add_row("batch id", str(result.get("batch_id", "—")))
    t.add_row("ingested", f"[green]{result.get('ingested', 0)}[/]")
    t.add_row("deduplicated", str(result.get("deduplicated", 0)))
    t.add_row("ledger hash", str(result.get("ledger_entry_hash", "—")))
    t.add_row("timestamp", str(result.get("timestamp", "—")))

    out.print(Panel(t, title="[bold green]Records[/]", border_style="green"))


# ---------------------------------------------------------------------------
# proof
# ---------------------------------------------------------------------------


@app.command()
def proof(
    proof_id: Annotated[str, typer.Argument(help="Proof ID returned by ingest")],
) -> None:
    """Fetch a proof bundle by proof ID."""
    result = _request(f"/ingest/records/{proof_id}/proof")
    if _S.json_out:
        _emit(result)
        return
    body = Syntax(json.dumps(result, indent=2), "json", theme="monokai")
    label = proof_id[:20] + "…" if len(proof_id) > 20 else proof_id
    out.print(Panel(body, title=f"[bold]Proof[/] [dim]{label}[/]", border_style="cyan"))


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@app.command()
def verify(
    artifact_hash: Annotated[str, typer.Argument(help="BLAKE3 hex hash to verify")],
) -> None:
    """Verify a committed artifact hash against the ledger."""
    result = _request(f"/ingest/records/hash/{artifact_hash}/verify")
    assert isinstance(result, dict)

    if _S.json_out:
        _emit(result)
        return

    valid = result.get("merkle_proof_valid", False)
    color = "green" if valid else "red"
    t = _kv_table()
    t.add_row("valid", f"[{color}]{'yes' if valid else 'no'}[/]")
    for k, v in result.items():
        if k != "merkle_proof_valid":
            t.add_row(k.replace("_", " "), str(v))

    out.print(Panel(t, title="[bold]Verification[/]", border_style=color))
    if not valid:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# canon
# ---------------------------------------------------------------------------


@app.command()
def canon(
    input_file: Annotated[Path, typer.Argument(help="JSON file to canonicalize", exists=True)],
    output: Annotated[Optional[Path], typer.Option("-o", "--output", help="Output file")] = None,
    hash_only: Annotated[bool, typer.Option("--hash", help="Print BLAKE3 hash only")] = False,
    format: Annotated[str, typer.Option(help="Output format: json | bytes | hex")] = "json",
) -> None:
    """Canonicalize a JSON document (RFC 8785) or emit its BLAKE3 hash."""
    try:
        document = json.loads(input_file.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        _die(f"invalid JSON: {exc}")

    canonical = canonicalize_document(document)
    canonical_bytes = document_to_bytes(canonical)

    if hash_only:
        text = hash_bytes(canonical_bytes).hex()
    elif format == "json":
        text = json.dumps(canonical, indent=2)
    elif format == "bytes":
        text = canonical_bytes.decode()
    else:
        text = canonical_bytes.hex()

    if output:
        output.write_text(text + "\n")
        if not _S.quiet:
            out.print(f"[dim]written → {output}[/]")
    else:
        out.print(text)


# ---------------------------------------------------------------------------
# shard
# ---------------------------------------------------------------------------


@shard_app.callback()
def _shard_root() -> None:
    """Shard inspection."""


@shard_app.command("list")
def shard_list() -> None:
    """List all shards on this node."""
    raw = _request("/shards")
    shards = _unwrap_list(raw)

    if _S.json_out:
        _emit(shards)
        return
    if not shards:
        out.print("[dim]No shards found.[/]")
        return

    t = Table(box=box.ROUNDED, header_style="bold cyan", show_lines=False)
    t.add_column("Shard ID")
    t.add_column("Seq", justify="right")
    t.add_column("Latest Root", style="dim")

    for s in shards:
        root = str(s.get("latest_root", "—"))
        t.add_row(
            str(s.get("shard_id", "—")),
            str(s.get("latest_seq", s.get("entry_count", "—"))),
            root[:32] + "…" if len(root) > 32 else root,
        )
    out.print(t)


@shard_app.command("inspect")
def shard_inspect(
    shard_id: Annotated[str, typer.Argument(help="Shard ID")],
) -> None:
    """Show latest header for a shard."""
    result = _request(f"/shards/{shard_id}/header/latest")
    if _S.json_out:
        _emit(result)
        return
    body = Syntax(json.dumps(result, indent=2), "json", theme="monokai")
    out.print(Panel(body, title=f"[bold]Shard[/] [dim]{shard_id}[/]", border_style="cyan"))


@shard_app.command("history")
def shard_history(
    shard_id: Annotated[str, typer.Argument(help="Shard ID")],
    limit: Annotated[int, typer.Option(help="Max entries to show")] = 20,
) -> None:
    """Show commit history for a shard."""
    result = _request(f"/shards/{shard_id}/history?limit={limit}")
    if _S.json_out:
        _emit(result)
        return
    entries = _unwrap_list(result) if isinstance(result, (dict, list)) else []
    if not entries:
        out.print("[dim]No history.[/]")
        return
    t = Table(box=box.SIMPLE, header_style="bold")
    t.add_column("Seq", justify="right")
    t.add_column("Root", style="dim")
    t.add_column("Timestamp")
    for e in entries:
        t.add_row(
            str(e.get("seq", "—")),
            str(e.get("root_hash", e.get("header_hash", "—")))[:24] + "…",
            str(e.get("timestamp", e.get("ts", "—"))),
        )
    out.print(t)


@shard_app.command("tail")
def shard_tail(
    shard_id: Annotated[str, typer.Argument(help="Shard ID")],
    n: Annotated[int, typer.Option(help="Number of ledger entries")] = 5,
) -> None:
    """Show the latest ledger entries for a shard."""
    result = _request(f"/ledger/{shard_id}/tail?n={n}")
    if _S.json_out:
        _emit(result)
        return
    body = Syntax(json.dumps(result, indent=2), "json", theme="monokai")
    out.print(Panel(body, title=f"[bold]Ledger tail[/] [dim]{shard_id}[/]", border_style="blue"))


# ---------------------------------------------------------------------------
# node
# ---------------------------------------------------------------------------


@node_app.callback()
def _node_root() -> None:
    """Node management."""


@node_app.command("list")
def node_list(
    registry: Annotated[str, typer.Option(help="Path to federation registry JSON")] = "",
) -> None:
    """List federation nodes from the registry."""
    try:
        reg = FederationRegistry.from_file(_reg_path(registry))
    except Exception as exc:
        _die(f"could not load registry: {exc}")

    if _S.json_out:
        _emit(
            [
                {
                    "node_id": n.node_id,
                    "status": n.status,
                    "operator": n.operator,
                    "jurisdiction": n.jurisdiction,
                    "endpoint": n.endpoint,
                }
                for n in reg.nodes
            ]
        )
        return

    t = Table(box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Node ID")
    t.add_column("Status")
    t.add_column("Operator")
    t.add_column("Jurisdiction")
    t.add_column("Endpoint")
    for n in reg.nodes:
        color = "green" if n.status == "active" else "dim"
        t.add_row(n.node_id, f"[{color}]{n.status}[/]", n.operator, n.jurisdiction, n.endpoint)
    out.print(t)


@node_app.command("start")
def node_start(
    host: Annotated[str, typer.Option(help="Bind host")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port")] = 8000,
    node_id: Annotated[str, typer.Option(help="Registry node ID (overrides host/port)")] = "",
    registry: Annotated[str, typer.Option(help="Path to federation registry")] = "",
    reload: Annotated[bool, typer.Option(help="Enable auto-reload (dev only)")] = False,
) -> None:
    """Start a local Olympus node."""
    if node_id:
        try:
            reg = FederationRegistry.from_file(_reg_path(registry))
            node = reg.get_node(node_id)
        except Exception as exc:
            _die(f"could not load node from registry: {exc}")
        parsed = urlparse(node.endpoint)
        if parsed.hostname:
            host = parsed.hostname
        if parsed.port:
            port = parsed.port

    if not os.environ.get("DATABASE_URL"):
        _die("DATABASE_URL must be set to start a node")

    import uvicorn
    from api.main import app as api_app

    if not _S.quiet:
        out.print(f"[dim]Starting Olympus node on {host}:{port}…[/]")
    uvicorn.run(api_app, host=host, port=port, reload=reload)


# ---------------------------------------------------------------------------
# federation
# ---------------------------------------------------------------------------


@fed_app.callback()
def _fed_root() -> None:
    """Federation tools."""


@fed_app.command("status")
def federation_status(
    shard_id: Annotated[str, typer.Option(help="Shard to query across live nodes")] = "",
    registry: Annotated[str, typer.Option(help="Path to federation registry")] = "",
) -> None:
    """Show quorum state and optional live shard agreement."""
    try:
        reg = FederationRegistry.from_file(_reg_path(registry))
    except Exception as exc:
        _die(f"could not load registry: {exc}")

    active = reg.active_nodes()
    quorum = reg.quorum_threshold()

    payload: dict = {
        "total_nodes": len(reg.nodes),
        "active_nodes": len(active),
        "quorum_threshold": quorum,
        "epoch": reg.epoch,
    }

    if shard_id:
        roots: dict[str, int] = {}
        for node in active:
            try:
                with urlopen(f"{node.endpoint}/shards", timeout=5) as resp:  # noqa: S310
                    data = _unwrap_list(json.loads(resp.read()))
                for s in data:
                    if s.get("shard_id") == shard_id:
                        r = str(s.get("latest_root", ""))
                        if r:
                            roots[r] = roots.get(r, 0) + 1
            except Exception:
                pass
        if roots:
            best, agreeing = max(roots.items(), key=lambda x: x[1])
            payload["shard_id"] = shard_id
            payload["latest_root"] = best
            payload["agreeing_nodes"] = agreeing

    if _S.json_out:
        _emit(payload)
        return

    t = _kv_table()
    t.add_row("total nodes", str(payload["total_nodes"]))
    t.add_row("active", str(payload["active_nodes"]))
    t.add_row("quorum", str(payload["quorum_threshold"]))
    t.add_row("epoch", str(payload["epoch"]))
    if shard_id and "latest_root" in payload:
        t.add_row("shard", shard_id)
        root = str(payload["latest_root"])
        t.add_row("latest root", root[:32] + "…" if len(root) > 32 else root)
        t.add_row("agreeing nodes", str(payload.get("agreeing_nodes", "—")))

    out.print(Panel(t, title="[bold]Federation[/]", border_style="blue"))


# ---------------------------------------------------------------------------
# dataset  (argparse compat shim)
# ---------------------------------------------------------------------------


@app.command(
    "dataset",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def dataset(ctx: typer.Context) -> None:
    """Dataset provenance tools (ADR-0010)."""
    import argparse

    from tools.dataset_cli import build_dataset_parser, dispatch_dataset

    sub = argparse.ArgumentParser(prog="olympus dataset")
    build_dataset_parser(sub)
    sys.exit(dispatch_dataset(sub.parse_args(ctx.args)))


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
