"""FastAPI + Jinja2 developer debug console for Olympus."""

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import urlopen

import nacl.exceptions
import nacl.signing
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates


API_BASE = os.environ.get("UI_API_BASE", "http://127.0.0.1:8000")
_parsed_api_base = urlparse(API_BASE)
if _parsed_api_base.scheme not in {"http", "https"} or not _parsed_api_base.netloc:
    raise ValueError("UI_API_BASE must be an absolute http(s) URL")

# Debug UI is disabled by default; set OLYMPUS_DEBUG_UI=true to enable.
DEBUG_UI_ENABLED = os.environ.get("OLYMPUS_DEBUG_UI", "false").lower() == "true"

app = FastAPI(title="Olympus Debug Console", version="0.1.0")
templates = Jinja2Templates(directory="ui/templates")


def _fetch_json(path: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from the Olympus API."""
    if not path.startswith("/") or "://" in path:
        raise ValueError("API path must be a relative path")
    with urlopen(f"{API_BASE}{path}", timeout=5) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _verify_signature(header: dict[str, Any]) -> bool:
    """Verify Ed25519 shard header signature."""
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(header["pubkey"]))
        verify_key.verify(bytes.fromhex(header["header_hash"]), bytes.fromhex(header["signature"]))
    except (ValueError, KeyError, nacl.exceptions.BadSignatureError):
        return False
    return True


def _is_chain_broken(entries: list[dict[str, Any]]) -> bool:
    """Return true when tail linkage invariant is broken."""
    for i in range(len(entries) - 1):
        if entries[i]["prev_entry_hash"] != entries[i + 1]["entry_hash"]:
            return True
    return False


@app.get("/")
def debug_console(request: Request):
    """Render the debug console view."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
    context: dict[str, Any] = {
        "request": request,
        "api_base": API_BASE,
        "shards": [],
        "banners": [],
    }

    try:
        shards = _fetch_json("/shards")
    except HTTPError as exc:
        if exc.code == 503:
            context["banners"].append("Database unavailable (503).")
            return templates.TemplateResponse(request, "index.html", context)
        context["banners"].append(f"API error: HTTP {exc.code}")
        return templates.TemplateResponse(request, "index.html", context)
    except URLError:
        context["banners"].append("API unavailable (connection failed).")
        return templates.TemplateResponse(request, "index.html", context)

    for shard in shards:
        shard_id = shard["shard_id"]
        shard_row = {"shard": shard, "header": None, "ledger_tail": [], "signature_valid": True}
        try:
            header = _fetch_json(f"/shards/{quote(shard_id)}/header/latest")
            shard_row["header"] = header
            shard_row["signature_valid"] = _verify_signature(header)
            if not shard_row["signature_valid"]:
                context["banners"].append(f"Invalid signature detected for shard {shard_id}.")

            ledger = _fetch_json(f"/ledger/{quote(shard_id)}/tail?n=10")
            entries = ledger.get("entries", [])
            shard_row["ledger_tail"] = entries
            if _is_chain_broken(entries):
                context["banners"].append(f"Chain linkage broken in shard {shard_id} ledger tail.")
        except HTTPError as exc:
            if exc.code == 503:
                context["banners"].append("Database unavailable (503).")
            else:
                context["banners"].append(f"Shard {shard_id} query failed (HTTP {exc.code}).")
        except URLError:
            context["banners"].append(f"Shard {shard_id} query failed (connection error).")

        context["shards"].append(shard_row)

    return templates.TemplateResponse(request, "index.html", context)


@app.get("/proof-explorer")
def proof_explorer(
    shard_id: str = Query(...),
    record_type: str = Query(...),
    record_id: str = Query(...),
    version: int = Query(..., ge=1),
):
    """Proxy proof explorer requests to the API."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
    path = (
        f"/shards/{quote(shard_id)}/proof?record_type={quote(record_type)}"
        f"&record_id={quote(record_id)}&version={version}"
    )
    try:
        proof = _fetch_json(path)
        return JSONResponse({"ok": True, "proof": proof})
    except HTTPError as exc:
        return JSONResponse(
            status_code=exc.code,
            content={"ok": False, "error": f"Proof query failed (HTTP {exc.code})."},
        )
    except URLError:
        return JSONResponse(status_code=503, content={"ok": False, "error": "API unavailable."})
