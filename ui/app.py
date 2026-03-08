"""FastAPI + Jinja2 developer debug console for Olympus."""

import json
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request as UrlRequest, urlopen

import nacl.exceptions
import nacl.signing
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from protocol.hashes import blake3_to_field_element
from protocol.poseidon_tree import PoseidonMerkleTree
from protocol.redaction import RedactionProtocol
from protocol.redaction_ledger import (
    RedactionProofWithLedger,
    ZKPublicInputs,
    verify_zk_redaction,
)
from protocol.ssmf import ExistenceProof, SparseMerkleTree


API_BASE = os.environ.get("UI_API_BASE", "http://127.0.0.1:8000")
_parsed_api_base = urlparse(API_BASE)
if _parsed_api_base.scheme not in {"http", "https"} or not _parsed_api_base.netloc:
    raise ValueError("UI_API_BASE must be an absolute http(s) URL")

OPENSTATES_API_BASE = os.environ.get("OPENSTATES_API_BASE", "https://v3.openstates.org")
_parsed_openstates_api_base = urlparse(OPENSTATES_API_BASE)
if (
    _parsed_openstates_api_base.scheme not in {"http", "https"}
    or not _parsed_openstates_api_base.netloc
):
    raise ValueError("OPENSTATES_API_BASE must be an absolute http(s) URL")

RAY_CAST_EPSILON = 1e-12

# Debug UI is disabled by default; set OLYMPUS_DEBUG_UI=true to enable.
DEBUG_UI_ENABLED = os.environ.get("OLYMPUS_DEBUG_UI", "false").lower() == "true"

app = FastAPI(title="Olympus Debug Console", version="0.1.0")
templates = Jinja2Templates(directory="ui/templates")

# In-memory store for committed documents.
# Key: "{document_id}:{version}"
# Not persisted across restarts; for debug/demo use only.
_commit_store: dict[str, dict[str, Any]] = {}


def _fetch_json(path: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from the Olympus API."""
    if not path.startswith("/") or "://" in path:
        raise ValueError("API path must be a relative path")
    with urlopen(f"{API_BASE}{path}", timeout=5) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _fetch_openstates_json(
    path: str, params: dict[str, Any]
) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from the OpenStates API using the configured API key."""
    if not path.startswith("/") or "://" in path:
        raise ValueError("OpenStates path must be relative")
    api_key = os.environ.get("OPENSTATES_API_KEY", "").strip()
    if not api_key:
        raise ValueError("OPENSTATES_API_KEY is required to query OpenStates.")
    query = urlencode({k: v for k, v in params.items() if v is not None and v != ""}, doseq=True)
    url = f"{OPENSTATES_API_BASE}{path}"
    if query:
        url = f"{url}?{query}"
    request = UrlRequest(url, headers={"X-API-KEY": api_key})
    with urlopen(request, timeout=10) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _results_from_payload(payload: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize paginated API payloads into a list of result dictionaries."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    for key in ("results", "items", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _normalize_chamber(value: str | None) -> str:
    """Return a lowercase chamber name for matching."""
    return (value or "").strip().lower()


def _choose_representative(
    people: list[dict[str, Any]],
    requested_name: str,
    chamber: str | None,
) -> dict[str, Any] | None:
    """Select the best OpenStates person match for the requested name and chamber."""
    normalized_name = requested_name.strip().lower()
    normalized_chamber = _normalize_chamber(chamber)
    preferred: list[dict[str, Any]] = []
    fallback: list[dict[str, Any]] = []
    for person in people:
        name = str(person.get("name", "")).strip().lower()
        role = person.get("current_role") or {}
        role_title = str(role.get("title", "")).strip().lower()
        chamber_name = str(role.get("org_classification", "")).strip().lower()
        matches_name = name == normalized_name or normalized_name in name
        matches_chamber = not normalized_chamber or normalized_chamber in {
            role_title,
            chamber_name,
        }
        if matches_name and matches_chamber:
            preferred.append(person)
        elif matches_name:
            fallback.append(person)
    return (preferred or fallback or people or [None])[0]


def _normalize_vote_entries(vote: dict[str, Any]) -> list[dict[str, Any]]:
    """Return per-legislator vote entries from varying OpenStates vote payloads."""
    for key in ("votes", "legislator_votes", "voters"):
        value = vote.get(key)
        if isinstance(value, list):
            return [entry for entry in value if isinstance(entry, dict)]
    return []


def _extract_voting_records(
    person: dict[str, Any],
    bills: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    """Build a representative voting record from bill vote payloads."""
    person_id = str(person.get("id", "")).strip()
    person_name = str(person.get("name", "")).strip().lower()
    records: list[dict[str, Any]] = []
    for bill in bills:
        votes = bill.get("votes")
        if not isinstance(votes, list):
            continue
        for vote in votes:
            if not isinstance(vote, dict):
                continue
            for entry in _normalize_vote_entries(vote):
                entry_person_id = str(entry.get("person_id") or entry.get("id") or "").strip()
                voter_name = str(entry.get("voter_name") or entry.get("name") or "").strip().lower()
                if person_id and entry_person_id != person_id and voter_name != person_name:
                    continue
                records.append(
                    {
                        "bill_identifier": str(bill.get("identifier", "")),
                        "bill_title": str(bill.get("title", "")),
                        "classification": bill.get("classification", []),
                        "motion": str(
                            vote.get("motion_text") or vote.get("motion") or "Recorded vote"
                        ),
                        "date": str(vote.get("date") or entry.get("voted_at") or ""),
                        "result": str(vote.get("result") or ""),
                        "option": str(entry.get("option") or entry.get("vote") or ""),
                        "organization": str(
                            (vote.get("organization") or {}).get("name")
                            if isinstance(vote.get("organization"), dict)
                            else vote.get("organization", "")
                        ),
                    }
                )
                break
    records.sort(key=lambda item: item["date"], reverse=True)
    return records[:limit]


def _normalize_whitespace(text: str) -> str:
    """Collapse repeated whitespace into single spaces."""
    return " ".join(text.split())


def _rewrite_legalese(text: str) -> str:
    """Apply deterministic legalese-to-plain-English substitutions."""
    replacements = {
        r"\bshall\b": "must",
        r"\bmay not\b": "cannot",
        r"\bpursuant to\b": "under",
        r"\bnotwithstanding\b": "even if",
        r"\bprior to\b": "before",
        r"\bsubsequent to\b": "after",
        r"\bcommence\b": "start",
        r"\bterminate\b": "end",
        r"\butilize\b": "use",
        r"\bpersons\b": "people",
    }
    rewritten = text
    for pattern, replacement in replacements.items():
        rewritten = re.sub(pattern, replacement, rewritten, flags=re.IGNORECASE)
    rewritten = re.sub(r"\s*;\s*", ". ", rewritten)
    return _normalize_whitespace(rewritten)


def _extract_bill_highlights(text: str) -> dict[str, list[str]]:
    """Extract simple structured highlights from pasted bill text."""
    sentences = [
        _rewrite_legalese(sentence.strip())
        for sentence in re.split(r"(?<=[.!?])\s+", _normalize_whitespace(text))
        if sentence.strip()
    ]
    dates = re.findall(
        r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}(?:,\s*\d{4})?",
        text,
        flags=re.IGNORECASE,
    )
    amounts = re.findall(r"\$\s?\d[\d,]*(?:\.\d+)?", text)
    actions = [
        sentence
        for sentence in sentences
        if any(
            keyword in sentence.lower()
            for keyword in ("must", "cannot", "authorizes", "requires", "prohibits")
        )
    ]
    return {
        "sentences": sentences,
        "dates": dates[:3],
        "amounts": amounts[:3],
        "actions": actions[:3],
    }


def _build_plain_english_summary(text: str) -> dict[str, Any]:
    """Produce a deterministic bill summary and prompt chain."""
    normalized = _normalize_whitespace(text)
    if not normalized:
        raise ValueError("Bill text is required.")
    highlights = _extract_bill_highlights(normalized)
    prompt_chain = [
        {
            "stage": "extract_obligations",
            "prompt": (
                "Read the legislation and list the actors, required actions, deadlines, money, and"
                " enforcement hooks."
            ),
            "output": {
                "actions": highlights["actions"],
                "dates": highlights["dates"],
                "amounts": highlights["amounts"],
            },
        },
        {
            "stage": "translate_for_constituents",
            "prompt": (
                "Rewrite the obligations in direct plain English, replace legalese with everyday"
                " terms, and keep uncertainty visible."
            ),
            "output": highlights["sentences"][:3],
        },
        {
            "stage": "flag_open_questions",
            "prompt": (
                "List what a resident, reporter, or advocate should still verify in the full text"
                " before relying on the summary."
            ),
            "output": [
                "Confirm fiscal effects in the enrolled bill text."
                if highlights["amounts"]
                else "No explicit dollar amount detected.",
                "Check the effective date section."
                if highlights["dates"]
                else "No clear effective date detected.",
            ],
        },
    ]
    summary_lines = highlights["sentences"][:2] or [normalized[:240]]
    return {
        "plain_english_summary": " ".join(summary_lines),
        "key_actions": highlights["actions"],
        "dates": highlights["dates"],
        "amounts": highlights["amounts"],
        "prompt_chain": prompt_chain,
    }


def _parse_geojson_geometry(payload: dict[str, Any]) -> list[list[tuple[float, float]]]:
    """Extract polygon rings from a Feature, FeatureCollection, Polygon, or MultiPolygon."""
    geo_type = payload.get("type")
    if geo_type == "FeatureCollection":
        polygons: list[list[tuple[float, float]]] = []
        for feature in payload.get("features", []):
            if isinstance(feature, dict):
                polygons.extend(_parse_geojson_geometry(feature))
        return polygons
    if geo_type == "Feature":
        geometry = payload.get("geometry")
        if not isinstance(geometry, dict):
            raise ValueError("GeoJSON feature is missing geometry.")
        return _parse_geojson_geometry(geometry)
    if geo_type == "Polygon":
        coordinates = payload.get("coordinates")
        if not isinstance(coordinates, list) or not coordinates:
            raise ValueError("GeoJSON polygon has no coordinates.")
        ring = coordinates[0]
        return [[(float(point[0]), float(point[1])) for point in ring]]
    if geo_type == "MultiPolygon":
        coordinates = payload.get("coordinates")
        if not isinstance(coordinates, list):
            raise ValueError("GeoJSON multipolygon has no coordinates.")
        polygons = []
        for polygon in coordinates:
            if polygon:
                polygons.append([(float(point[0]), float(point[1])) for point in polygon[0]])
        return polygons
    raise ValueError("GeoJSON must be a Feature, FeatureCollection, Polygon, or MultiPolygon.")


def _point_in_polygon(point: tuple[float, float], polygon: list[tuple[float, float]]) -> bool:
    """Determine whether a point falls inside a polygon using ray casting."""
    x, y = point
    inside = False
    if len(polygon) < 3:
        return False
    j = len(polygon) - 1
    for i in range(len(polygon)):
        xi, yi = polygon[i]
        xj, yj = polygon[j]
        intersects = ((yi > y) != (yj > y)) and (
            x < (xj - xi) * (y - yi) / ((yj - yi) or RAY_CAST_EPSILON) + xi
        )
        if intersects:
            inside = not inside
        j = i
    return inside


def _project_to_svg(
    point: tuple[float, float],
    bounds: tuple[float, float, float, float],
    width: int = 420,
    height: int = 280,
    padding: int = 20,
) -> tuple[float, float]:
    """Project longitude/latitude-like points into an SVG viewport."""
    min_x, min_y, max_x, max_y = bounds
    scale_x = (width - 2 * padding) / ((max_x - min_x) or 1.0)
    scale_y = (height - 2 * padding) / ((max_y - min_y) or 1.0)
    px = padding + (point[0] - min_x) * scale_x
    py = height - padding - (point[1] - min_y) * scale_y
    return px, py


def _build_geofence_svg(
    polygons: list[list[tuple[float, float]]],
    constituents: list[dict[str, Any]],
) -> str:
    """Render a compact SVG showing district outlines and constituent points."""
    points = [(float(item["lon"]), float(item["lat"])) for item in constituents]
    all_points = [point for polygon in polygons for point in polygon] + points
    min_x = min(point[0] for point in all_points)
    max_x = max(point[0] for point in all_points)
    min_y = min(point[1] for point in all_points)
    max_y = max(point[1] for point in all_points)
    bounds = (min_x, min_y, max_x, max_y)
    path_data = []
    for polygon in polygons:
        projected = [_project_to_svg(point, bounds) for point in polygon]
        if not projected:
            continue
        first_x, first_y = projected[0]
        commands = [f"M {first_x:.2f} {first_y:.2f}"]
        commands.extend(f"L {x:.2f} {y:.2f}" for x, y in projected[1:])
        commands.append("Z")
        path_data.append(" ".join(commands))
    circles = []
    for item in constituents:
        cx, cy = _project_to_svg((float(item["lon"]), float(item["lat"])), bounds)
        color = "#166534" if item["inside"] else "#991b1b"
        circles.append(
            f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="5" fill="{color}"><title>{item["name"]}</title></circle>'
        )
    return (
        '<svg viewBox="0 0 420 280" role="img" aria-label="District overlap map" '
        'xmlns="http://www.w3.org/2000/svg">'
        '<rect width="420" height="280" fill="#f8fafc" />'
        + "".join(
            f'<path d="{segment}" fill="rgba(15,118,110,0.18)" stroke="#0f766e" stroke-width="2" />'
            for segment in path_data
        )
        + "".join(circles)
        + "</svg>"
    )


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


@app.get("/civic/voting-record")
def representative_voting_record(
    name: str = Query(..., min_length=1),
    jurisdiction: str = Query(..., min_length=1),
    chamber: str | None = Query(default=None),
    limit: int = Query(default=10, ge=1, le=25),
):
    """Fetch a representative voting record using live OpenStates data."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
    try:
        people_payload = _fetch_openstates_json(
            "/people",
            {"jurisdiction": jurisdiction, "name": name, "per_page": 10},
        )
        people = _results_from_payload(people_payload)
        person = _choose_representative(people, name, chamber)
        if person is None:
            return JSONResponse(
                status_code=404,
                content={"ok": False, "error": "No matching OpenStates representative was found."},
            )
        bills_payload = _fetch_openstates_json(
            "/bills",
            {
                "jurisdiction": jurisdiction,
                "sort": "updated_at",
                "per_page": max(limit * 2, 10),
                "include": ["votes"],
            },
        )
        bills = _results_from_payload(bills_payload)
        votes = _extract_voting_records(person, bills, limit=limit)
    except ValueError as exc:
        return JSONResponse(status_code=503, content={"ok": False, "error": str(exc)})
    except HTTPError as exc:
        return JSONResponse(
            status_code=exc.code,
            content={"ok": False, "error": f"OpenStates query failed (HTTP {exc.code})."},
        )
    except URLError:
        return JSONResponse(
            status_code=503,
            content={"ok": False, "error": "OpenStates API unavailable."},
        )

    role = person.get("current_role") if isinstance(person.get("current_role"), dict) else {}
    return JSONResponse(
        {
            "ok": True,
            "representative": {
                "id": person.get("id"),
                "name": person.get("name"),
                "party": person.get("party"),
                "district": role.get("district"),
                "chamber": role.get("title") or role.get("org_classification"),
                "jurisdiction": jurisdiction,
            },
            "votes": votes,
            "source": {"provider": "OpenStates", "bills_scanned": len(bills)},
        }
    )


@app.post("/civic/simplify-bill")
async def simplify_bill_text(request: Request):
    """Turn pasted legislative text into a plain-English summary with prompt-chain visibility."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
    try:
        body = await request.json()
        text = str(body["text"])
        result = _build_plain_english_summary(text)
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )
    return JSONResponse({"ok": True, **result})


@app.post("/civic/geofence-preview")
async def geofence_preview(request: Request):
    """Render a district boundary preview and compute constituent overlap counts."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
    try:
        body = await request.json()
        raw_geojson = body["district_geojson"]
        geojson = json.loads(raw_geojson) if isinstance(raw_geojson, str) else raw_geojson
        if not isinstance(geojson, dict):
            raise ValueError("district_geojson must decode to an object.")
        raw_constituents = body["constituents"]
        constituents = (
            json.loads(raw_constituents) if isinstance(raw_constituents, str) else raw_constituents
        )
        if not isinstance(constituents, list):
            raise ValueError("constituents must decode to an array.")
        polygons = _parse_geojson_geometry(geojson)
        marked_constituents = []
        for item in constituents:
            if not isinstance(item, dict):
                raise ValueError("Each constituent must be an object.")
            lat = float(item["lat"])
            lon = float(item["lon"])
            inside = any(_point_in_polygon((lon, lat), polygon) for polygon in polygons)
            marked_constituents.append(
                {
                    "name": str(item.get("name", "Constituent")),
                    "lat": lat,
                    "lon": lon,
                    "inside": inside,
                }
            )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    overlap = [item for item in marked_constituents if item["inside"]]
    outside = [item for item in marked_constituents if not item["inside"]]
    return JSONResponse(
        {
            "ok": True,
            "district_count": len(polygons),
            "overlap_count": len(overlap),
            "outside_count": len(outside),
            "constituents": marked_constituents,
            "svg": _build_geofence_svg(polygons, marked_constituents),
        }
    )


@app.post("/commit")
async def commit_document(
    document_id: str = Form(...),
    version: int = Form(1),
    file: UploadFile = File(...),
):
    """Commit a document using the dual-anchor strategy (BLAKE3 + Poseidon)."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": "File must be valid UTF-8."}
        )

    # Accept JSON array of strings or plain text (one section per non-empty line).
    parts: list[str] = []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            parts = [str(item) for item in parsed if str(item).strip()]
        else:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "JSON file must be an array of strings."},
            )
    except json.JSONDecodeError:
        parts = [line for line in text.splitlines() if line.strip()]

    if not parts:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": "Document has no sections."}
        )

    # Build Poseidon Merkle tree over field-element leaves derived from each section.
    leaf_fields = [blake3_to_field_element(part.encode("utf-8")) for part in parts]
    poseidon_tree = PoseidonMerkleTree(leaf_fields)
    poseidon_root = poseidon_tree.get_root()

    smt = SparseMerkleTree()
    try:
        tree, blake3_root = RedactionProtocol.commit_document_dual(
            document_parts=parts,
            poseidon_root=poseidon_root,
            smt=smt,
            document_id=document_id,
            version=version,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

    commit_key = f"{document_id}:{version}"
    _commit_store[commit_key] = {
        "parts": parts,
        "leaf_fields": leaf_fields,
        "tree": tree,
        "smt": smt,
        "blake3_root": blake3_root,
        "poseidon_root": poseidon_root,
        "document_id": document_id,
        "version": version,
    }

    return JSONResponse(
        {
            "ok": True,
            "document_id": document_id,
            "version": version,
            "blake3_root": blake3_root,
            "poseidon_root": poseidon_root,
            "sections_count": len(parts),
            "commit_key": commit_key,
        }
    )


@app.get("/committed/{doc_id}/{version}/sections")
def get_committed_sections(doc_id: str, version: int):
    """Return sections of a previously committed document."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    commit_key = f"{doc_id}:{version}"
    entry = _commit_store.get(commit_key)
    if entry is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No committed document for '{commit_key}'."},
        )

    return JSONResponse(
        {
            "ok": True,
            "document_id": doc_id,
            "version": version,
            "sections": entry["parts"],
            "blake3_root": entry["blake3_root"],
            "poseidon_root": entry["poseidon_root"],
        }
    )


@app.post("/redact")
async def create_redaction(request: Request):
    """Generate a redaction proof bundle for a previously committed document."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    try:
        body = await request.json()
        document_id = str(body["document_id"])
        version = int(body["version"])
        revealed_indices = [int(i) for i in body["revealed_indices"]]
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    commit_key = f"{document_id}:{version}"
    entry = _commit_store.get(commit_key)
    if entry is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No committed document for '{commit_key}'."},
        )

    parts: list[str] = entry["parts"]
    leaf_fields: list[str] = entry["leaf_fields"]
    tree = entry["tree"]
    smt: SparseMerkleTree = entry["smt"]
    poseidon_root: str = entry["poseidon_root"]

    for idx in revealed_indices:
        if idx < 0 or idx >= len(parts):
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": f"Section index {idx} is out of range."},
            )

    # Compute the redacted commitment: Poseidon root over the nullified leaf vector
    # (revealed leaves kept, redacted leaves replaced with field element 0).
    revealed_set = set(revealed_indices)
    nullified = [leaf_fields[i] if i in revealed_set else "0" for i in range(len(parts))]
    redacted_tree = PoseidonMerkleTree(nullified)
    redacted_commitment = redacted_tree.get_root()
    revealed_count = len(revealed_indices)

    proof = RedactionProtocol.create_redaction_proof_with_ledger(
        tree=tree,
        revealed_indices=revealed_indices,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id=document_id,
        version=version,
        zk_proof={},
        redacted_commitment=redacted_commitment,
        revealed_count=revealed_count,
    )

    smt_root_hex = smt.get_root().hex()
    revealed_content = [parts[i] for i in revealed_indices]

    bundle = {
        "smt_proof": {
            "key": proof.smt_proof.key.hex(),
            "value_hash": proof.smt_proof.value_hash.hex(),
            "siblings": [s.hex() for s in proof.smt_proof.siblings],
            "root_hash": proof.smt_proof.root_hash.hex(),
        },
        "zk_proof": proof.zk_proof,
        "zk_public_inputs": {
            "original_root": proof.zk_public_inputs.original_root,
            "redacted_commitment": proof.zk_public_inputs.redacted_commitment,
            "revealed_count": proof.zk_public_inputs.revealed_count,
        },
        "smt_root": smt_root_hex,
        "revealed_indices": revealed_indices,
        "revealed_content": revealed_content,
        "total_parts": len(parts),
    }

    return JSONResponse({"ok": True, "bundle": bundle})


@app.post("/verify")
async def verify_proof_bundle(request: Request):
    """Verify a redaction proof bundle (SMT anchor + ZK proof)."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    try:
        body = await request.json()
        smt_proof_data = body["smt_proof"]
        smt_proof = ExistenceProof(
            key=bytes.fromhex(smt_proof_data["key"]),
            value_hash=bytes.fromhex(smt_proof_data["value_hash"]),
            siblings=[bytes.fromhex(s) for s in smt_proof_data["siblings"]],
            root_hash=bytes.fromhex(smt_proof_data["root_hash"]),
        )
        zk_pi = body["zk_public_inputs"]
        public_inputs = ZKPublicInputs(
            original_root=str(zk_pi["original_root"]),
            redacted_commitment=str(zk_pi["redacted_commitment"]),
            revealed_count=int(zk_pi["revealed_count"]),
        )
        proof = RedactionProofWithLedger(
            smt_proof=smt_proof,
            zk_proof=body["zk_proof"],
            zk_public_inputs=public_inputs,
        )
        smt_root = bytes.fromhex(body["smt_root"])
        revealed_indices: list[int] = body.get("revealed_indices", [])
        revealed_content: list[str] = body.get("revealed_content", [])
        total_parts: int = int(body.get("total_parts", 0))
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"Invalid proof bundle: {exc}"},
        )

    smt_anchor_ok = proof.verify_smt_anchor(smt_root)
    zk_ok = verify_zk_redaction(proof.zk_proof, proof.zk_public_inputs)
    overall = smt_anchor_ok and zk_ok

    revealed_sections = [
        {"index": idx, "content": content}
        for idx, content in zip(revealed_indices, revealed_content)
    ]

    return JSONResponse(
        {
            "ok": True,
            "verified": overall,
            "smt_anchor_verified": smt_anchor_ok,
            "zk_verified": zk_ok,
            "revealed_sections": revealed_sections,
            "total_parts": total_parts,
        }
    )
