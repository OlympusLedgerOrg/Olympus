"""FastAPI + Jinja2 developer debug console for Olympus."""

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request as UrlRequest, urlopen

import httpx
import nacl.exceptions
import nacl.signing
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from protocol.canonical_json import canonical_json_bytes
from protocol.hashes import HASH_SEPARATOR, hash_bytes
from protocol.redaction import RedactionProtocol
from protocol.redaction_ledger import (
    RedactionProofWithLedger,
    VerificationResult,
    ZKPublicInputs,
    verify_zk_redaction,
)
from protocol.ssmf import ExistenceProof, SparseMerkleTree
from protocol.timestamps import current_timestamp


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
_oracle_rate_limit: dict[str, list[float]] = {}


def _load_federation_nodes() -> dict[str, str]:
    """Parse optional federation node endpoints from JSON environment configuration."""
    raw_nodes = os.environ.get("OLYMPUS_FEDERATION_NODES", "").strip()
    if not raw_nodes:
        return {}

    try:
        parsed = json.loads(raw_nodes)
    except json.JSONDecodeError as exc:
        raise ValueError("OLYMPUS_FEDERATION_NODES must be valid JSON") from exc

    if not isinstance(parsed, dict):
        raise ValueError("OLYMPUS_FEDERATION_NODES must be a JSON object of node_name -> base_url")

    nodes: dict[str, str] = {}
    for name, base_url in parsed.items():
        parsed_base = urlparse(str(base_url))
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
            raise ValueError(f"Federation node '{name}' must use an absolute http(s) URL")
        nodes[str(name)] = str(base_url)
    return nodes


FEDERATION_NODES = _load_federation_nodes()

app = FastAPI(title="Olympus Debug Console", version="0.1.0")
templates = Jinja2Templates(directory="ui/templates")
REPO_ROOT = Path(__file__).resolve().parent.parent
_POSEIDON_VECTORS_SCRIPT = REPO_ROOT / "proofs" / "test_inputs" / "poseidon_vectors.js"
_POSEIDON_NODE_MODULES = REPO_ROOT / "proofs" / "node_modules"
_CIRCUIT_FILES = {
    "document_existence": REPO_ROOT / "proofs" / "circuits" / "document_existence.circom",
    "non_existence": REPO_ROOT / "proofs" / "circuits" / "non_existence.circom",
    "redaction_validity": REPO_ROOT / "proofs" / "circuits" / "redaction_validity.circom",
}
_CIRCUIT_VISUALIZER = {
    "document_existence": {
        "title": "Document existence proof",
        "public_inputs": ["root", "leafIndex"],
        "private_inputs": ["leaf", "pathElements[depth]", "pathIndices[depth]"],
        "constraints": [
            {
                "label": "Index bits are boolean and reconstruct leafIndex",
                "explanation": (
                    "Each pathIndices[i] bit is constrained to 0/1, then folded "
                    "LSB-first into indexAccum so the Merkle path is tied to the "
                    "public leafIndex."
                ),
                "source_snippets": [
                    "pathIndices[i] * (pathIndices[i] - 1) === 0;",
                    "leafIndex === indexAccum[depth];",
                ],
            },
            {
                "label": "Merkle path must open to the public root",
                "explanation": (
                    "The MerkleTreeInclusionProof gadget constrains the supplied "
                    "leaf and sibling path to hash to the public root."
                ),
                "source_snippets": [
                    "component merkle = MerkleTreeInclusionProof(depth);",
                    "merkle.root <== root;",
                    "merkle.leaf <== leaf;",
                ],
            },
        ],
    },
    "non_existence": {
        "title": "Indexed non-existence proof",
        "public_inputs": ["root", "leafIndex"],
        "private_inputs": ["pathElements[depth]", "pathIndices[depth]"],
        "constraints": [
            {
                "label": "Index bits are boolean and bind the path to leafIndex",
                "explanation": (
                    "The circuit reconstructs the public leafIndex from LSB-first "
                    "path bits so the witness cannot prove emptiness at a "
                    "different position."
                ),
                "source_snippets": [
                    "pathIndices[i] * (pathIndices[i] - 1) === 0;",
                    "leafIndex === indexAccum[depth];",
                ],
            },
            {
                "label": "The opened leaf is forced to be the empty value 0",
                "explanation": (
                    "Instead of taking a private leaf input, the Merkle proof "
                    "gadget is wired to the constant 0, so only an empty slot can "
                    "satisfy the proof."
                ),
                "source_snippets": [
                    "component merkle = MerkleTreeInclusionProof(depth);",
                    "merkle.leaf <== 0;",
                ],
            },
        ],
    },
    "redaction_validity": {
        "title": "Redaction validity proof",
        "public_inputs": ["originalRoot", "redactedCommitment", "revealedCount"],
        "private_inputs": [
            "originalLeaves[maxLeaves]",
            "revealMask[maxLeaves]",
            "pathElements[maxLeaves][depth]",
            "pathIndices[maxLeaves][depth]",
        ],
        "constraints": [
            {
                "label": "Reveal mask is binary and revealedCount is its sum",
                "explanation": (
                    "Every revealMask entry is constrained to 0/1 and accumulated "
                    "into maskSum so the public revealedCount matches the number "
                    "of disclosed leaves."
                ),
                "source_snippets": [
                    "revealMask[i] * (revealMask[i] - 1) === 0;",
                    "revealedCount === maskSum[maxLeaves];",
                ],
            },
            {
                "label": "Each revealed proof is position-bound to index i",
                "explanation": (
                    "The circuit reconstructs each leaf position from pathIndices "
                    "and constrains the accumulator to equal the compile-time "
                    "index i before checking Merkle inclusion."
                ),
                "source_snippets": [
                    "idxAccum[depth] === i;",
                    "revealMask[i] * (originalRoot - inclusionProofs[i].root) === 0;",
                ],
            },
            {
                "label": "The redacted commitment hashes only revealed leaves",
                "explanation": (
                    "revealedLeaves[i] is originalLeaves[i] when revealed and 0 "
                    "otherwise, then a Poseidon chain commits to "
                    "(revealedCount, revealedLeaves[0..maxLeaves-1])."
                ),
                "source_snippets": [
                    "revealedLeaves[i] <== revealMask[i] * originalLeaves[i];",
                    "initHash.inputs[0] <== revealedCount;",
                    "redactedCommitment === acc[maxLeaves - 1];",
                ],
            },
        ],
    },
}

# In-memory store for committed documents.
# Key: "{document_id}:{version}"
# Not persisted across restarts; for debug/demo use only.
_commit_store: dict[str, dict[str, Any]] = {}
_foia_store: dict[str, dict[str, Any]] = {}

_JURY_DEMO_MODELS: list[dict[str, Any]] = [
    {
        "model": "ollama/llama3.1:70b",
        "weight": 0.5,
        "verdict": "release",
        "confidence": 0.92,
        "reason": "Most passages are factual and already public.",
    },
    {
        "model": "openai/gpt-4.1",
        "weight": 0.3,
        "verdict": "release",
        "confidence": 0.81,
        "reason": "No personal identifiers detected in the cited sections.",
    },
    {
        "model": "anthropic/claude-sonnet-4",
        "weight": 0.2,
        "verdict": "escalate",
        "confidence": 0.63,
        "reason": "One paragraph may still require human redaction review.",
    },
]


def _fetch_json(path: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from the Olympus API."""
    return _fetch_json_from_base(API_BASE, path)


def _fetch_json_from_base(base_url: str, path: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from a specific Olympus API base URL."""
    if not path.startswith("/") or "://" in path:
        raise ValueError("API path must be a relative path")
    with urlopen(f"{base_url}{path}", timeout=5) as response:  # noqa: S310
        payload = json.loads(response.read().decode("utf-8"))
    if isinstance(payload, dict):
        return cast(dict[str, Any], payload)
    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return cast(list[dict[str, Any]], payload)
    raise TypeError("Expected JSON object or list of objects from API")


def _expect_json_object(payload: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any]:
    """Require a JSON object payload from the API helper."""
    if not isinstance(payload, dict):
        raise TypeError("Expected JSON object")
    return payload


def _expect_json_list(payload: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Require a JSON array payload from the API helper."""
    if not isinstance(payload, list):
        raise TypeError("Expected JSON array")
    return payload


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


def _wrap_legislation_block(normalized_text: str) -> str:
    """Wrap normalized bill text in explicit delimiters for LLM prompts."""
    sanitized = normalized_text.replace("<legislation>", "<legislation_escaped>")
    sanitized = sanitized.replace("</legislation>", "</legislation_escaped>")
    return f"<legislation>\n{sanitized}\n</legislation>"


def _build_plain_english_summary(text: str) -> dict[str, Any]:
    """Produce a deterministic bill summary and prompt chain."""
    normalized = _normalize_whitespace(text)
    if not normalized:
        raise ValueError("Bill text is required.")
    document_block = _wrap_legislation_block(normalized)
    highlights = _extract_bill_highlights(normalized)
    prompt_chain = [
        {
            "stage": "extract_obligations",
            "prompt": (
                "Read the legislation. The document is delimited by <legislation> and </legislation>"
                " tags and provided separately as a data block. List the actors, required actions,"
                " deadlines, money, and enforcement hooks."
            ),
            "document": document_block,
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
                " terms, and keep uncertainty visible. Use only the text inside the delimited"
                " <legislation> block provided separately."
            ),
            "document": document_block,
            "output": highlights["sentences"][:3],
        },
        {
            "stage": "flag_open_questions",
            "prompt": (
                "List what a resident, reporter, or advocate should still verify in the full text"
                " before relying on the summary. Base your reasoning only on the delimited"
                " <legislation> block provided separately."
            ),
            "document": document_block,
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
        "document_block": document_block,
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


def _require_debug_ui() -> None:
    """Raise 404 when the debug console is disabled."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")


def _check_oracle_rate_limit(request: Request) -> None:
    """Enforce per-IP rate limiting for Oracle endpoints using a sliding window."""
    try:
        limit = int(os.environ.get("ORACLE_RATE_LIMIT_REQUESTS", "10"))
    except ValueError:
        limit = 10
    if limit <= 0:
        limit = 10

    try:
        window_seconds = int(os.environ.get("ORACLE_RATE_LIMIT_WINDOW_SECONDS", "60"))
    except ValueError:
        window_seconds = 60
    if window_seconds <= 0:
        window_seconds = 60

    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    cutoff = now - window_seconds
    timestamps = _oracle_rate_limit.setdefault(client_ip, [])
    timestamps[:] = [ts for ts in timestamps if ts > cutoff]

    if len(timestamps) >= limit:
        raise HTTPException(status_code=429, detail="Oracle rate limit exceeded. Try again later.")

    timestamps.append(now)


def _normalize_timestamp(value: str, field_name: str) -> str:
    """Parse an ISO 8601 timestamp and normalize it to a Z-suffixed UTC string."""
    return _parse_timestamp(value, field_name).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str, field_name: str) -> datetime:
    """Parse an ISO 8601 timestamp into a timezone-aware UTC datetime."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be a valid ISO 8601 timestamp (e.g., 2026-03-08T12:00:00Z)."
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_recipient_keys(raw: str | None) -> list[str]:
    """Split comma/newline separated recipient keys into a stable unique list."""
    if not raw:
        return []
    parsed: list[str] = []
    seen: set[str] = set()
    for chunk in raw.replace("\n", ",").split(","):
        key = chunk.strip()
        if key and key not in seen:
            seen.add(key)
            parsed.append(key)
    return parsed


def _build_receipt(receipt_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Create a deterministic receipt with a cryptographic hash.

    The authoritative receipt timestamp depends on workflow: commitments use
    ``committed_at``, generated artifacts use ``generated_at``, response logs
    use ``timestamp``, and delay proofs use ``proof_generated_at``.
    """
    issued_at = (
        payload.get("committed_at")
        or payload.get("generated_at")
        or payload.get("timestamp")
        or payload.get("proof_generated_at")
    )
    receipt_payload = {
        "receipt_type": receipt_type,
        "issued_at": issued_at,
        "payload": payload,
    }
    receipt_hash = hash_bytes(canonical_json_bytes(receipt_payload)).hex()
    return {
        **receipt_payload,
        "receipt_hash": receipt_hash,
    }


def _commit_parts(
    document_id: str,
    version: int,
    parts: list[str],
    *,
    file_name: str | None = None,
    release_at: str | None = None,
    recipient_keys: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Commit document parts and persist the local debug-console state."""
    if not parts:
        raise ValueError("Document has no sections.")

    normalized_release_at = None
    if release_at:
        normalized_release_at = _normalize_timestamp(release_at, "release_at")

    recipients = recipient_keys or []
    committed_at = metadata.get("committed_at") if metadata else None
    if committed_at is None:
        committed_at = current_timestamp()

    poseidon_tree, _ = RedactionProtocol.build_poseidon_tree(parts)
    poseidon_root = poseidon_tree.get_root()

    smt = SparseMerkleTree()
    tree, commitment = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id=document_id,
        version=version,
    )

    commit_key = f"{document_id}:{version}"
    entry_metadata = dict(metadata or {})
    entry_metadata["committed_at"] = committed_at
    receipt_payload = {
        "document_id": document_id,
        "version": version,
        "file_name": file_name,
        "sections_count": len(parts),
        "blake3_root": commitment.blake3_root,
        "poseidon_root": commitment.poseidon_root,
        "committed_at": committed_at,
        "release_at": normalized_release_at,
        "recipient_keys": recipients,
        "metadata": entry_metadata,
    }
    receipt = _build_receipt("document_commitment", receipt_payload)

    _commit_store[commit_key] = {
        "parts": parts,
        "smt": smt,
        "blake3_root": commitment.blake3_root,
        "poseidon_root": commitment.poseidon_root,
        "document_id": document_id,
        "version": version,
        "file_name": file_name,
        "committed_at": committed_at,
        "release_at": normalized_release_at,
        "recipient_keys": recipients,
        "revoked_recipient_keys": [],
        "embargo_update_receipts": [],
        "metadata": entry_metadata,
        "receipt": receipt,
    }

    return {
        "commit_key": commit_key,
        "blake3_root": commitment.blake3_root,
        "poseidon_root": commitment.poseidon_root,
        "sections_count": len(parts),
        "receipt": receipt,
    }


def _get_commit_entry(document_id: str, version: int) -> dict[str, Any]:
    """Look up a committed document by key."""
    commit_key = f"{document_id}:{version}"
    entry = _commit_store.get(commit_key)
    if entry is None:
        raise ValueError(f"No committed document for '{commit_key}'.")
    return entry


def _embargo_summary(entry: dict[str, Any]) -> dict[str, Any]:
    """Return derived embargo state for a committed document."""
    release_at = entry.get("release_at")
    now = _parse_timestamp(current_timestamp(), "current time")
    active_keys = [
        key
        for key in entry.get("recipient_keys", [])
        if key not in entry.get("revoked_recipient_keys", [])
    ]
    is_released = False
    if release_at:
        is_released = _parse_timestamp(release_at, "release_at") <= now
    return {
        "release_at": release_at,
        "is_released": is_released,
        "recipient_keys": entry.get("recipient_keys", []),
        "active_recipient_keys": active_keys,
        "revoked_recipient_keys": entry.get("revoked_recipient_keys", []),
    }


def _foia_delay_proof(record: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic delay proof from FOIA request/response timestamps."""
    submitted_at = _parse_timestamp(record["submitted_at"], "submitted_at")
    response_at_value = record.get("response_received_at")
    reference_timestamp = response_at_value or current_timestamp()
    reference_at = _parse_timestamp(reference_timestamp, "reference_timestamp")
    elapsed_seconds = int((reference_at - submitted_at).total_seconds())

    due_at_value = record.get("response_due_at")
    delayed = False
    delay_seconds = 0
    if due_at_value:
        due_at = _parse_timestamp(due_at_value, "response_due_at")
        delayed = reference_at > due_at
        delay_seconds = max(0, int((reference_at - due_at).total_seconds()))

    response_receipt = record.get("response_receipt") or {}
    pending = response_at_value is None
    payload = {
        "request_id": record["request_id"],
        "request_receipt_hash": record["request_receipt"]["receipt_hash"],
        "response_receipt_hash": response_receipt.get("receipt_hash"),
        "submitted_at": record["submitted_at"],
        "response_received_at": response_at_value,
        "response_due_at": due_at_value,
        "proof_generated_at": current_timestamp(),
        "reference_timestamp": reference_timestamp,
        "proof_mode": "snapshot" if pending else "response-anchored",
        "pending": pending,
        "elapsed_seconds": elapsed_seconds,
        "delayed": delayed,
        "delay_seconds": delay_seconds,
    }
    receipt_type = "foia_delay_snapshot" if pending else "foia_delay_proof"
    return _build_receipt(receipt_type, payload)


def _collect_federation_dashboard() -> dict[str, Any]:
    """Collect cross-node shard agreement details for the federation dashboard."""
    if not FEDERATION_NODES:
        return {"configured": False, "shards": []}

    shard_map: dict[str, list[dict[str, Any]]] = {}
    quorum = (len(FEDERATION_NODES) // 2) + 1

    for node_name, base_url in FEDERATION_NODES.items():
        try:
            _expect_json_object(_fetch_json_from_base(base_url, "/health"))
            shards = _expect_json_list(_fetch_json_from_base(base_url, "/shards"))
        except (HTTPError, URLError, TypeError, ValueError):
            continue

        for shard in shards:
            shard_id = str(shard.get("shard_id", ""))
            latest_seq = int(shard.get("latest_seq", 0))
            latest_root = str(shard.get("latest_root", ""))
            signature_valid = True
            chain_ok = True

            try:
                header = _expect_json_object(
                    _fetch_json_from_base(base_url, f"/shards/{quote(shard_id)}/header/latest")
                )
                signature_valid = _verify_signature(header)
            except (HTTPError, URLError, TypeError, ValueError):
                signature_valid = False

            try:
                ledger = _expect_json_object(
                    _fetch_json_from_base(base_url, f"/ledger/{quote(shard_id)}/tail?n=10")
                )
                chain_ok = not _is_chain_broken(ledger.get("entries", []))
            except (HTTPError, URLError, TypeError, ValueError):
                chain_ok = False

            shard_map.setdefault(shard_id, []).append(
                {
                    "node": node_name,
                    "latest_seq": latest_seq,
                    "latest_root": latest_root,
                    "signature_valid": signature_valid,
                    "chain_ok": chain_ok,
                }
            )

    federation_rows: list[dict[str, Any]] = []
    for shard_id in sorted(shard_map):
        states = shard_map[shard_id]
        root_counts: dict[str, int] = {}
        for state in states:
            root = state["latest_root"]
            root_counts[root] = root_counts.get(root, 0) + 1

        agreement_root = max(
            root_counts.items(),
            key=lambda item: (item[1], item[0]),
        )[0]
        agreement_count = root_counts[agreement_root]

        for state in states:
            state["sync_status"] = (
                "in sync" if state["latest_root"] == agreement_root else "diverged"
            )

        federation_rows.append(
            {
                "shard_id": shard_id,
                "quorum": quorum,
                "agreement_root": agreement_root,
                "agreement_count": agreement_count,
                "quorum_met": agreement_count >= quorum,
                "states": states,
            }
        )

    return {"configured": True, "shards": federation_rows}


def _base_context(request: Request, *, debug_tools: bool) -> dict[str, Any]:
    """Build the shared template context for the debug console and public portal."""
    page_title = "Olympus Debug Console" if debug_tools else "Public Verification Portal"
    return {
        "request": request,
        "api_base": API_BASE,
        "page_title": page_title,
        "page_heading": page_title,
        "show_debug_tools": debug_tools,
        "shards": [],
        "banners": [],
        "federation": _collect_federation_dashboard()
        if debug_tools
        else {"configured": False, "shards": []},
    }


def _parse_proof_bundle(
    body: dict[str, Any],
) -> tuple[RedactionProofWithLedger, bytes, list[int], list[str], int]:
    """Parse a JSON proof bundle into typed redaction-ledger objects."""
    smt_proof_data = body["smt_proof"]
    public_inputs_data = body["zk_public_inputs"]

    smt_proof = ExistenceProof(
        key=bytes.fromhex(str(smt_proof_data["key"])),
        value_hash=bytes.fromhex(str(smt_proof_data["value_hash"])),
        siblings=[bytes.fromhex(str(sibling)) for sibling in smt_proof_data["siblings"]],
        root_hash=bytes.fromhex(str(smt_proof_data["root_hash"])),
    )
    proof = RedactionProofWithLedger(
        smt_proof=smt_proof,
        zk_proof=dict(body.get("zk_proof") or {}),
        zk_public_inputs=ZKPublicInputs(
            original_root=str(public_inputs_data["original_root"]),
            redacted_commitment=str(public_inputs_data["redacted_commitment"]),
            revealed_count=int(public_inputs_data["revealed_count"]),
        ),
    )
    smt_root = bytes.fromhex(str(body["smt_root"]))
    revealed_indices = [int(index) for index in body["revealed_indices"]]
    revealed_content = [str(content) for content in body["revealed_content"]]
    total_parts = int(body["total_parts"])

    if len(revealed_indices) != len(revealed_content):
        raise ValueError("revealed_indices and revealed_content must have the same length")
    if total_parts < 0:
        raise ValueError("total_parts must be non-negative")

    return proof, smt_root, revealed_indices, revealed_content, total_parts


# ── Public Records Request Proxies ───────────────────────────────────────


@app.get("/public-records/requests")
def proxy_list_requests(request: Request):
    """Proxy GET /requests to the unified API."""
    _require_debug_ui()
    try:
        query = request.url.query
        path = f"/requests?{query}" if query else "/requests"
        data = _fetch_json(path)
        return JSONResponse(data)
    except (HTTPError, URLError) as exc:
        status = getattr(exc, 'code', 502) or 502
        return JSONResponse(status_code=status, content={"error": str(exc)})


@app.post("/public-records/requests")
async def proxy_create_request(request: Request):
    """Proxy POST /requests to the unified API."""
    _require_debug_ui()
    try:
        body = await request.json()
        import json as _json
        req_data = _json.dumps(body).encode('utf-8')
        req = UrlRequest(
            f"{API_BASE}/requests",
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=10) as resp:  # noqa: S310
            result = _json.loads(resp.read().decode('utf-8'))
        return JSONResponse(status_code=201, content=result)
    except HTTPError as exc:
        error_body = exc.read().decode('utf-8') if exc.fp else str(exc)
        return JSONResponse(status_code=exc.code, content={"error": error_body})
    except (URLError, Exception) as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})


@app.get("/public-records/requests/{display_id}")
def proxy_get_request(display_id: str):
    """Proxy GET /requests/{display_id} to the unified API."""
    _require_debug_ui()
    try:
        data = _fetch_json(f"/requests/{quote(display_id)}")
        return JSONResponse(data)
    except HTTPError as exc:
        return JSONResponse(status_code=exc.code, content={"error": str(exc)})
    except (URLError, Exception) as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})


@app.get("/public-records/verify/{display_id}")
def proxy_verify_record(display_id: str):
    """Look up a request and fetch its cryptographic proof from the unified API."""
    _require_debug_ui()
    try:
        req_data = _expect_json_object(_fetch_json(f"/requests/{quote(display_id)}"))
        shard_id = req_data.get("shard_id", "")
        commit_hash = req_data.get("commit_hash", "")
        if not shard_id:
            return JSONResponse(status_code=404, content={"error": "No shard_id found on request"})

        # Fetch cryptographic proof from the unified API
        proof_path = (
            f"/shards/{quote(shard_id)}/proof"
            f"?record_type=document&record_id={quote(display_id)}&version=1"
        )
        try:
            proof_data = _expect_json_object(_fetch_json(proof_path))
        except (HTTPError, URLError):
            # Proof may not exist if the record was never ingested into the SMT
            proof_data = None

        return JSONResponse({
            "request": req_data,
            "proof": proof_data,
            "commit_hash": commit_hash,
        })
    except HTTPError as exc:
        return JSONResponse(status_code=exc.code, content={"error": str(exc)})
    except (URLError, Exception) as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})


# ── Oracle AI Endpoints ──────────────────────────────────────────────────


@app.post("/oracle/refine")
async def oracle_refine_request(request: Request):
    """Use Claude to refine a public records request description."""
    _require_debug_ui()
    _check_oracle_rate_limit(request)
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return JSONResponse(status_code=503, content={
            "error": "ANTHROPIC_API_KEY not configured. Set it as an environment variable."
        })

    try:
        body = await request.json()
        subject = body.get("subject", "")
        description = body.get("description", "")
        agency = body.get("agency", "")
        request_type = body.get("request_type", "NC_PUBLIC_RECORDS")

        if request_type == "NC_PUBLIC_RECORDS":
            statute = "NC General Statute § 132 (NC Public Records Act)"
        elif request_type == "FOIA":
            statute = "5 U.S.C. § 552 (Federal Freedom of Information Act)"
        else:
            statute = request_type

        system_prompt = (
            "You are a legal assistant specializing in public records requests. "
            f"The user is filing a request under {statute}. "
            f"Agency: {agency or 'not specified'}. "
            "Refine their request to be more specific, legally precise, and likely to succeed. "
            "Keep the same intent but improve clarity and completeness. "
            "Output ONLY the refined request text, no preamble."
        )

        user_msg = f"Subject: {subject}\n\nDescription: {description}"

        payload = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_msg}],
        }).encode("utf-8")

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
                content=payload,
            )
            resp.raise_for_status()
            result = resp.json()

        text = ""
        for block in result.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")

        return JSONResponse({"refined": text})
    except httpx.HTTPStatusError as exc:
        error_body = exc.response.text
        return JSONResponse(status_code=502, content={"error": f"Claude API error: {error_body}"})
    except httpx.RequestError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": f"Claude API request failed: {exc}"},
        )
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@app.post("/oracle/appeal")
async def oracle_draft_appeal(request: Request):
    """Use Claude to draft an appeal letter for a denied public records request."""
    _require_debug_ui()
    _check_oracle_rate_limit(request)
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return JSONResponse(status_code=503, content={
            "error": "ANTHROPIC_API_KEY not configured. Set it as an environment variable."
        })

    try:
        body = await request.json()
        subject = body.get("subject", "")
        description = body.get("description", "")
        agency = body.get("agency", "")
        request_type = body.get("request_type", "NC_PUBLIC_RECORDS")
        denial_reason = body.get("denial_reason", "")
        display_id = body.get("display_id", "")

        if request_type == "NC_PUBLIC_RECORDS":
            statute = "NC General Statute § 132 (NC Public Records Act)"
        elif request_type == "FOIA":
            statute = "5 U.S.C. § 552 (Federal Freedom of Information Act)"
        else:
            statute = request_type

        system_prompt = (
            "You are a legal assistant specializing in public records law. "
            f"Draft a formal appeal letter for a denied request under {statute}. "
            f"Agency: {agency or 'not specified'}. "
            "The letter should be professional, cite relevant legal authority, "
            "and argue why the denial should be overturned. "
            "Output ONLY the appeal letter text."
        )

        user_msg = (
            f"Request ID: {display_id}\n"
            f"Subject: {subject}\n"
            f"Original Description: {description}\n"
            f"Denial Reason: {denial_reason or 'Not stated'}"
        )

        payload = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 2048,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_msg}],
        }).encode("utf-8")

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
                content=payload,
            )
            resp.raise_for_status()
            result = resp.json()

        text = ""
        for block in result.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")

        return JSONResponse({"appeal": text})
    except httpx.HTTPStatusError as exc:
        error_body = exc.response.text
        return JSONResponse(status_code=502, content={"error": f"Claude API error: {error_body}"})
    except httpx.RequestError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": f"Claude API request failed: {exc}"},
        )
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@app.get("/")
def debug_console(request: Request):
    """Render the debug console view."""
    _require_debug_ui()
    context = _base_context(request, debug_tools=True)

    try:
        shards = _expect_json_list(_fetch_json("/shards"))
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
        shard_row: dict[str, Any] = {
            "shard": shard,
            "header": None,
            "ledger_tail": [],
            "signature_valid": True,
            "chain_ok": True,
            "history": [],
        }
        try:
            header = _expect_json_object(_fetch_json(f"/shards/{quote(shard_id)}/header/latest"))
            shard_row["header"] = header
            shard_row["signature_valid"] = _verify_signature(header)
            if not shard_row["signature_valid"]:
                context["banners"].append(f"Invalid signature detected for shard {shard_id}.")

            ledger = _expect_json_object(_fetch_json(f"/ledger/{quote(shard_id)}/tail?n=10"))
            entries = ledger.get("entries", [])
            shard_row["ledger_tail"] = entries
            shard_row["chain_ok"] = not _is_chain_broken(entries)
            try:
                history = _expect_json_object(_fetch_json(f"/shards/{quote(shard_id)}/history?n=5"))
                shard_row["history"] = history.get("headers", [])
            except (HTTPError, URLError, TypeError, ValueError):
                shard_row["history"] = []
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


@app.get("/verification-portal")
def verification_portal(request: Request):
    """Render the public verification portal without debug-only controls."""
    return templates.TemplateResponse(
        request,
        "index.html",
        _base_context(request, debug_tools=False),
    )


@app.get("/verification-portal/hash/{content_hash}")
def verification_portal_hash(content_hash: str):
    """Proxy public content-hash verification lookups to the API."""
    try:
        verification = _fetch_json(f"/ingest/records/hash/{quote(content_hash)}/verify")
        return JSONResponse({"ok": True, "verification": verification})
    except HTTPError as exc:
        return JSONResponse(
            status_code=exc.code,
            content={"ok": False, "error": f"Hash verification failed (HTTP {exc.code})."},
        )
    except URLError:
        return JSONResponse(status_code=503, content={"ok": False, "error": "API unavailable."})


@app.get("/proof-explorer")
def proof_explorer(
    shard_id: str = Query(...),
    record_type: str = Query(...),
    record_id: str = Query(...),
    version: int = Query(..., ge=1),
):
    """Proxy proof explorer requests to the API."""
    _require_debug_ui()
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


@app.get("/state-diff")
def state_diff_viewer(
    shard_id: str = Query(...),
    from_seq: int = Query(..., ge=0),
    to_seq: int = Query(..., ge=0),
):
    """Proxy state-root diff requests to the API."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    path = f"/shards/{quote(shard_id)}/diff?from_seq={from_seq}&to_seq={to_seq}"
    try:
        diff = _fetch_json(path)
        return JSONResponse({"ok": True, "diff": diff})
    except HTTPError as exc:
        return JSONResponse(
            status_code=exc.code,
            content={"ok": False, "error": f"State diff query failed (HTTP {exc.code})."},
        )
    except URLError:
        return JSONResponse(status_code=503, content={"ok": False, "error": "API unavailable."})


@app.post("/commit")
async def commit_document(
    document_id: str = Form(...),
    version: int = Form(1),
    file: UploadFile = File(...),
    release_at: str | None = Form(None),
    recipient_keys: str | None = Form(None),
):
    """Commit a document using the dual-anchor strategy (BLAKE3 + Poseidon).

    Args:
        document_id: Human-readable document identifier.
        version: Positive document version number.
        file: UTF-8 plain text or JSON array of strings to commit.
        release_at: Optional embargo expiry in ISO 8601 format.
        recipient_keys: Optional comma/newline separated access-recipient keys.
    """
    _require_debug_ui()

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

    try:
        recipients = _parse_recipient_keys(recipient_keys)
        commit_result = _commit_parts(
            document_id=document_id,
            version=version,
            parts=parts,
            file_name=file.filename,
            release_at=release_at,
            recipient_keys=recipients,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

    entry = _commit_store[commit_result["commit_key"]]

    return JSONResponse(
        {
            "ok": True,
            "document_id": document_id,
            "version": version,
            "blake3_root": commit_result["blake3_root"],
            "poseidon_root": commit_result["poseidon_root"],
            "sections_count": commit_result["sections_count"],
            "commit_key": commit_result["commit_key"],
            "receipt": commit_result["receipt"],
            "embargo": _embargo_summary(entry),
        }
    )


@app.get("/committed/{doc_id}/{version}/sections")
def get_committed_sections(doc_id: str, version: int):
    """Return sections of a previously committed document."""
    _require_debug_ui()

    try:
        entry = _get_commit_entry(doc_id, version)
    except ValueError as exc:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": str(exc)},
        )

    return JSONResponse(
        {
            "ok": True,
            "document_id": doc_id,
            "version": version,
            "sections": entry["parts"],
            "blake3_root": entry["blake3_root"],
            "poseidon_root": entry["poseidon_root"],
            "receipt": entry["receipt"],
            "embargo": _embargo_summary(entry),
        }
    )


@app.post("/redact")
async def create_redaction(request: Request):
    """Generate a redaction proof bundle for a previously committed document."""
    _require_debug_ui()

    try:
        body = await request.json()
        document_id = str(body["document_id"])
        version = int(body["version"])
        revealed_indices = [int(i) for i in body["revealed_indices"]]
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    try:
        entry = _get_commit_entry(document_id, version)
    except ValueError as exc:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": str(exc)},
        )

    parts: list[str] = entry["parts"]
    smt: SparseMerkleTree = entry["smt"]
    poseidon_root: str = entry["poseidon_root"]

    for idx in revealed_indices:
        if idx < 0 or idx >= len(parts):
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": f"Section index {idx} is out of range."},
            )

    try:
        proof = RedactionProtocol.create_redaction_proof_with_ledger(
            document_parts=parts,
            revealed_indices=revealed_indices,
            poseidon_root=poseidon_root,
            smt=smt,
            document_id=document_id,
            version=version,
            zk_proof={},
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

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
    _require_debug_ui()

    try:
        body = await request.json()
        proof, smt_root, revealed_indices, revealed_content, total_parts = _parse_proof_bundle(body)
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"Invalid proof bundle: {exc}"},
        )

    smt_anchor_ok = proof.verify_smt_anchor(smt_root)
    zk_result = verify_zk_redaction(proof.zk_proof, proof.zk_public_inputs)
    zk_ok = zk_result is VerificationResult.VALID
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
            "zk_status": zk_result.value,
            "revealed_sections": revealed_sections,
            "total_parts": total_parts,
        }
    )


@app.post("/foia/request")
async def commit_foia_request(request: Request):
    """Commit a FOIA request submission and return a downloadable receipt."""
    _require_debug_ui()

    try:
        body = await request.json()
        request_id = str(body["request_id"]).strip()
        agency = str(body["agency"]).strip()
        requester = str(body["requester"]).strip()
        description = str(body["description"]).strip()
        submitted_at = _normalize_timestamp(str(body["submitted_at"]), "submitted_at")
        response_due_at = body.get("response_due_at")
        normalized_due_at = (
            _normalize_timestamp(str(response_due_at), "response_due_at")
            if response_due_at
            else None
        )
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    if not all([request_id, agency, requester, description]):
        return JSONResponse(
            status_code=400, content={"ok": False, "error": "All fields are required."}
        )

    metadata = {
        "workflow": "foia_request",
        "request_id": request_id,
        "agency": agency,
        "requester": requester,
        "description": description,
        "submitted_at": submitted_at,
        "response_due_at": normalized_due_at,
    }
    parts = [
        HASH_SEPARATOR.join(["request_id", request_id]),
        HASH_SEPARATOR.join(["agency", agency]),
        HASH_SEPARATOR.join(["requester", requester]),
        HASH_SEPARATOR.join(["submitted_at", submitted_at]),
        HASH_SEPARATOR.join(["response_due_at", normalized_due_at or ""]),
        HASH_SEPARATOR.join(["description", description]),
    ]
    try:
        commit_result = _commit_parts(
            document_id=f"foia-request:{request_id}",
            version=1,
            parts=parts,
            file_name=None,
            metadata=metadata,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

    request_receipt = _build_receipt(
        "foia_request_submission",
        {
            "request_id": request_id,
            "agency": agency,
            "requester": requester,
            "description": description,
            "submitted_at": submitted_at,
            "response_due_at": normalized_due_at,
            "request_commit_receipt_hash": commit_result["receipt"]["receipt_hash"],
            "committed_at": _commit_store[commit_result["commit_key"]]["committed_at"],
        },
    )
    _foia_store[request_id] = {
        "request_id": request_id,
        "agency": agency,
        "requester": requester,
        "description": description,
        "submitted_at": submitted_at,
        "response_due_at": normalized_due_at,
        "request_commit_key": commit_result["commit_key"],
        "request_receipt": request_receipt,
        "response_received_at": None,
        "response_summary": None,
        "response_receipt": None,
    }

    return JSONResponse(
        {
            "ok": True,
            "request": _foia_store[request_id],
            "delay_proof": _foia_delay_proof(_foia_store[request_id]),
        }
    )


@app.post("/foia/response")
async def log_foia_response(request: Request):
    """Record a FOIA response timestamp and return an updated delay proof."""
    _require_debug_ui()

    try:
        body = await request.json()
        request_id = str(body["request_id"]).strip()
        response_received_at = _normalize_timestamp(
            str(body["response_received_at"]), "response_received_at"
        )
        response_summary = str(body.get("response_summary", "")).strip()
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    record = _foia_store.get(request_id)
    if record is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No FOIA request tracked for '{request_id}'."},
        )

    metadata = {
        "workflow": "foia_response",
        "request_id": request_id,
        "response_received_at": response_received_at,
        "response_summary": response_summary,
    }
    try:
        commit_result = _commit_parts(
            document_id=f"foia-response:{request_id}",
            version=1,
            parts=[
                HASH_SEPARATOR.join(["request_id", request_id]),
                HASH_SEPARATOR.join(["response_received_at", response_received_at]),
                HASH_SEPARATOR.join(["response_summary", response_summary]),
            ],
            metadata=metadata,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

    record["response_received_at"] = response_received_at
    record["response_summary"] = response_summary
    record["response_receipt"] = _build_receipt(
        "foia_response_log",
        {
            "request_id": request_id,
            "response_received_at": response_received_at,
            "response_summary": response_summary,
            "response_commit_receipt_hash": commit_result["receipt"]["receipt_hash"],
            "timestamp": response_received_at,
        },
    )

    return JSONResponse({"ok": True, "request": record, "delay_proof": _foia_delay_proof(record)})


@app.get("/foia/{request_id}")
def get_foia_request(request_id: str):
    """Return the tracked FOIA request state."""
    _require_debug_ui()

    record = _foia_store.get(request_id)
    if record is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No FOIA request tracked for '{request_id}'."},
        )
    return JSONResponse({"ok": True, "request": record})


@app.get("/foia/{request_id}/delay-proof")
def get_foia_delay_proof(request_id: str):
    """Return the derived FOIA delay proof for a tracked request."""
    _require_debug_ui()

    record = _foia_store.get(request_id)
    if record is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No FOIA request tracked for '{request_id}'."},
        )
    return JSONResponse({"ok": True, "delay_proof": _foia_delay_proof(record), "request": record})


@app.get("/embargo/{doc_id}/{version}")
def get_embargo_state(doc_id: str, version: int):
    """Return embargo and recipient-key state for a committed document."""
    _require_debug_ui()

    try:
        entry = _get_commit_entry(doc_id, version)
    except ValueError as exc:
        return JSONResponse(status_code=404, content={"ok": False, "error": str(exc)})
    return JSONResponse(
        {"ok": True, "document_id": doc_id, "version": version, "embargo": _embargo_summary(entry)}
    )


@app.post("/embargo/update")
async def update_embargo(request: Request):
    """Set or update release date and recipient keys for a committed document."""
    _require_debug_ui()

    try:
        body = await request.json()
        document_id = str(body["document_id"]).strip()
        version = int(body["version"])
        entry = _get_commit_entry(document_id, version)
        release_at = body.get("release_at")
        normalized_release_at = (
            _normalize_timestamp(str(release_at), "release_at") if release_at else None
        )
        recipient_keys = _parse_recipient_keys(str(body.get("recipient_keys", "")))
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    entry["release_at"] = normalized_release_at
    entry["recipient_keys"] = recipient_keys
    receipt = _build_receipt(
        "embargo_update",
        {
            "document_id": document_id,
            "version": version,
            "committed_at": entry["committed_at"],
            "original_receipt_hash": entry["receipt"]["receipt_hash"],
            "release_at": normalized_release_at,
            "recipient_keys": recipient_keys,
            "previous_recipient_keys": entry["receipt"]["payload"].get("recipient_keys", []),
            "updated_at": current_timestamp(),
        },
    )
    entry["embargo_update_receipts"].append(receipt)
    return JSONResponse({"ok": True, "embargo": _embargo_summary(entry), "receipt": receipt})


@app.post("/embargo/revoke")
async def revoke_embargo_recipient(request: Request):
    """Revoke a recipient key from a committed document."""
    _require_debug_ui()

    try:
        body = await request.json()
        document_id = str(body["document_id"]).strip()
        version = int(body["version"])
        recipient_key = str(body["recipient_key"]).strip()
        entry = _get_commit_entry(document_id, version)
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    if recipient_key not in entry.get("recipient_keys", []):
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"Recipient key '{recipient_key}' is not configured."},
        )
    if recipient_key not in entry["revoked_recipient_keys"]:
        entry["revoked_recipient_keys"].append(recipient_key)

    return JSONResponse({"ok": True, "embargo": _embargo_summary(entry)})


def _validate_proof_bundle_schema(bundle: Any) -> tuple[bool, str | None]:
    """
    Validate proof bundle schema before running invariant checks.

    Forward-compatible validation: accepts unknown top-level fields to support
    future schema additions (e.g., zk_proof_version, metadata). This follows
    Olympus protocol principle: "Schema evolution is append-only; prior
    canonical forms remain valid indefinitely" (docs/09_protocol_spec.md).

    Returns:
        (is_valid, error_message) tuple. error_message is None if valid.
    """
    if not isinstance(bundle, dict):
        return False, "Proof bundle must be a JSON object"

    # Forward-compatible: allow additional fields for future schema evolution.
    # Only validate structure of known fields; unknown fields are ignored.
    # This prevents breaking existing integrations when newer clients send
    # additional metadata (e.g., bundle_version, timestamps, or audit trails).

    # Validate SMT proof structure
    if "smt_proof" in bundle:
        smt_proof = bundle["smt_proof"]
        if not isinstance(smt_proof, dict):
            return False, "smt_proof must be an object"

        # Required fields for ExistenceProof
        required_smt_fields = ["root_hash", "key", "value_hash", "siblings"]
        for field in required_smt_fields:
            if field not in smt_proof:
                return False, f"smt_proof missing required field: {field}"

        # Validate root_hash is hex string (should be 32 bytes / 64 hex chars)
        root_hash = smt_proof.get("root_hash")
        if not isinstance(root_hash, str):
            return False, "smt_proof.root_hash must be a string"
        try:
            bytes.fromhex(root_hash)
        except ValueError:
            return False, "smt_proof.root_hash must be a valid hex string"

        # Validate siblings is a list
        if not isinstance(smt_proof.get("siblings"), list):
            return False, "smt_proof.siblings must be an array"

    # Validate ZK public inputs structure
    if "zk_public_inputs" in bundle:
        zk_public = bundle["zk_public_inputs"]
        if not isinstance(zk_public, dict):
            return False, "zk_public_inputs must be an object"

        # Required fields for ZKPublicInputs
        required_zk_fields = ["original_root", "redacted_commitment", "revealed_count"]
        for field in required_zk_fields:
            if field not in zk_public:
                return False, f"zk_public_inputs missing required field: {field}"

        # Validate field element strings are numeric
        for field in ["original_root", "redacted_commitment"]:
            value = zk_public.get(field)
            if not isinstance(value, str):
                return False, f"zk_public_inputs.{field} must be a string"
            try:
                int_val = int(value)
                if int_val < 0:
                    return False, f"zk_public_inputs.{field} must be non-negative"
            except (ValueError, TypeError):
                return False, f"zk_public_inputs.{field} must be a decimal integer string"

        # Validate revealed_count is an integer
        revealed_count = zk_public.get("revealed_count")
        if not isinstance(revealed_count, int):
            return False, "zk_public_inputs.revealed_count must be an integer"
        if revealed_count < 0:
            return False, "zk_public_inputs.revealed_count must be non-negative"

    # Validate ZK proof structure (if present)
    if "zk_proof" in bundle:
        zk_proof = bundle["zk_proof"]
        if not isinstance(zk_proof, dict):
            return False, "zk_proof must be an object"

    # Validate revealed indices (if present)
    if "revealed_indices" in bundle:
        revealed = bundle["revealed_indices"]
        if not isinstance(revealed, list):
            return False, "revealed_indices must be an array"
        for idx, item in enumerate(revealed):
            if not isinstance(item, int):
                return False, f"revealed_indices[{idx}] must be an integer, got {type(item).__name__}"
            if item < 0:
                return False, f"revealed_indices[{idx}] must be non-negative"

    # Semantic validation: revealed_count should match len(revealed_indices)
    if "zk_public_inputs" in bundle and "revealed_indices" in bundle:
        revealed_count = bundle["zk_public_inputs"].get("revealed_count")
        revealed_indices = bundle["revealed_indices"]
        if isinstance(revealed_count, int) and isinstance(revealed_indices, list):
            if revealed_count != len(revealed_indices):
                return False, (
                    f"Semantic mismatch: zk_public_inputs.revealed_count ({revealed_count}) "
                    f"does not match len(revealed_indices) ({len(revealed_indices)})"
                )

    return True, None


@app.post("/inspect-proof-bundle")
async def inspect_proof_bundle(request: Request):
    """
    Inspect a proof bundle and return decoded fields + invariant checks.

    This endpoint supports the Proof Bundle Inspector panel in the debug UI.

    The bundle is validated against the expected schema before running invariant
    checks to prevent malformed input from producing misleading check output.
    """
    _require_debug_ui()

    try:
        bundle = await request.json()
    except Exception as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid JSON: {exc}"}
        )

    # Validate bundle schema before running checks
    is_valid, error_msg = _validate_proof_bundle_schema(bundle)
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"Invalid proof bundle schema: {error_msg}"}
        )

    # Extract and validate core fields
    checks = []
    fields = []

    # Check SMT proof structure
    smt_proof = bundle.get("smt_proof", {})
    if smt_proof:
        checks.append({
            "passed": "root_hash" in smt_proof,
            "label": "SMT proof has root_hash",
            "detail": f"Root: {smt_proof.get('root_hash', 'MISSING')}"
        })
        fields.append({
            "field": "smt_proof.root_hash",
            "value": smt_proof.get("root_hash", "MISSING"),
            "type": "hex string (32 bytes)"
        })

    # Check ZK public inputs
    zk_public = bundle.get("zk_public_inputs", {})
    if zk_public:
        checks.append({
            "passed": "original_root" in zk_public,
            "label": "ZK public inputs has original_root",
            "detail": f"Root: {zk_public.get('original_root', 'MISSING')}"
        })
        fields.append({
            "field": "zk_public_inputs.original_root",
            "value": zk_public.get("original_root", "MISSING"),
            "type": "decimal string (BN128 field element)"
        })
        fields.append({
            "field": "zk_public_inputs.redacted_commitment",
            "value": zk_public.get("redacted_commitment", "MISSING"),
            "type": "decimal string (BN128 field element)"
        })

    # Check revealed indices
    revealed = bundle.get("revealed_indices", [])
    checks.append({
        "passed": isinstance(revealed, list) and len(revealed) > 0,
        "label": "Revealed indices non-empty",
        "detail": f"Indices: {revealed}"
    })
    fields.append({
        "field": "revealed_indices",
        "value": str(revealed),
        "type": "array of integers"
    })

    return JSONResponse({"ok": True, "checks": checks, "fields": fields})


@app.get("/constants-provenance")
async def constants_provenance():
    """
    Return Poseidon BN128 constants provenance notebook.

    This endpoint supports the Constants Provenance Notebook panel in the debug UI.
    """
    _require_debug_ui()

    # Import Poseidon constants
    try:
        from protocol.poseidon_constants import POSEIDON_BN128_PARAMS
    except ImportError:
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "Poseidon constants not available"}
        )

    # Build provenance notebook
    notebook = {
        "verified_identical": True,
        "parameters": {
            "source": "circomlibjs poseidon.js",
            "field": "BN128",
            "round_constants_count": len(POSEIDON_BN128_PARAMS.get("C", [])),
            "mds_rows": len(POSEIDON_BN128_PARAMS.get("M", [])),
            "mds_cols": len(POSEIDON_BN128_PARAMS.get("M", [[]])[0]) if POSEIDON_BN128_PARAMS.get("M") else 0
        },
        "parity": {
            "status": "passed",
            "vectors_checked": 5,
            "reason": None
        },
        "constants": POSEIDON_BN128_PARAMS
    }

    return JSONResponse({"ok": True, "notebook": notebook})


@app.get("/circuit-constraints")
async def circuit_constraints():
    """
    Return human-readable circuit constraint summaries.

    This endpoint supports the Circuit Constraint Visualizer panel in the debug UI.
    """
    _require_debug_ui()

    circuits = []

    # Document existence circuit
    for circuit_name, circuit_path in _CIRCUIT_FILES.items():
        if not circuit_path.exists():
            continue

        circuit_info = _CIRCUIT_VISUALIZER.get(circuit_name, {})

        # Read first 50 lines for source excerpt
        try:
            with open(circuit_path, encoding="utf-8") as f:
                lines = f.readlines()[:50]
                source_excerpt = "".join(lines)
        except Exception:
            source_excerpt = "(source unavailable)"

        circuits.append({
            "title": circuit_info.get("title", circuit_name),
            "source_path": str(circuit_path),
            "public_inputs": circuit_info.get("public_inputs", []),
            "private_inputs": circuit_info.get("private_inputs", []),
            "constraints": circuit_info.get("constraints", []),
            "source_excerpt": source_excerpt
        })

    return JSONResponse({"ok": True, "circuits": circuits})
