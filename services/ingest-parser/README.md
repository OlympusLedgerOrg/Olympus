# Ingest Parser Service

A standalone, deterministic microservice for extracting structured data from documents (PDFs, images, office files) for the Olympus ledger system.

## Overview

This service provides document parsing with **cryptographic determinism guarantees**:

1. **CPU-only execution**: Forces FP32 on CPU to avoid GPU floating-point non-determinism
2. **Strict version pinning**: All dependencies and AI models are pinned with hashes
3. **Deterministic output**: All floating-point values (bounding boxes) rounded to exactly 4 decimal places
4. **Full provenance**: Every output includes file hash, parser version, model hashes, and environment digest

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Olympus Python API (api/)                                  │
│  - Receives document upload                                 │
│  - Calculates raw_file_blake3 hash immediately              │
│  - Calls ingest-parser-service                              │
└────────────────┬────────────────────────────────────────────┘
                 │ HTTP POST /parse
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  Ingest Parser Service (this service)                       │
│  - Validates raw file hash                                  │
│  - Runs CPU-only document extraction                        │
│  - Rounds all coordinates to 4 decimal places               │
│  - Returns standardized JSON with provenance                │
└─────────────────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  Olympus Canonicalization (protocol/canonical_json.py)      │
│  - RFC 8785 (JCS) canonicalization                          │
│  - Sorts keys, strips whitespace                            │
│  - Produces deterministic bytes for hashing                 │
└─────────────────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  Rust CD-HS-ST Service (cdhs-smf-rust/)                    │
│  - BLAKE3 hash of canonical bytes                           │
│  - SMT commitment                                           │
│  - Ed25519 signing                                          │
└─────────────────────────────────────────────────────────────┘
```

## API Contract

### POST /parse

Accepts a raw file binary and returns a strictly formatted JSON.

**Request:**
- Content-Type: `multipart/form-data`
- Body: `file` (binary) - The raw document to parse

**Response:**
```json
{
  "provenance": {
    "raw_file_blake3": "blake3_abc123...",
    "parser_name": "docling",
    "parser_version": "2.1.0",
    "model_hash": "sha256_def456...",
    "environment_digest": "sha256_ghi789..."
  },
  "document": {
    "pages": [
      {
        "page_number": 1,
        "blocks": [
          {
            "id": "blk_01",
            "type": "text",
            "content": "Example text content",
            "bbox": [10.0000, 20.0000, 200.0000, 35.0000]
          }
        ]
      }
    ]
  }
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "parser_name": "docling",
  "parser_version": "2.1.0",
  "model_hash": "sha256_...",
  "cpu_only": true
}
```

## Determinism Guarantees

### 1. CPU-Only Execution

GPU floating-point math (CUDA/TensorCore) is non-deterministic across different hardware. This service enforces CPU execution:

```python
# Environment variables set at startup
os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "0"
torch.set_num_threads(1)  # Single-threaded for reproducibility
```

### 2. Bounding Box Rounding

All bounding box coordinates are rounded to exactly 4 decimal places:

```python
def round_bbox(bbox: list[float]) -> list[float]:
    return [round(v, 4) for v in bbox]
```

This prevents floating-point drift from causing different hashes for semantically identical documents.

### 3. Model Pinning

AI model weights are downloaded at build time, hashed, and verified at runtime:

```python
EXPECTED_MODEL_HASH = "sha256_abc123..."

def verify_model_hash(model_path: str) -> bool:
    actual_hash = compute_sha256(model_path)
    return actual_hash == EXPECTED_MODEL_HASH
```

## Building

### Docker Build

```bash
cd services/ingest-parser
docker build -t olympus/ingest-parser:latest .
```

### Local Development

```bash
cd services/ingest-parser
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-lock.txt
python -m ingest_parser.main
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `INGEST_PARSER_HOST` | `0.0.0.0` | Host to bind to |
| `INGEST_PARSER_PORT` | `8090` | Port to listen on |
| `INGEST_PARSER_MAX_FILE_SIZE_MB` | `256` | Maximum file size in MB |
| `INGEST_PARSER_MODEL_PATH` | `/models` | Path to AI model weights |
| `INGEST_PARSER_LOG_LEVEL` | `INFO` | Logging level |

## Testing

```bash
# Run unit tests
pytest tests/

# Test with curl
curl -X POST http://localhost:8090/parse \
  -F "file=@sample.pdf"
```

## Security Considerations

1. **No network access at parse time**: Models are pre-loaded at startup
2. **Memory limits**: Configurable per-request memory limits
3. **File size limits**: Enforced at upload time
4. **No arbitrary code execution**: Parser runs in sandboxed mode
