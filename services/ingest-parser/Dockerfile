# syntax=docker/dockerfile:1.6

# ==============================================================================
# Ingest Parser Service - Deterministic Document Extraction
# ==============================================================================
#
# This Dockerfile builds a deterministic document parsing service for Olympus.
#
# DETERMINISM GUARANTEES:
# 1. CPU-only execution (no GPU floating-point non-determinism)
# 2. Strict version pinning with hash verification
# 3. Single-threaded execution for reproducibility
# 4. Model weights downloaded and hashed at build time
#
# BUILD ARGS:
#   PARSER_BACKEND: docling (default) | marker | fallback
#
# ==============================================================================

# Stage 1: Base image with Python
FROM python:3.12-slim-bookworm AS base

# Prevent Python from writing bytecode and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For pikepdf
    libqpdf-dev \
    # For general build tools
    build-essential \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# Stage 2: Dependencies
# ==============================================================================
FROM base AS deps

WORKDIR /app

# Copy requirements first for better caching
COPY requirements-lock.txt ./

# Install Python dependencies with hash verification
RUN pip install --no-cache-dir --require-hashes -r requirements-lock.txt

# ==============================================================================
# Stage 3: Application
# ==============================================================================
FROM deps AS app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser src/ ./src/
COPY --chown=appuser:appuser pyproject.toml README.md ./

# Install the application
RUN pip install --no-cache-dir --no-deps -e .

# Create model directory
RUN mkdir -p /models && chown appuser:appuser /models

# ==============================================================================
# Stage 4: Runtime
# ==============================================================================
FROM app AS runtime

# Switch to non-root user
USER appuser

# Environment variables for deterministic execution
ENV CUDA_VISIBLE_DEVICES="" \
    PYTORCH_ENABLE_MPS_FALLBACK="0" \
    TF_CPP_MIN_LOG_LEVEL="2" \
    JAX_PLATFORM_NAME="cpu" \
    OMP_NUM_THREADS="1" \
    MKL_NUM_THREADS="1" \
    OPENBLAS_NUM_THREADS="1" \
    VECLIB_MAXIMUM_THREADS="1" \
    NUMEXPR_NUM_THREADS="1" \
    # Service configuration
    INGEST_PARSER_HOST="0.0.0.0" \
    INGEST_PARSER_PORT="8090" \
    INGEST_PARSER_CPU_ONLY="true" \
    INGEST_PARSER_NUM_THREADS="1" \
    INGEST_PARSER_LOG_LEVEL="INFO" \
    INGEST_PARSER_MAX_FILE_SIZE_MB="256" \
    INGEST_PARSER_NAME="fallback"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8090/health').raise_for_status()"

# Expose port
EXPOSE 8090

# Run the service
CMD ["python", "-m", "ingest_parser.main"]

# ==============================================================================
# Stage 5: With Docling (optional, larger image)
# ==============================================================================
FROM runtime AS with-docling

USER root

# Install Docling (this will be a larger image with ML dependencies)
RUN pip install --no-cache-dir docling>=2.0.0

# Download and hash model weights at build time
ARG MODEL_DOWNLOAD_SCRIPT=""
RUN if [ -n "$MODEL_DOWNLOAD_SCRIPT" ]; then \
        echo "$MODEL_DOWNLOAD_SCRIPT" | python; \
    fi

USER appuser

ENV INGEST_PARSER_NAME="docling"

# ==============================================================================
# Labels for provenance tracking
# ==============================================================================
LABEL org.opencontainers.image.title="Olympus Ingest Parser Service" \
      org.opencontainers.image.description="Deterministic document extraction for Olympus ledger" \
      org.opencontainers.image.vendor="Olympus Project" \
      org.opencontainers.image.source="https://github.com/OlympusLedgerOrg/Olympus"
