# Multi-stage build for Olympus
# Security: Pin specific version for reproducibility
FROM --platform=linux/amd64 python:3.13-slim AS base

# Security: Set environment variables to prevent bytecode generation and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Security: Install system dependencies and remove cache
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    curl \
    libmagic1 \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install uv for fast, platform-aware dependency resolution
RUN pip install --no-cache-dir uv

# Install Python dependencies from pyproject.toml (platform + Python version aware)
COPY pyproject.toml .
RUN uv pip install --system --no-cache ".[observability]"

# Build the PyO3 extension as a wheel so production gets olympus_core without
# carrying Rust tooling in the runtime image.
FROM --platform=linux/amd64 ghcr.io/pyo3/maturin:v1.8.7 AS olympus-core-builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
RUN maturin build --release --interpreter python3.13 --out /wheels

# Development stage
FROM base AS development

COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY . .

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Production stage
FROM base AS production

# Install the prebuilt Rust/Python extension into the production environment.
COPY --from=olympus-core-builder /wheels /tmp/wheels
RUN pip install --no-cache-dir /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels

# Security: Create non-root user with specific UID/GID and no home directory shell access
RUN groupadd -r -g 1000 olympus \
    && useradd -r -u 1000 -g olympus -m -s /sbin/nologin olympus

# Copy application code with specific ownership
COPY --chown=olympus:olympus protocol /app/protocol
COPY --chown=olympus:olympus storage /app/storage
COPY --chown=olympus:olympus api /app/api
COPY --chown=olympus:olympus integrations /app/integrations
COPY --chown=olympus:olympus schemas /app/schemas
COPY --chown=olympus:olympus alembic /app/alembic
COPY --chown=olympus:olympus alembic.ini /app/alembic.ini
COPY --chown=olympus:olympus scripts /app/scripts

# ZK proof layer: circuits, zkeys, vkeys, snarkjs node helper + node_modules
# Only copy what's needed at runtime — skip test inputs, smoke tests, ptau files
COPY --chown=olympus:olympus proofs/snarkjs_bridge.py /app/proofs/snarkjs_bridge.py
COPY --chown=olympus:olympus proofs/snarkjs_node_helper.js /app/proofs/snarkjs_node_helper.js
COPY --chown=olympus:olympus proofs/proof_generator.py /app/proofs/proof_generator.py
COPY --chown=olympus:olympus proofs/__init__.py /app/proofs/__init__.py
COPY --chown=olympus:olympus proofs/build/document_existence_js /app/proofs/build/document_existence_js
COPY --chown=olympus:olympus proofs/build/redaction_validity_js /app/proofs/build/redaction_validity_js
COPY --chown=olympus:olympus proofs/build/non_existence_js /app/proofs/build/non_existence_js
COPY --chown=olympus:olympus proofs/build/document_existence_final.zkey /app/proofs/build/document_existence_final.zkey
COPY --chown=olympus:olympus proofs/build/redaction_validity_final.zkey /app/proofs/build/redaction_validity_final.zkey
COPY --chown=olympus:olympus proofs/build/non_existence_final.zkey /app/proofs/build/non_existence_final.zkey
COPY --chown=olympus:olympus proofs/keys/verification_keys /app/proofs/keys/verification_keys
COPY proofs/package.json proofs/package-lock.json /app/proofs/
COPY --chown=olympus:olympus proofs/safe-jsonpath /app/proofs/safe-jsonpath
RUN mkdir -p /tmp/npm-install \
    && cd /tmp/npm-install && npm init -y \
    && npm install snarkjs@0.7.5 --no-audit --no-fund --omit=dev \
    && mv /tmp/npm-install/node_modules /app/proofs/node_modules \
    && rm -rf /tmp/npm-install \
    && chown -R olympus:olympus /app/proofs/node_modules

# Security: Set explicit file permissions (read-only for all, directories executable)
# Make startup script executable (555) after the blanket read-only pass.
RUN find /app -type f -exec chmod 444 {} \; \
    && find /app -type d -exec chmod 555 {} \; \
    && chmod 555 /app/scripts/startup.sh

# Security: Switch to non-root user
USER olympus

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5)" || exit 1

# Expose port
EXPOSE 8000

# Security labels for container scanning
LABEL org.opencontainers.image.description="Olympus - Append-only public ledger for government documents"
LABEL org.opencontainers.image.vendor="Olympus Contributors"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL security.non-root="true"

# Run the application
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
