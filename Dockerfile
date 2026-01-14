# Multi-stage build for Olympus
# Security: Pin specific version for reproducibility
FROM python:3.12.8-slim AS base

# Security: Set environment variables to prevent bytecode generation and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Security: Install system dependencies and remove cache
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# Development stage
FROM base AS development

COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Production stage
FROM base AS production

# Security: Create non-root user with specific UID/GID and no home directory shell access
RUN groupadd -r -g 1000 olympus \
    && useradd -r -u 1000 -g olympus -m -s /sbin/nologin olympus

# Copy application code with specific ownership
COPY --chown=olympus:olympus protocol /app/protocol
COPY --chown=olympus:olympus storage /app/storage
COPY --chown=olympus:olympus api /app/api
COPY --chown=olympus:olympus app /app/app
COPY --chown=olympus:olympus schemas /app/schemas

# Security: Set explicit file permissions (read-only for all, directories executable)
RUN find /app -type f -exec chmod 444 {} \; \
    && find /app -type d -exec chmod 555 {} \;

# Security: Switch to non-root user
USER olympus

# Set environment variables
ENV DATABASE_URL=postgresql://olympus:olympus@postgres:5432/olympus

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
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
