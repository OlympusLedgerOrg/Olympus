# Multi-stage build for Olympus
FROM python:3.12-slim AS base

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Development stage
FROM base AS development

COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Production stage
FROM python:3.12-slim AS production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=postgresql://olympus:olympus@postgres:5432/olympus

WORKDIR /app

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN addgroup --system --gid 1000 app && \
    adduser --system --uid 1000 --ingroup app --home /app app

# Copy virtual environment from base stage
COPY --from=base /venv /venv
ENV PATH="/venv/bin:$PATH"

# Copy application code (app files last to leverage caching)
COPY --chown=app:app protocol /app/protocol
COPY --chown=app:app storage /app/storage
COPY --chown=app:app api /app/api
COPY --chown=app:app app /app/app
COPY --chown=app:app schemas /app/schemas

# Drop privileges - run as non-root user
USER app:app

# Health check with simple connectivity test
# Note: Install requests in requirements.txt if using HTTP check, or use socket
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('127.0.0.1', 8000)); s.close()" || exit 1

# Expose port
EXPOSE 8000

# Run the application with multiple workers for production
# Note: For additional security in production orchestrators (K8s, ECS):
# - Use seccomp profiles to restrict syscalls
# - Drop Linux capabilities with --cap-drop=ALL --cap-add=NET_BIND_SERVICE
# - Use read-only root filesystem with --read-only
# - Mount /tmp as tmpfs for writable space
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
