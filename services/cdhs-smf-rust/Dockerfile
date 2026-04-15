# Multi-stage build for the Olympus Rust CD-HS-ST service.
#
# This service implements the Constant-Depth Hierarchical Sparse Tree (CD-HS-ST)
# with a gRPC interface over Unix socket. It handles all SMT operations:
# Update, ProveInclusion, ProveNonInclusion, GetRoot, SignRoot, Canonicalize.
#
# Build stage: compile with Rust stable using cargo.
# Final stage: gcr.io/distroless/cc-debian12 — minimal runtime with C/C++ libs
#   required for Rust binaries with some dependencies.

# --- Build Stage ---
FROM rust:1.87-slim-bookworm AS build

# Install protobuf compiler for prost/tonic code generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy only manifests first to cache dependencies
COPY Cargo.toml Cargo.lock* ./
COPY build.rs ./

# Create a dummy main.rs to build dependencies
RUN mkdir -p src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    echo 'pub fn placeholder() {}' > src/lib.rs

# Copy proto file for build.rs
RUN mkdir -p ../proto
COPY ../proto/cdhs_smf.proto ../proto/ || true

# Build dependencies only (this layer is cached if Cargo.toml/lock unchanged)
RUN cargo build --release || true

# Now copy the real source code
COPY src ./src
COPY ../proto ../proto || true

# Touch source files to ensure rebuild with real code
RUN touch src/main.rs src/lib.rs

# Build the actual binary
RUN cargo build --release

# --- Final Stage ---
# Using cc-debian12 because Rust binaries with crypto dependencies
# often require libgcc and other minimal C runtime libraries.
FROM gcr.io/distroless/cc-debian12

# Copy the compiled binary
COPY --from=build /src/target/release/cdhs-smf-rust /cdhs-smf-rust

# Create socket directory (will be mounted as volume in production)
# Note: distroless doesn't have mkdir, so the volume mount handles this

# Run as nonroot user
USER 65532:65532

# Declare read-only filesystem expectation
LABEL org.opencontainers.image.description="Olympus Rust CD-HS-ST service — distroless, read-only" \
      org.opencontainers.image.title="cdhs-smf-rust" \
      io.olympus.security.readonly-rootfs="required"

ENTRYPOINT ["/cdhs-smf-rust"]
