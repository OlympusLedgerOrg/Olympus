# Multi-stage build for the Olympus Rust CD-HS-ST service.
#
# This service implements the Constant-Depth Hierarchical Sparse Tree (CD-HS-ST)
# with a gRPC interface over Unix socket. It handles all SMT operations:
# Update, ProveInclusion, ProveNonInclusion, GetRoot, SignRoot, Canonicalize.
#
# Build stage: compile with Rust 1.95 using cargo.
# Final stage: gcr.io/distroless/cc-debian12 — minimal runtime with C/C++ libs
#   required for Rust binaries with some dependencies.

# --- Build Stage ---
FROM rust:1.95-slim-bookworm AS build

WORKDIR /src

# Copy only manifests first to cache dependencies. The build context is the
# repository root so the shared proto definition can be included too.
COPY services/cdhs-smf-rust/Cargo.toml services/cdhs-smf-rust/Cargo.lock* ./
COPY services/cdhs-smf-rust/build.rs ./

# Create a dummy main.rs to build dependencies
RUN mkdir -p src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    echo 'pub fn placeholder() {}' > src/lib.rs

# Copy proto file for build.rs. build.rs uses protoc-bin-vendored, so this
# image does not need a system protobuf-compiler package.
RUN mkdir -p /proto
COPY proto/cdhs_smf.proto /proto/

# Fetch dependencies only (this layer is cached if Cargo.toml/lock unchanged).
RUN cargo fetch --locked

# Now copy the real source code
COPY services/cdhs-smf-rust/src ./src

# Touch source files to ensure rebuild with real code
RUN touch src/main.rs src/lib.rs

# Build the actual binary
RUN cargo build --release

# --- Final Stage ---
# Using cc-debian12 because Rust binaries with crypto dependencies
# often require libgcc and other minimal C runtime libraries.
FROM gcr.io/distroless/cc-debian12

# Copy the compiled binary
COPY --from=build /src/target/release/cdhs-smf-service /cdhs-smf-rust

# Create socket directory (will be mounted as volume in production)
# Note: distroless doesn't have mkdir, so the volume mount handles this

# Run as nonroot user
USER 65532:65532

# Declare read-only filesystem expectation
LABEL org.opencontainers.image.description="Olympus Rust CD-HS-ST service — distroless, read-only" \
      org.opencontainers.image.title="cdhs-smf-rust" \
      io.olympus.security.readonly-rootfs="required"

ENTRYPOINT ["/cdhs-smf-rust"]
