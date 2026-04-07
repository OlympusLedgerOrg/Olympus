# Multi-stage build for the Olympus Go sequencer.
#
# Build stage: compile a fully static binary (CGO_ENABLED=0) so it runs
# without any libc in the minimal final image.
#
# Final stage: gcr.io/distroless/static-debian12 — no shell, no package
# manager, no unnecessary OS tools.  The resulting image should be deployed
# with a read-only root filesystem (Docker: --read-only; Kubernetes:
# securityContext.readOnlyRootFilesystem: true).

# --- Build Stage ---
FROM golang:1.24.13-alpine AS build

WORKDIR /src

# Copy dependency manifests first to take advantage of Docker layer caching.
# Dependencies are only re-downloaded when go.mod / go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Copy only the source directories required to compile the sequencer binary.
# cmd/ is the main package; internal/ and proto/ are local imports used by it.
# This avoids sending VCS metadata, test data, or other workspace files into
# the build context.
COPY cmd ./cmd
COPY internal ./internal
COPY proto ./proto

# Compile a fully static binary.
# CGO_ENABLED=0  — required for the distroless/static image (no libc present).
# GOOS=linux     — explicit target OS for cross-compile safety.
# -ldflags "-s -w" — strip DWARF debug info and the symbol table to reduce
#                    binary size without affecting runtime behaviour.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -ldflags="-s -w" \
        -o /out/sequencer \
        ./cmd/sequencer

# --- Final Stage ---
# gcr.io/distroless/static-debian12 contains only the bare minimum needed to
# run a statically linked binary: CA certificates and timezone data.  It has
# no shell, no package manager, and no debugging utilities, which drastically
# reduces the attack surface.
FROM gcr.io/distroless/static-debian12

# Copy only the compiled binary from the build stage.
COPY --from=build /out/sequencer /sequencer

# Run as the pre-configured nonroot user (UID/GID 65532) so the container
# does not run as root even if the runtime security context is misconfigured.
USER 65532:65532

# Declare that the container is designed to run with a read-only root
# filesystem.  Enforce this at the runtime layer:
#   Docker:     docker run --read-only ...
#   Kubernetes: securityContext.readOnlyRootFilesystem: true
LABEL org.opencontainers.image.description="Olympus Go sequencer — distroless, read-only" \
      io.olympus.security.readonly-rootfs="required"

ENTRYPOINT ["/sequencer"]
