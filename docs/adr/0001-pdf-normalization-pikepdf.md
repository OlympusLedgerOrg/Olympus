# ADR 0001: PDF Normalization via pikepdf (v1.3.0-pikepdf-linearized)

## Context
- Olympus needs byte-stable PDF canonicalization.
- Prior approach used regex-based metadata stripping without structural guarantees.
- Requirements: remove volatile metadata, linearize structure, and pin a deterministic version.

## Decision
- Use `pikepdf` (v9.4.1) for PDF normalization.
- Strip volatile info dictionary keys (CreationDate, ModDate, Producer, Creator, Title, Subject, Author, Keywords) and clear XMP metadata.
- Save PDFs with `static_id=True` and `linearize=True` plus LF line endings to enforce deterministic byte order.
- Canonicalizer version pinned to `1.3.0-pikepdf-linearized`.

## Alternatives Considered
- Apache PDFBox via JVM bridge: more dependencies, heavier runtime, less natural for Python stack.
- Regex-only scrub (previous): insufficient structural normalization and fragile to PDF variants.

## Consequences
- Introduces a new pinned dependency (`pikepdf==9.4.1`).
- Deterministic, idempotent PDF hashes across runs and platforms.
- Requires libqpdf (bundled with manylinux wheel) but no JVM runtime.
