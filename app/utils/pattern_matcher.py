"""
Thin wrapper around the Rust ``olympus_matcher`` extension module.

This module provides a lazy-initialised default :class:`Matcher` instance
pre-loaded with Olympus built-in patterns.  Any FastAPI route that previously
called ``re.match`` / ``re.search`` on request-supplied (untrusted) input
should import :func:`get_default_matcher` instead.

The underlying ``regex`` crate uses a DFA/NFA hybrid that runs in guaranteed
linear time — immune to catastrophic backtracking (ReDoS) by design.

Build the extension first::

    cd verifiers/rust/olympus-matcher
    maturin develop --release

Example usage::

    from app.utils.pattern_matcher import get_default_matcher

    matcher = get_default_matcher()
    result = matcher.match_first(user_supplied_text)
    if result:
        print(f"Pattern '{result.pattern}' matched at {result.span}")
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from olympus_matcher import Matcher, MatchResult  # noqa: F401

_DEFAULT_MATCHER: "Matcher | None" = None


def get_default_matcher() -> "Matcher":
    """Return the lazily-initialised default :class:`Matcher`.

    The matcher is created once and reused for the lifetime of the process.
    Built-in Olympus patterns are registered on first access.

    Returns:
        A :class:`~olympus_matcher.Matcher` loaded with the built-in patterns.

    Raises:
        ImportError: if the ``olympus_matcher`` Rust extension has not been
            compiled and installed (run ``maturin develop --release``).
    """
    global _DEFAULT_MATCHER
    if _DEFAULT_MATCHER is None:
        from olympus_matcher import Matcher  # type: ignore[import]

        m = Matcher()
        # ── Built-in Olympus patterns ────────────────────────────────────────
        # Redaction marker: matches the literal token [REDACTED] in documents.
        m.add_pattern("redaction_marker", '"[REDACTED]"')
        # Document file references: PDF and DOCX attachments.
        m.add_pattern("doc_reference", "*.pdf|*.docx")
        # ────────────────────────────────────────────────────────────────────
        _DEFAULT_MATCHER = m
    return _DEFAULT_MATCHER
