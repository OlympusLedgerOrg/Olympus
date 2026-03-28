"""
Runtime patches for third-party library vulnerabilities that have no upstream fix yet.

Each patch is documented with the corresponding CVE/advisory and should be removed
once an official patched release is available and pinned in requirements.txt.

Architecture (two-step for CVE-2026-4539):
  Step 1 — ``_patch_pygments_atomic_groups()``:  Rewrites the vulnerable patterns
    in ``AdlLexer.tokens`` / ``AtomsLexer.tokens`` using Python ``re`` atomic
    groups ``(?>…)`` before Pygments compiles them.  This alone gives a partial
    fix (still O(n²) for the archetype-ID pattern at large n, but no longer
    pathological exponential blow-up).

  Step 2 — ``_patch_pygments_rust_bridge()``:  If the ``olympus_core`` Rust
    extension is available (built with ``maturin develop`` or installed as a
    wheel), the already-compiled ``_tokens`` match functions for both patterns
    are replaced with Rust-backed wrappers.  Rust's ``regex`` crate uses a DFA
    that scans each character exactly once, giving a strict O(n) guarantee.
    The application falls back gracefully to Step 1 if the extension is absent.
"""

from __future__ import annotations

import logging


_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

# Vulnerable originals (as they appear in Pygments 2.19.2)
_GUID_VULN = r'(\d|[a-fA-F])+(-(\d|[a-fA-F])+){3,}'
_ARCH_VULN = (
    r'([ \t]*)(([a-zA-Z]\w+(\.[a-zA-Z]\w+)*::)?[a-zA-Z]\w+'
    r'(-[a-zA-Z]\w+){2}\.\w+[\w-]*\.v\d+(\.\d+){,2}((-[a-z]+)(\.\d+)?)?)'
)

# Safe replacements used by Step 1 (atomic groups, Python 3.11+ re)
_GUID_ATOMIC = r'(?>[0-9a-fA-F]+)(-(?>[0-9a-fA-F]+)){3,}'
_ARCH_ATOMIC = (
    r'([ \t]*)((?:(?>[a-zA-Z]\w+)(?:\.(?>[a-zA-Z]\w+))*::)?'
    r'(?>[a-zA-Z]\w+)(?:-[a-zA-Z]\w+){2}\.\w+[\w-]*\.v\d+'
    r'(?:\.\d+){,2}(?:(?:-[a-z]+)(?:\.\d+)?)?)'
)


# ---------------------------------------------------------------------------
# Step 1: atomic-group patch (pure Python, no Rust required)
# ---------------------------------------------------------------------------

def _patch_pygments_atomic_groups() -> None:
    """Patch CVE-2026-4539 using Python re atomic groups (GHSA-5239-wwwm-4pmq).

    Affected versions: Pygments <= 2.19.2 (no upstream fix released yet).

    Two patterns in ``pygments/lexers/archetype.py`` cause catastrophic
    backtracking for adversarial inputs:

    1. ``AdlLexer.tokens['metadata'][4]`` — GUID regex with nested alternation
       groups inside repeated quantifiers.
    2. ``AtomsLexer.tokens['archetype_id'][0]`` — archetype-ID regex with
       ``\\w+`` inside nested optional quantifiers.

    Fix: wrap the quantified groups in atomic groups ``(?>…)`` (Python 3.11+).
    Atomic groups prevent the regex engine from backtracking into a committed
    match, eliminating the exponential blow-up.  Step 2 replaces these with the
    fully O(n) Rust engine when available.

    Remove this patch once Pygments releases a patched version.
    """
    try:
        import pygments.lexers.archetype as _archetype  # type: ignore[import-not-found]

        _REPLACEMENTS = [
            (_archetype.AdlLexer,    'metadata',     _GUID_VULN, _GUID_ATOMIC),
            (_archetype.AtomsLexer,  'archetype_id', _ARCH_VULN, _ARCH_ATOMIC),
        ]

        for klass, state, vuln, safe in _REPLACEMENTS:
            # Guard: skip if _tokens already compiled for this class
            if '_tokens' in klass.__dict__:
                continue
            rules = klass.tokens.get(state)
            if not rules:
                continue
            new_rules = []
            for rule in rules:
                if isinstance(rule, tuple) and len(rule) >= 2 and rule[0] == vuln:
                    rule = (safe,) + rule[1:]
                new_rules.append(rule)
            klass.tokens[state] = new_rules

    except Exception:
        _log.debug(
            "Atomic-group patch for CVE-2026-4539 failed to apply; "
            "Pygments AdlLexer may remain vulnerable.",
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Step 2: Rust bridge (olympus_core) - O(n) DFA replacement

def _patch_pygments_rust_bridge() -> None:
    """Replace atomic-group patterns with Rust O(n) matchers (CVE-2026-4539).

    Requires the ``olympus_core`` extension (``maturin develop`` or wheel).
    Falls back silently to the Step-1 atomic-group patch when unavailable.

    The bridge replaces the compiled ``re.Pattern.match`` functions stored in
    ``AdlLexer._tokens`` with thin Python callables that delegate to
    ``AdlScanner.match_guid()`` / ``AdlScanner.match_archetype_id()``.
    Rust's ``regex`` crate is DFA-based; it cannot backtrack and processes each
    character exactly once regardless of input structure.
    """
    try:
        from olympus_core import AdlScanner  # type: ignore[import-not-found]
    except ImportError:
        return  # Extension not built; atomic-group patch remains active.
    except Exception:
        return

    try:
        from pygments.lexers.archetype import AdlLexer

        scanner = AdlScanner()

        # ------------------------------------------------------------------ #
        # Minimal re.Match surrogate — supports group(), start(), end(),      #
        # groups().  Satisfies both simple token actions and bygroups().       #
        # ------------------------------------------------------------------ #
        class _RustMatch:
            """Lightweight re.Match-compatible wrapper around Rust match spans."""

            __slots__ = ("_text", "_spans")

            def __init__(self, text: str, spans: list) -> None:
                # spans[0] = (start, end) for the full match (group 0).
                # spans[i] = (start, end) or None for capture group i (i >= 1).
                self._text = text
                self._spans = spans

            def group(self, n: int = 0) -> str | None:
                if n >= len(self._spans):
                    return None
                span = self._spans[n]
                return self._text[span[0] : span[1]] if span is not None else None

            def start(self, n: int = 0) -> int:
                if n >= len(self._spans):
                    return -1
                span = self._spans[n]
                return span[0] if span is not None else -1

            def end(self, n: int = 0) -> int:
                if n >= len(self._spans):
                    return -1
                span = self._spans[n]
                return span[1] if span is not None else -1

            def groups(self) -> tuple:
                return tuple(
                    (self._text[s[0] : s[1]] if s is not None else None)
                    for s in self._spans[1:]
                )

        # ------------------------------------------------------------------ #
        # Rust-backed match functions (same call signature as re.Pattern.match) #
        # ------------------------------------------------------------------ #
        def _guid_match(text: str, pos: int = 0) -> _RustMatch | None:
            result = scanner.match_guid(text, pos)
            if result is None:
                return None
            start, end = result
            return _RustMatch(text, [(start, end)])

        def _arch_match(text: str, pos: int = 0) -> _RustMatch | None:
            spans = scanner.match_archetype_id(text, pos)
            if spans is None:
                return None
            return _RustMatch(text, spans)

        # ------------------------------------------------------------------ #
        # Force _tokens to be compiled (it's built lazily on first            #
        # instantiation; we trigger it here so the bridge is immediately       #
        # active for all subsequent uses).                                      #
        # ------------------------------------------------------------------ #
        if "_tokens" not in AdlLexer.__dict__:
            _dummy = AdlLexer()
            del _dummy

        # ------------------------------------------------------------------ #
        # Walk every state in _tokens and replace the two vulnerable compiled  #
        # match functions with their Rust-backed equivalents.  We identify      #
        # them by the pattern string on the underlying re.Pattern object.       #
        # ------------------------------------------------------------------ #
        for state in list(AdlLexer._tokens.keys()):
            new_rules = []
            for rexmatch, action, new_state in AdlLexer._tokens[state]:
                try:
                    pattern = rexmatch.__self__.pattern
                except AttributeError:
                    # rexmatch is not a bound re.Pattern.match method
                    new_rules.append((rexmatch, action, new_state))
                    continue

                if pattern == _GUID_ATOMIC:
                    new_rules.append((_guid_match, action, new_state))
                elif pattern == _ARCH_ATOMIC:
                    new_rules.append((_arch_match, action, new_state))
                else:
                    new_rules.append((rexmatch, action, new_state))
            AdlLexer._tokens[state] = new_rules

    except Exception:
        _log.warning(
            "Rust bridge for CVE-2026-4539 failed to initialise; "
            "falling back to atomic-group Python patch.",
            exc_info=True,
        )
# ---------------------------------------------------------------------------

def apply_all() -> None:
    """Apply all runtime patches.  Called once at application startup."""
    _patch_pygments_atomic_groups()   # Step 1: fix tokens dict source
    _patch_pygments_rust_bridge()     # Step 2: upgrade to Rust O(n) engine
