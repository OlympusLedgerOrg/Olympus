"""
Runtime patches for third-party library vulnerabilities that have no upstream fix yet.

Each patch is documented with the corresponding CVE/advisory and should be removed
once an official patched release is available and pinned in requirements.txt.
"""

from __future__ import annotations


def _patch_pygments_adl_lexer_redos() -> None:
    """Patch CVE-2026-4539: Pygments AdlLexer ReDoS (GHSA-5239-wwwm-4pmq).

    Affected versions: Pygments <= 2.19.2 (no upstream fix released yet).

    Two patterns in ``pygments/lexers/archetype.py`` cause catastrophic
    backtracking for adversarial inputs:

    1. ``AdlLexer.tokens['metadata'][4]`` — GUID-matching regex with nested
       alternation groups inside repeated quantifiers.
    2. ``AtomsLexer.tokens['archetype_id'][0]`` — archetype-ID regex with
       ``\\w+`` inside nested optional quantifiers.

    Fix: wrap the outer quantified groups in atomic groups ``(?>...)``
    (requires Python 3.11+ / CPython ``re`` module).  Atomic groups prevent
    the regex engine from backtracking into an already-committed match,
    eliminating the exponential blow-up.

    Remove this patch once Pygments releases a version with a first_patched_version
    set in GHSA-5239-wwwm-4pmq.
    """
    try:
        import pygments.lexers.archetype as _archetype

        # --- Patch 1: GUID pattern in AdlLexer.tokens['metadata'] ---
        _GUID_VULN = r'(\d|[a-fA-F])+(-(\d|[a-fA-F])+){3,}'
        _GUID_SAFE = r'(?>[0-9a-fA-F]+)(-(?>[0-9a-fA-F]+)){3,}'

        # --- Patch 2: archetype-ID pattern in AtomsLexer.tokens['archetype_id'] ---
        _ARCH_VULN = (
            r'([ \t]*)(([a-zA-Z]\w+(\.[a-zA-Z]\w+)*::)?[a-zA-Z]\w+'
            r'(-[a-zA-Z]\w+){2}\.\w+[\w-]*\.v\d+(\.\d+){,2}((-[a-z]+)(\.\d+)?)?)'
        )
        # Atomic groups on the \w+ parts prevent catastrophic backtracking
        _ARCH_SAFE = (
            r'([ \t]*)((?:(?>[a-zA-Z]\w+)(?:\.(?>[a-zA-Z]\w+))*::)?'
            r'(?>[a-zA-Z]\w+)(?:-[a-zA-Z]\w+){2}\.\w+[\w-]*\.v\d+'
            r'(?:\.\d+){,2}(?:(?:-[a-z]+)(?:\.\d+)?)?)'
        )

        _REPLACEMENTS = [
            (_archetype.AdlLexer, 'metadata', _GUID_VULN, _GUID_SAFE),
            (_archetype.AtomsLexer, 'archetype_id', _ARCH_VULN, _ARCH_SAFE),
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
        pass  # Never break startup due to a patch failure


def apply_all() -> None:
    """Apply all runtime patches. Called once at application startup."""
    _patch_pygments_adl_lexer_redos()
