# olympus-matcher

DFA-based pattern matcher for Olympus, exposed to Python via PyO3.

Uses Rust's [`regex`](https://docs.rs/regex) crate which employs a DFA/NFA
hybrid guaranteeing **linear-time matching** — immune to ReDoS by design.
No `unsafe` blocks.

## Features

- `Matcher` class with named, compiled patterns
- ADL (Olympus pattern mini-language) compiler
- Raw regex bypass for pre-validated patterns
- Full capture-group support
- `MatchResult` with span and capture fields

## Build

```sh
cd verifiers/rust/olympus-matcher
maturin develop --release
```

Requires:
- Rust 1.70+ (`rustup update stable`)
- `maturin` (`pip install maturin`)

## Quick test

```python
from olympus_matcher import Matcher

m = Matcher()
m.add_pattern("redaction_marker", '"[REDACTED]"')
m.add_pattern("doc_reference", "*.pdf|*.docx")

result = m.match_first("The file report.pdf is [REDACTED]")
print(result)  # MatchResult(matched=True, pattern='doc_reference', span=...)
```

## Running tests

```sh
cargo test
```

## Running benchmarks

```sh
cargo bench
```
