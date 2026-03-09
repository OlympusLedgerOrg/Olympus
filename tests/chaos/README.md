# Chaos Engineering Suite — Expected System Behaviour

This directory contains automated fault-injection tests for the Olympus ledger.
Each test simulates a specific failure mode and verifies that the system degrades
gracefully while preserving ledger integrity.

---

## Test Coverage

| Module | Fault | Expected behaviour |
|--------|-------|--------------------|
| `test_disk_full.py` | Storage write fails (simulated `OSError: No space left`) | In-memory operations succeed; write-through failure surfaces as a clear error; no partial/corrupt entries |
| `test_network_partition.py` | Remote TSA / guardian node unreachable | Local commit succeeds; RFC 3161 timestamping degrades gracefully; SMT divergence counter increments |
| `test_clock_skew.py` | System clock returns a timestamp far in the past or future | Timestamps are accepted; ISO 8601 serialisation is unaffected; chain ordering relies on hash linkage, not wall time |
| `test_db_connection_loss.py` | PostgreSQL connection pool exhausted or refuses connections | API returns HTTP 503 with structured error; existing chain is not modified; retry with exponential backoff fires |

---

## Running the Chaos Suite

The chaos tests do **not** require a live PostgreSQL instance; they use monkeypatching
and mock objects to inject failures without external dependencies:

```bash
pytest tests/chaos/ -v
```

To include them in the full test run:

```bash
pytest tests/ -v --tb=short -m "not postgres"
```

---

## Fault Injection Philosophy

Olympus is an append-only ledger — the primary invariant under all fault conditions is:

> **No committed entry may be silently lost, modified, or left in an inconsistent state.**

Each test verifies three properties:

1. **Graceful degradation** — the system returns a structured error or degrades to a
   reduced-capability mode rather than crashing.
2. **Chain integrity** — any entries committed before the fault was injected remain
   verifiable via `Ledger.verify_chain()`.
3. **Observable failure** — the fault is surfaced via a log message, HTTP error, or
   Prometheus counter so operators can detect it.

---

## Adding New Fault Scenarios

1. Add a new `test_<fault>.py` file in this directory.
2. Use `pytest.MonkeyPatch` or `unittest.mock.patch` to inject the fault.
3. Assert the three properties above (graceful degradation, chain integrity,
   observable failure).
4. Update the table in this README with the new entry.
