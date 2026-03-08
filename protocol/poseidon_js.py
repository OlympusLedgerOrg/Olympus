"""
JS-backed Poseidon helper for Olympus.

Invokes a **persistent** Node.js subprocess (``proofs/poseidon_node_helper.js``)
to compute Poseidon hashes using circomlibjs, ensuring bit-for-bit parity with
the circom circuit parameters.

The module is opt-in: set the environment variable

    OLY_POSEIDON_BACKEND=js

to route ``_poseidon_hash_pairs`` calls in ``protocol.poseidon_tree`` through
this backend.  The default (``py``) continues to use poseidon_py and requires
no Node.js installation.

Performance
-----------
A single ``node`` process is started lazily on the first hash request and kept
alive for the lifetime of the Python interpreter.  V8 + circomlibjs start-up
cost is paid once per Python process regardless of tree size or call count.
Communication uses line-delimited JSON on stdin/stdout — the fastest IPC
mechanism available without native bindings.

For a depth-20 Merkle tree the JS backend makes exactly 20 round-trips over
the persistent pipe (one per level via ``batch_hash2``), compared to 20
process spawns in a naive per-call design.

Security
--------
* ``subprocess.Popen`` is invoked with a list — no shell injection is possible.
* All payloads go through ``json.dumps`` with ``separators=(',', ':')`` so no
  control characters (including newlines) appear in the request line.
* ``stderr`` is drained by a daemon thread to prevent the child from blocking
  on a full pipe buffer.
* ``atexit`` ensures the child is terminated when the interpreter exits.
* Reads use ``queue.get(timeout=...)`` so a hung Node process is detected.
* If the process dies it is restarted transparently on the next call.

IPC protocol (line-delimited JSON, all integers as decimal strings):

  Single pair:
    request  : {"op":"hash2","a":"<int>","b":"<int>"}
    response : {"out":"<int>"}

  Batch pairs (preferred — one round-trip per tree level):
    request  : {"op":"batch_hash2","pairs":[{"a":"<int>","b":"<int>"},...]}
    response : {"outs":["<int>",...]}

  Full Merkle root:
    request  : {"op":"merkle_root","leaves":["<int>",...][,"depth":N]}
    response : {"out":"<int>"}
"""

from __future__ import annotations

import atexit
import collections
import json
import os
import queue
import shutil
import subprocess
import threading
from pathlib import Path


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_SCRIPT = Path(__file__).parent.parent / "proofs" / "poseidon_node_helper.js"
_NODE_MODULES = _SCRIPT.parent / "node_modules"

_REQUEST_TIMEOUT = 30.0  # seconds


# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
def _node_available() -> bool:
    """Return True if the ``node`` binary is on PATH."""
    return shutil.which("node") is not None


def _check_prerequisites() -> None:
    """Raise RuntimeError if Node.js or node_modules is missing."""
    if not _node_available():
        raise RuntimeError(
            "OLY_POSEIDON_BACKEND=js requires Node.js on PATH. "
            "Install Node >= 18 or switch back to the default Python backend."
        )
    if not _SCRIPT.exists():
        raise RuntimeError(
            f"Node helper script not found at {_SCRIPT}. "
            "Ensure proofs/poseidon_node_helper.js is present in the repository."
        )
    if not _NODE_MODULES.is_dir():
        raise RuntimeError(
            f"proofs/node_modules not found at {_NODE_MODULES}. "
            "Run `npm install` inside the proofs/ directory first."
        )


# ---------------------------------------------------------------------------
# Persistent Node.js process
# ---------------------------------------------------------------------------
class _PoseidonNodeProcess:
    """
    Long-lived Node.js subprocess for circomlibjs Poseidon computations.

    Keeps a single ``node`` process alive for the interpreter lifetime.
    Communication is via line-delimited JSON on stdin/stdout.  Two daemon
    threads drain stdout and stderr respectively so the child never blocks
    on full pipe buffers.

    Thread safety: a ``threading.Lock`` serialises the write-flush-dequeue
    cycle so concurrent callers cannot interleave their requests.
    """

    def __init__(self, script: Path) -> None:
        self._script = script
        self._proc: subprocess.Popen[str] | None = None
        self._stdout_queue: queue.Queue[str | None] = queue.Queue()
        self._stderr_buf: collections.deque[str] = collections.deque(maxlen=50)
        self._lock = threading.Lock()
        atexit.register(self._shutdown)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _start(self) -> None:
        """Spawn a fresh Node.js process and start reader threads."""
        _check_prerequisites()
        self._stdout_queue = queue.Queue()
        self._stderr_buf.clear()
        proc = subprocess.Popen(
            ["node", str(self._script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._proc = proc

        threading.Thread(
            target=self._stdout_reader,
            args=(proc,),
            daemon=True,
            name="poseidon-node-stdout",
        ).start()
        threading.Thread(
            target=self._stderr_reader,
            args=(proc,),
            daemon=True,
            name="poseidon-node-stderr",
        ).start()

    def _stdout_reader(self, proc: subprocess.Popen[str]) -> None:
        """Daemon thread: move stdout lines into the response queue."""
        assert proc.stdout
        try:
            for line in proc.stdout:
                self._stdout_queue.put(line)
        finally:
            self._stdout_queue.put(None)  # EOF sentinel

    def _stderr_reader(self, proc: subprocess.Popen[str]) -> None:
        """Daemon thread: drain stderr into a ring buffer for diagnostics."""
        assert proc.stderr
        for line in proc.stderr:
            self._stderr_buf.append(line.rstrip())

    def _ensure_alive(self) -> None:
        """Start (or restart) the process if it is not running."""
        if self._proc is None or self._proc.poll() is not None:
            self._start()

    def _last_stderr(self) -> str:
        return "\n".join(self._stderr_buf) if self._stderr_buf else "(no stderr output)"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def call(self, payload: dict) -> dict:
        """
        Send one JSON request and return the parsed response.

        Uses compact ``json.dumps`` (no whitespace, no newlines in values)
        so the line protocol is not confused by control characters.

        Raises:
            RuntimeError: On Node.js error, process exit, or timeout.
        """
        # Compact separators ensure the payload fits on a single line;
        # json.dumps also escapes all control characters in string values.
        line = json.dumps(payload, separators=(",", ":")) + "\n"

        with self._lock:
            self._ensure_alive()
            assert self._proc and self._proc.stdin  # guaranteed by _ensure_alive

            try:
                self._proc.stdin.write(line)
                self._proc.stdin.flush()
            except BrokenPipeError as exc:
                raise RuntimeError(
                    f"Node Poseidon process closed unexpectedly.\nstderr:\n{self._last_stderr()}"
                ) from exc

            try:
                response_line = self._stdout_queue.get(timeout=_REQUEST_TIMEOUT)
            except queue.Empty as exc:
                raise RuntimeError(
                    f"Node Poseidon process timed out after {_REQUEST_TIMEOUT}s. "
                    f"stderr:\n{self._last_stderr()}"
                ) from exc

            if response_line is None:
                raise RuntimeError(
                    f"Node Poseidon process exited unexpectedly.\nstderr:\n{self._last_stderr()}"
                )

            result: dict = json.loads(response_line)
            if "error" in result:
                raise RuntimeError(f"Node Poseidon error: {result['error']}")
            return result

    def _shutdown(self) -> None:
        """Terminate the Node.js process cleanly on interpreter shutdown."""
        import logging

        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                logging.getLogger(__name__).debug(
                    "Error during poseidon node shutdown; killing process",
                    exc_info=True,
                )
                proc.kill()


# Module-level singleton — created lazily on first use.
_node_process: _PoseidonNodeProcess | None = None
_init_lock = threading.Lock()


def _get_process() -> _PoseidonNodeProcess:
    """Return the module-level singleton, creating it on first call."""
    global _node_process
    if _node_process is None:
        with _init_lock:
            if _node_process is None:
                _node_process = _PoseidonNodeProcess(_SCRIPT)
    return _node_process


def _run_node(payload: dict) -> dict:
    """Send one JSON request to the persistent Node process and return the response."""
    return _get_process().call(payload)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def batch_compute_poseidon2(pairs: list[tuple[int, int]]) -> list[int]:
    """
    Compute Poseidon(a, b) for multiple pairs in a single IPC round-trip.

    All pairs are hashed in one ``batch_hash2`` round-trip to the persistent
    Node.js process.  For a depth-N Merkle tree this means one IPC call per
    level regardless of width — O(N) total round-trips for the full tree.

    Args:
        pairs: List of ``(a, b)`` tuples of BN128 field element integers.

    Returns:
        List of Poseidon hashes (one per pair), reduced mod SNARK_SCALAR_FIELD.

    Raises:
        RuntimeError: If Node.js or proofs/node_modules is unavailable.
    """
    if not pairs:
        return []
    payload = {
        "op": "batch_hash2",
        "pairs": [{"a": str(a), "b": str(b)} for a, b in pairs],
    }
    return [int(v) for v in _run_node(payload)["outs"]]


def compute_poseidon2(a: int, b: int) -> int:
    """
    Compute Poseidon(a, b) via circomlibjs, returning an in-field int.

    Delegates to :func:`batch_compute_poseidon2` (single-item batch) so
    the Node process is always reached through the same code path.

    Args:
        a: First BN128 field element (integer).
        b: Second BN128 field element (integer).

    Returns:
        Poseidon hash as a Python int, reduced mod SNARK_SCALAR_FIELD.

    Raises:
        RuntimeError: If Node.js or proofs/node_modules is unavailable.
    """
    return batch_compute_poseidon2([(a, b)])[0]


def compute_poseidon_merkle_root(leaves: list[int], depth: int | None = None) -> str:
    """
    Compute a full Poseidon Merkle root via circomlibjs in a single round-trip.

    Pads to ``2**depth`` zeros when *depth* is given; otherwise duplicates
    the last leaf on odd counts (matching the Python backend convention).

    Args:
        leaves: List of BN128 field elements as Python ints.
        depth:  Optional fixed tree depth.

    Returns:
        Decimal string representation of the Merkle root.

    Raises:
        RuntimeError: If Node.js or proofs/node_modules is unavailable.
    """
    payload: dict = {"op": "merkle_root", "leaves": [str(v) for v in leaves]}
    if depth is not None:
        payload["depth"] = depth
    return _run_node(payload)["out"]


def backend_enabled() -> bool:
    """Return True when ``OLY_POSEIDON_BACKEND=js`` is set in the environment."""
    return os.environ.get("OLY_POSEIDON_BACKEND", "py").lower() == "js"
