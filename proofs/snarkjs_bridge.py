"""
Persistent Node.js subprocess bridge for snarkjs Groth16 operations.

Follows the same persistent-process pattern as ``protocol/poseidon_js.py``:
a single ``node`` subprocess is spawned on first use and kept alive for the
lifetime of the Python interpreter.  All prove/verify calls go through
line-delimited JSON IPC, avoiding the per-call overhead of ``npx snarkjs``.

IPC protocol (line-delimited JSON):

  fullProve (witness generation + Groth16 proof in one step):
    → {"op":"fullProve","input":{...},"wasmFile":"/path","zkeyFile":"/path"}
    ← {"proof":{...},"publicSignals":[...]}

  prove (from pre-computed witness file):
    → {"op":"prove","witnessFile":"/path","zkeyFile":"/path"}
    ← {"proof":{...},"publicSignals":[...]}

  verify:
    → {"op":"verify","vkeyFile":"/path","proof":{...},"publicSignals":[...]}
    ← {"ok":true|false}
"""

from __future__ import annotations

import atexit
import collections
import functools
import json
import queue
import shutil
import subprocess  # nosec B404
import threading
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_SCRIPT = Path(__file__).resolve().parent / "snarkjs_node_helper.js"
_NODE_MODULES = _SCRIPT.parent / "node_modules"

_REQUEST_TIMEOUT = 120.0  # seconds (proof generation can be slow)


@functools.lru_cache(maxsize=1)
def _resolve_node_path() -> str:
    """Return absolute path to ``node`` binary or raise RuntimeError."""
    node_path = shutil.which("node")
    if node_path is None:
        raise RuntimeError(
            "snarkjs bridge requires Node.js on PATH. "
            "Install Node >= 18 or use the CLI fallback (snarkjs_bin='npx')."
        )
    return node_path


def _resolve_rapidsnark_path() -> str | None:
    """Return absolute path to the ``rapidsnark`` binary if available, else ``None``.

    Rapidsnark is an optional C++ native Groth16 prover (Mysten Labs fork) that
    is 5-10× faster than snarkjs for the prove step.  It uses the same ``.zkey``
    and ``.wtns`` files, making it a transparent drop-in for ``snarkjs groth16
    prove``.  The result is identical to snarkjs for the same witness inputs.

    Returns:
        Absolute path to ``rapidsnark``, or ``None`` if not installed.

    Example::

        if path := _resolve_rapidsnark_path():
            # Use rapidsnark for 5-10× faster proving
            subprocess.run([path, zkey, witness, proof_out, public_out])
        else:
            # Fall back to snarkjs bridge
            snarkjs_bridge.prove(witness_file=witness, zkey_file=zkey)
    """
    return shutil.which("rapidsnark")


# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

def _node_available() -> bool:
    """Return True if the ``node`` binary is on PATH."""
    try:
        _resolve_node_path()
    except RuntimeError:
        return False
    return True


def _check_prerequisites() -> None:
    """Raise RuntimeError if Node.js or proofs/node_modules is missing."""
    if not _node_available():
        raise RuntimeError(
            "snarkjs bridge requires Node.js on PATH. "
            "Install Node >= 18 or use the CLI fallback."
        )
    if not _SCRIPT.exists():
        raise RuntimeError(
            f"snarkjs helper script not found at {_SCRIPT}. "
            "Ensure proofs/snarkjs_node_helper.js is present in the repository."
        )
    if not _NODE_MODULES.is_dir():
        raise RuntimeError(
            f"proofs/node_modules not found at {_NODE_MODULES}. "
            "Run `npm install` inside the proofs/ directory first."
        )


# ---------------------------------------------------------------------------
# Persistent Node.js process
# ---------------------------------------------------------------------------
class _SnarkjsNodeProcess:
    """
    Long-lived Node.js subprocess for snarkjs Groth16 operations.

    Mirrors the design of ``protocol.poseidon_js._PoseidonNodeProcess``:
    - Single ``node`` process kept alive for interpreter lifetime
    - Line-delimited JSON on stdin/stdout
    - Daemon threads drain stdout and stderr
    - Thread lock serialises the write-flush-dequeue cycle

    Args:
        script: Path to the ``snarkjs_node_helper.js`` script.
        timeout: Seconds to wait for a response before raising RuntimeError.
    """

    def __init__(self, script: Path, *, timeout: float = _REQUEST_TIMEOUT) -> None:
        self._script = script
        self._timeout = timeout
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
        proc = subprocess.Popen(  # nosec B603 B607
            [_resolve_node_path(), str(self._script.resolve())],
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
            name="snarkjs-node-stdout",
        ).start()
        threading.Thread(
            target=self._stderr_reader,
            args=(proc,),
            daemon=True,
            name="snarkjs-node-stderr",
        ).start()

    def _stdout_reader(self, proc: subprocess.Popen[str]) -> None:
        """Daemon thread: move stdout lines into the response queue."""
        if proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                self._stdout_queue.put(line)
        finally:
            self._stdout_queue.put(None)  # EOF sentinel

    def _stderr_reader(self, proc: subprocess.Popen[str]) -> None:
        """Daemon thread: drain stderr into a ring buffer for diagnostics."""
        if proc.stderr is None:
            return
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

    def call(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Send one JSON request and return the parsed response.

        Uses compact ``json.dumps`` (no whitespace, no newlines) so the
        line protocol is not confused by control characters.

        Raises:
            RuntimeError: On Node.js error, process exit, or timeout.
        """
        line = json.dumps(payload, separators=(",", ":")) + "\n"

        with self._lock:
            self._ensure_alive()
            if self._proc is None or self._proc.stdin is None:
                raise RuntimeError("snarkjs node process unavailable after _ensure_alive")

            try:
                self._proc.stdin.write(line)
                self._proc.stdin.flush()
            except BrokenPipeError as exc:
                raise RuntimeError(
                    f"snarkjs node process closed unexpectedly.\nstderr:\n{self._last_stderr()}"
                ) from exc

            try:
                response_line = self._stdout_queue.get(timeout=self._timeout)
            except queue.Empty as exc:
                raise RuntimeError(
                    f"snarkjs node process timed out after {self._timeout}s.\n"
                    f"stderr:\n{self._last_stderr()}"
                ) from exc

            if response_line is None:
                raise RuntimeError(
                    f"snarkjs node process exited unexpectedly.\n"
                    f"stderr:\n{self._last_stderr()}"
                )

            result: dict[str, Any] = json.loads(response_line)
            if "error" in result:
                raise RuntimeError(f"snarkjs error: {result['error']}")
            return result

    @property
    def alive(self) -> bool:
        """Return True if the Node.js process is currently running."""
        return self._proc is not None and self._proc.poll() is None

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
                    "Error during snarkjs node shutdown; killing process",
                    exc_info=True,
                )
                proc.kill()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_node_process: _SnarkjsNodeProcess | None = None
_init_lock = threading.Lock()


def _get_process() -> _SnarkjsNodeProcess:
    """Return the module-level singleton, creating it on first call."""
    global _node_process  # noqa: PLW0603
    if _node_process is None:
        with _init_lock:
            if _node_process is None:
                _node_process = _SnarkjsNodeProcess(_SCRIPT)
    return _node_process


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def bridge_available() -> bool:
    """Return True if Node.js and snarkjs dependencies are available."""
    return _node_available() and _SCRIPT.exists() and _NODE_MODULES.is_dir()


def full_prove(
    *,
    input_signals: dict[str, Any],
    wasm_file: Path,
    zkey_file: Path,
) -> tuple[dict[str, Any], list[Any]]:
    """
    Generate a Groth16 witness and proof in one step.

    Combines witness generation (from circuit inputs + WASM) and proof
    generation (with the proving key) in a single snarkjs ``fullProve`` call.

    Args:
        input_signals: Circuit input signals (JSON-serialisable dict).
        wasm_file: Path to the circuit's WASM witness generator.
        zkey_file: Path to the circuit's proving key (.zkey).

    Returns:
        Tuple of ``(proof_dict, public_signals_list)``.

    Raises:
        RuntimeError: If Node.js, snarkjs, or the helper is unavailable.
        FileNotFoundError: If wasm_file or zkey_file does not exist.
    """
    if not wasm_file.exists():
        raise FileNotFoundError(f"WASM file not found: {wasm_file}")
    if not zkey_file.exists():
        raise FileNotFoundError(f"ZKey file not found: {zkey_file}")

    result = _get_process().call({
        "op": "fullProve",
        "input": input_signals,
        "wasmFile": str(wasm_file.resolve()),
        "zkeyFile": str(zkey_file.resolve()),
    })
    return result["proof"], result["publicSignals"]


def prove(
    *,
    witness_file: Path,
    zkey_file: Path,
) -> tuple[dict[str, Any], list[Any]]:
    """
    Generate a Groth16 proof from a pre-computed witness.

    Args:
        witness_file: Path to the witness file (.wtns).
        zkey_file: Path to the circuit's proving key (.zkey).

    Returns:
        Tuple of ``(proof_dict, public_signals_list)``.

    Raises:
        RuntimeError: If Node.js, snarkjs, or the helper is unavailable.
        FileNotFoundError: If witness_file or zkey_file does not exist.
    """
    if not witness_file.exists():
        raise FileNotFoundError(f"Witness file not found: {witness_file}")
    if not zkey_file.exists():
        raise FileNotFoundError(f"ZKey file not found: {zkey_file}")

    result = _get_process().call({
        "op": "prove",
        "witnessFile": str(witness_file.resolve()),
        "zkeyFile": str(zkey_file.resolve()),
    })
    return result["proof"], result["publicSignals"]


def verify(
    *,
    vkey_file: Path,
    proof: dict[str, Any],
    public_signals: list[Any],
) -> bool:
    """
    Verify a Groth16 proof.

    Args:
        vkey_file: Path to the verification key JSON file.
        proof: Groth16 proof object (dict).
        public_signals: Public signals list.

    Returns:
        True if the proof is valid, False otherwise.

    Raises:
        RuntimeError: If Node.js, snarkjs, or the helper is unavailable.
        FileNotFoundError: If vkey_file does not exist.
    """
    if not vkey_file.exists():
        raise FileNotFoundError(f"Verification key not found: {vkey_file}")

    result = _get_process().call({
        "op": "verify",
        "vkeyFile": str(vkey_file.resolve()),
        "proof": proof,
        "publicSignals": public_signals,
    })
    return bool(result.get("ok", False))
