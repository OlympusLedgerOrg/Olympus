"""
Unit tests for protocol/poseidon_js.py without a live Node.js process.

All subprocess interactions are mocked.  Tests cover:
  * _resolve_node_path / _node_available
  * _check_prerequisites (error branches)
  * _PoseidonNodeProcess._validate_field_value
  * _PoseidonNodeProcess._validate_payload
  * _PoseidonNodeProcess.call (happy path + error branches)
  * _PoseidonNodeProcess._shutdown
  * _get_process singleton
  * _run_node
  * batch_compute_poseidon2
  * compute_poseidon2
  * compute_poseidon_merkle_root
  * backend_enabled
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import protocol.poseidon_js as pjs


# ---------------------------------------------------------------------------
# _resolve_node_path / _node_available
# ---------------------------------------------------------------------------


class TestResolveNodePath:
    def test_raises_when_node_not_on_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pjs._resolve_node_path.cache_clear()
        monkeypatch.setattr("shutil.which", lambda _: None)
        with pytest.raises(RuntimeError, match="OLY_POSEIDON_BACKEND=js requires Node"):
            pjs._resolve_node_path()
        pjs._resolve_node_path.cache_clear()

    def test_returns_path_when_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pjs._resolve_node_path.cache_clear()
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/node")
        path = pjs._resolve_node_path()
        assert path == "/usr/bin/node"
        pjs._resolve_node_path.cache_clear()


class TestNodeAvailable:
    def test_returns_false_when_node_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pjs._resolve_node_path.cache_clear()
        monkeypatch.setattr("shutil.which", lambda _: None)
        assert pjs._node_available() is False
        pjs._resolve_node_path.cache_clear()

    def test_returns_true_when_node_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pjs._resolve_node_path.cache_clear()
        monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/node")
        assert pjs._node_available() is True
        pjs._resolve_node_path.cache_clear()


# ---------------------------------------------------------------------------
# _check_prerequisites
# ---------------------------------------------------------------------------


class TestCheckPrerequisites:
    def test_raises_when_node_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pjs._resolve_node_path.cache_clear()
        monkeypatch.setattr("shutil.which", lambda _: None)
        with pytest.raises(RuntimeError, match="requires Node.js"):
            pjs._check_prerequisites()
        pjs._resolve_node_path.cache_clear()

    def test_raises_when_script_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pjs._resolve_node_path.cache_clear()
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/node")
        mock_script = MagicMock(spec=Path)
        mock_script.exists.return_value = False
        mock_script.resolve.return_value = mock_script
        monkeypatch.setattr(pjs, "_SCRIPT", mock_script)
        with pytest.raises(RuntimeError, match="Node helper script not found"):
            pjs._check_prerequisites()
        pjs._resolve_node_path.cache_clear()

    def test_raises_when_node_modules_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pjs._resolve_node_path.cache_clear()
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/node")
        mock_script = MagicMock(spec=Path)
        mock_script.exists.return_value = True
        mock_modules = MagicMock(spec=Path)
        mock_modules.is_dir.return_value = False
        monkeypatch.setattr(pjs, "_SCRIPT", mock_script)
        monkeypatch.setattr(pjs, "_NODE_MODULES", mock_modules)
        with pytest.raises(RuntimeError, match="proofs/node_modules not found"):
            pjs._check_prerequisites()
        pjs._resolve_node_path.cache_clear()


# ---------------------------------------------------------------------------
# _PoseidonNodeProcess._validate_field_value
# ---------------------------------------------------------------------------


class TestValidateFieldValue:
    def setup_method(self) -> None:
        self.proc = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))

    def test_valid_decimal_string(self) -> None:
        self.proc._validate_field_value("12345", field="a")  # must not raise

    def test_zero_string(self) -> None:
        self.proc._validate_field_value("0", field="a")  # must not raise

    def test_non_string_raises(self) -> None:
        with pytest.raises(ValueError, match="decimal string"):
            self.proc._validate_field_value(12345, field="a")

    def test_non_decimal_string_raises(self) -> None:
        with pytest.raises(ValueError, match="decimal string"):
            self.proc._validate_field_value("0xabc", field="a")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError, match="decimal string"):
            self.proc._validate_field_value("", field="a")

    def test_negative_string_raises(self) -> None:
        with pytest.raises(ValueError, match="decimal string"):
            self.proc._validate_field_value("-1", field="a")


# ---------------------------------------------------------------------------
# _PoseidonNodeProcess._validate_payload
# ---------------------------------------------------------------------------


class TestValidatePayload:
    def setup_method(self) -> None:
        self.proc = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))

    def test_hash2_valid(self) -> None:
        self.proc._validate_payload({"op": "hash2", "a": "1", "b": "2"})

    def test_hash2_bad_a_raises(self) -> None:
        with pytest.raises(ValueError, match="decimal string"):
            self.proc._validate_payload({"op": "hash2", "a": "x", "b": "2"})

    def test_hash2_bad_b_raises(self) -> None:
        with pytest.raises(ValueError, match="decimal string"):
            self.proc._validate_payload({"op": "hash2", "a": "1", "b": None})

    def test_batch_hash2_valid(self) -> None:
        self.proc._validate_payload({"op": "batch_hash2", "pairs": [{"a": "1", "b": "2"}]})

    def test_batch_hash2_empty_pairs_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            self.proc._validate_payload({"op": "batch_hash2", "pairs": []})

    def test_batch_hash2_non_list_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            self.proc._validate_payload({"op": "batch_hash2", "pairs": None})

    def test_batch_hash2_pair_not_dict_raises(self) -> None:
        with pytest.raises(ValueError, match="must be a dict"):
            self.proc._validate_payload({"op": "batch_hash2", "pairs": [["1", "2"]]})

    def test_batch_hash2_bad_pair_field_raises(self) -> None:
        with pytest.raises(ValueError, match="decimal string"):
            self.proc._validate_payload({"op": "batch_hash2", "pairs": [{"a": "abc", "b": "1"}]})

    def test_merkle_root_valid(self) -> None:
        self.proc._validate_payload({"op": "merkle_root", "leaves": ["1", "2", "3"]})

    def test_merkle_root_with_depth(self) -> None:
        self.proc._validate_payload({"op": "merkle_root", "leaves": ["1"], "depth": 4})

    def test_merkle_root_empty_leaves_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            self.proc._validate_payload({"op": "merkle_root", "leaves": []})

    def test_merkle_root_non_list_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            self.proc._validate_payload({"op": "merkle_root", "leaves": None})

    def test_merkle_root_invalid_depth_raises(self) -> None:
        with pytest.raises(ValueError, match="depth must be an integer"):
            self.proc._validate_payload({"op": "merkle_root", "leaves": ["1"], "depth": "5"})

    def test_invalid_op_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported poseidon_js op"):
            self.proc._validate_payload({"op": "evil_op"})

    def test_non_dict_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="must be a dictionary"):
            self.proc._validate_payload(["not", "a", "dict"])  # type: ignore[arg-type]

    def test_none_op_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported poseidon_js op"):
            self.proc._validate_payload({"op": None})


# ---------------------------------------------------------------------------
# _PoseidonNodeProcess.call – mocked subprocess
# ---------------------------------------------------------------------------


def _make_mocked_process(response_json: str | None = None) -> pjs._PoseidonNodeProcess:
    """Return a _PoseidonNodeProcess with a mocked internal process."""
    proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None  # process is alive
    mock_proc.stdin = MagicMock()
    proc_instance._proc = mock_proc
    if response_json is not None:
        proc_instance._stdout_queue.put(response_json + "\n")
    return proc_instance


class TestPoseidonNodeProcessCall:
    def test_successful_hash2_call(self) -> None:
        proc_instance = _make_mocked_process('{"out":"99"}')
        result = proc_instance.call({"op": "hash2", "a": "1", "b": "2"})
        assert result == {"out": "99"}

    def test_error_in_response_raises(self) -> None:
        proc_instance = _make_mocked_process('{"error":"compute failed"}')
        with pytest.raises(RuntimeError, match="Node Poseidon error"):
            proc_instance.call({"op": "hash2", "a": "1", "b": "2"})

    def test_none_sentinel_raises(self) -> None:
        proc_instance = _make_mocked_process(None)
        proc_instance._stdout_queue.put(None)  # EOF sentinel
        with pytest.raises(RuntimeError, match="exited unexpectedly"):
            proc_instance.call({"op": "hash2", "a": "1", "b": "2"})

    def test_timeout_raises(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdin = MagicMock()
        proc_instance._proc = mock_proc
        # Queue is empty → timeout
        import protocol.poseidon_js as pjs_module

        original_timeout = pjs_module._REQUEST_TIMEOUT
        pjs_module._REQUEST_TIMEOUT = 0.01
        try:
            with pytest.raises(RuntimeError, match="timed out"):
                proc_instance.call({"op": "hash2", "a": "1", "b": "2"})
        finally:
            pjs_module._REQUEST_TIMEOUT = original_timeout

    def test_broken_pipe_raises(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdin = MagicMock()
        mock_proc.stdin.write.side_effect = BrokenPipeError("pipe broken")
        proc_instance._proc = mock_proc
        with pytest.raises(RuntimeError, match="closed unexpectedly"):
            proc_instance.call({"op": "hash2", "a": "1", "b": "2"})

    def test_calls_ensure_alive_when_proc_none(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        # _proc is None → _ensure_alive will call _start
        # Mock _start to avoid spawning a real process
        proc_instance._start = MagicMock()  # type: ignore[method-assign]

        def _fake_start():
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            mock_proc.stdin = MagicMock()
            proc_instance._proc = mock_proc
            proc_instance._stdout_queue.put('{"out":"77"}\n')

        proc_instance._start = _fake_start  # type: ignore[method-assign]
        result = proc_instance.call({"op": "hash2", "a": "3", "b": "4"})
        assert result == {"out": "77"}


# ---------------------------------------------------------------------------
# _PoseidonNodeProcess._shutdown
# ---------------------------------------------------------------------------


class TestPoseidonNodeProcessShutdown:
    def test_shutdown_when_proc_is_none(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        proc_instance._proc = None
        proc_instance._shutdown()  # must not raise

    def test_shutdown_closes_and_waits(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        proc_instance._proc = mock_proc
        proc_instance._shutdown()
        mock_proc.stdin.close.assert_called_once()
        mock_proc.wait.assert_called_once_with(timeout=5)

    def test_shutdown_kills_on_exception(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdin.close.side_effect = Exception("bad")
        proc_instance._proc = mock_proc
        proc_instance._shutdown()  # must not propagate exception
        mock_proc.kill.assert_called_once()

    def test_shutdown_skips_already_exited(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0  # already exited
        proc_instance._proc = mock_proc
        proc_instance._shutdown()
        mock_proc.wait.assert_not_called()


# ---------------------------------------------------------------------------
# _stdout_reader / _stderr_reader
# ---------------------------------------------------------------------------


class TestStdoutStderrReaders:
    def test_stdout_reader_enqueues_lines(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.stdout = iter(['{"out":"1"}\n', '{"out":"2"}\n'])
        proc_instance._stdout_reader(mock_proc)
        assert proc_instance._stdout_queue.get_nowait() == '{"out":"1"}\n'
        assert proc_instance._stdout_queue.get_nowait() == '{"out":"2"}\n'
        assert proc_instance._stdout_queue.get_nowait() is None  # sentinel

    def test_stdout_reader_sends_sentinel_when_none(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.stdout = None
        proc_instance._stdout_reader(mock_proc)
        # No sentinel sent when stdout is None

    def test_stderr_reader_fills_buffer(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.stderr = iter(["error line 1\n", "error line 2\n"])
        proc_instance._stderr_reader(mock_proc)
        assert "error line 1" in proc_instance._stderr_buf
        assert "error line 2" in proc_instance._stderr_buf

    def test_stderr_reader_skips_when_none(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.stderr = None
        proc_instance._stderr_reader(mock_proc)  # must not raise

    def test_last_stderr_empty(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        assert "(no stderr output)" in proc_instance._last_stderr()

    def test_last_stderr_with_content(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        proc_instance._stderr_buf.append("some error")
        assert "some error" in proc_instance._last_stderr()


# ---------------------------------------------------------------------------
# _ensure_alive
# ---------------------------------------------------------------------------


class TestEnsureAlive:
    def test_starts_when_proc_is_none(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        started = {"called": False}

        def fake_start():
            started["called"] = True
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            proc_instance._proc = mock_proc

        proc_instance._start = fake_start  # type: ignore[method-assign]
        proc_instance._ensure_alive()
        assert started["called"]

    def test_restarts_when_proc_exited(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        old_mock = MagicMock()
        old_mock.poll.return_value = 1  # exited
        proc_instance._proc = old_mock

        restarted = {"called": False}

        def fake_start():
            restarted["called"] = True
            new_mock = MagicMock()
            new_mock.poll.return_value = None
            proc_instance._proc = new_mock

        proc_instance._start = fake_start  # type: ignore[method-assign]
        proc_instance._ensure_alive()
        assert restarted["called"]

    def test_no_restart_when_alive(self) -> None:
        proc_instance = pjs._PoseidonNodeProcess(Path("/tmp/fake.js"))
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # alive
        proc_instance._proc = mock_proc
        started = {"called": False}

        def fake_start():
            started["called"] = True

        proc_instance._start = fake_start  # type: ignore[method-assign]
        proc_instance._ensure_alive()
        assert not started["called"]


# ---------------------------------------------------------------------------
# _get_process singleton
# ---------------------------------------------------------------------------


class TestGetProcess:
    def test_returns_singleton(self) -> None:
        # Reset the module-level singleton
        import protocol.poseidon_js as pjs_mod

        original = pjs_mod._node_process
        try:
            pjs_mod._node_process = None
            p1 = pjs._get_process()
            p2 = pjs._get_process()
            assert p1 is p2
        finally:
            pjs_mod._node_process = original


# ---------------------------------------------------------------------------
# _run_node
# ---------------------------------------------------------------------------


class TestRunNode:
    def test_delegates_to_process_call(self) -> None:
        mock_proc = MagicMock()
        mock_proc.call.return_value = {"out": "42"}

        import protocol.poseidon_js as pjs_mod

        original = pjs_mod._node_process
        try:
            pjs_mod._node_process = mock_proc
            result = pjs._run_node({"op": "hash2", "a": "1", "b": "2"})
            assert result == {"out": "42"}
            mock_proc.call.assert_called_once()
        finally:
            pjs_mod._node_process = original


# ---------------------------------------------------------------------------
# batch_compute_poseidon2
# ---------------------------------------------------------------------------


class TestBatchComputePoseidon2:
    def test_empty_list_returns_empty(self) -> None:
        assert pjs.batch_compute_poseidon2([]) == []

    def test_delegates_to_run_node(self) -> None:
        with patch.object(pjs, "_run_node", return_value={"outs": ["99", "100"]}) as mock_rn:
            result = pjs.batch_compute_poseidon2([(1, 2), (3, 4)])
        assert result == [99, 100]
        mock_rn.assert_called_once()

    def test_payload_structure(self) -> None:
        captured: list[dict] = []
        with patch.object(
            pjs, "_run_node", side_effect=lambda p: (captured.append(p), {"outs": ["5"]})[1]
        ):
            pjs.batch_compute_poseidon2([(7, 8)])
        assert captured[0]["op"] == "batch_hash2"
        assert captured[0]["pairs"][0] == {"a": "7", "b": "8"}


# ---------------------------------------------------------------------------
# compute_poseidon2
# ---------------------------------------------------------------------------


class TestComputePoseidon2:
    def test_delegates_to_batch(self) -> None:
        with patch.object(pjs, "batch_compute_poseidon2", return_value=[77]) as mock_batch:
            result = pjs.compute_poseidon2(3, 5)
        assert result == 77
        mock_batch.assert_called_once_with([(3, 5)])


# ---------------------------------------------------------------------------
# compute_poseidon_merkle_root
# ---------------------------------------------------------------------------


class TestComputePoseidonMerkleRoot:
    def test_without_depth(self) -> None:
        with patch.object(pjs, "_run_node", return_value={"out": "12345"}) as mock_rn:
            result = pjs.compute_poseidon_merkle_root([1, 2, 3])
        assert result == "12345"
        payload = mock_rn.call_args[0][0]
        assert payload["op"] == "merkle_root"
        assert "depth" not in payload

    def test_with_depth(self) -> None:
        with patch.object(pjs, "_run_node", return_value={"out": "99999"}) as mock_rn:
            result = pjs.compute_poseidon_merkle_root([1, 2], depth=4)
        assert result == "99999"
        payload = mock_rn.call_args[0][0]
        assert payload["depth"] == 4


# ---------------------------------------------------------------------------
# backend_enabled
# ---------------------------------------------------------------------------


class TestBackendEnabled:
    def test_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OLY_POSEIDON_BACKEND", raising=False)
        assert pjs.backend_enabled() is False

    def test_enabled_when_js(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OLY_POSEIDON_BACKEND", "js")
        assert pjs.backend_enabled() is True

    def test_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OLY_POSEIDON_BACKEND", "JS")
        assert pjs.backend_enabled() is True

    def test_py_backend_is_not_js(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OLY_POSEIDON_BACKEND", "py")
        assert pjs.backend_enabled() is False
