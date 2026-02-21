"""Tests for tools/chain_verify_cli.py."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from protocol.ledger import Ledger


# Add tools to path so we can import chain_verify_cli
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
import chain_verify_cli


@pytest.fixture()
def valid_ledger_file(tmp_path: Path) -> Path:
    """Create a valid ledger export file."""
    ledger = Ledger()
    ledger.append(record_hash="aabb", shard_id="shard-1", shard_root="ccdd")
    ledger.append(record_hash="eeff", shard_id="shard-1", shard_root="1122")
    ledger.append(record_hash="3344", shard_id="shard-2", shard_root="5566")

    data = {"entries": [e.to_dict() for e in ledger.entries]}
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(data))
    return path


@pytest.fixture()
def broken_ledger_file(tmp_path: Path) -> Path:
    """Create a ledger with a broken chain."""
    ledger = Ledger()
    ledger.append(record_hash="aabb", shard_id="shard-1", shard_root="ccdd")
    ledger.append(record_hash="eeff", shard_id="shard-1", shard_root="1122")

    entries_data = [e.to_dict() for e in ledger.entries]
    # Break the chain
    entries_data[1]["prev_entry_hash"] = "0000000000000000"

    data = {"entries": entries_data}
    path = tmp_path / "broken_ledger.json"
    path.write_text(json.dumps(data))
    return path


class TestVerifyCommand:
    def test_valid_chain(self, valid_ledger_file: Path, capsys):
        args = type("Args", (), {"ledger_file": str(valid_ledger_file)})()
        result = chain_verify_cli.cmd_verify(args)
        assert result == 0
        assert "VALID" in capsys.readouterr().out

    def test_broken_chain(self, broken_ledger_file: Path, capsys):
        args = type("Args", (), {"ledger_file": str(broken_ledger_file)})()
        result = chain_verify_cli.cmd_verify(args)
        assert result == 1
        assert "CHAIN BREAK" in capsys.readouterr().err


class TestInspectCommand:
    def test_inspect_summary(self, valid_ledger_file: Path, capsys):
        args = type("Args", (), {"ledger_file": str(valid_ledger_file)})()
        result = chain_verify_cli.cmd_inspect(args)
        assert result == 0
        output = capsys.readouterr().out
        assert "3 entries" in output
        assert "shard-1" in output
        assert "shard-2" in output


class TestLookupCommand:
    def test_lookup_existing_entry(self, valid_ledger_file: Path, capsys):
        # Load to get a hash
        with open(valid_ledger_file) as f:
            data = json.load(f)
        entry_hash = data["entries"][0]["entry_hash"]

        args = type(
            "Args",
            (),
            {
                "ledger_file": str(valid_ledger_file),
                "entry_hash": entry_hash,
            },
        )()
        result = chain_verify_cli.cmd_lookup(args)
        assert result == 0

    def test_lookup_missing_entry(self, valid_ledger_file: Path, capsys):
        args = type(
            "Args",
            (),
            {
                "ledger_file": str(valid_ledger_file),
                "entry_hash": "nonexistent",
            },
        )()
        result = chain_verify_cli.cmd_lookup(args)
        assert result == 1

    def test_lookup_prefix_match(self, valid_ledger_file: Path, capsys):
        with open(valid_ledger_file) as f:
            data = json.load(f)
        entry_hash = data["entries"][0]["entry_hash"]
        prefix = entry_hash[:8]

        args = type(
            "Args",
            (),
            {
                "ledger_file": str(valid_ledger_file),
                "entry_hash": prefix,
            },
        )()
        result = chain_verify_cli.cmd_lookup(args)
        assert result == 0


class TestDiagnoseCommand:
    def test_diagnose_healthy(self, valid_ledger_file: Path, capsys):
        args = type("Args", (), {"ledger_file": str(valid_ledger_file)})()
        result = chain_verify_cli.cmd_diagnose(args)
        assert result == 0
        output = capsys.readouterr().out
        assert "No issues found" in output

    def test_diagnose_broken(self, broken_ledger_file: Path, capsys):
        args = type("Args", (), {"ledger_file": str(broken_ledger_file)})()
        result = chain_verify_cli.cmd_diagnose(args)
        assert result == 1
        captured = capsys.readouterr()
        assert "issue(s) found" in captured.err


class TestMainEntryPoint:
    def test_no_command_prints_help(self, capsys):
        with patch("sys.argv", ["chain_verify_cli"]):
            result = chain_verify_cli.main()
            assert result == 1

    def test_verify_command(self, valid_ledger_file: Path):
        with patch("sys.argv", ["chain_verify_cli", "verify", str(valid_ledger_file)]):
            result = chain_verify_cli.main()
            assert result == 0
