"""Regression checks for new federation and formal-spec artifacts."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_federation_protocol_doc_covers_replication_and_consensus() -> None:
    """Federation prototype doc should pin node messaging and quorum rules."""
    path = REPO_ROOT / "docs" / "14_federation_protocol.md"
    text = path.read_text(encoding="utf-8")

    assert "node-to-node protocol" in text
    assert "shard replication" in text
    assert "header-signing consensus" in text
    assert "guardian_ack" in text
    assert "quorum certificate" in text
    assert "GET /shards/{shard_id}/header/latest" in text
    assert "GET /ledger/{shard_id}/tail" in text


def test_formal_spec_artifacts_capture_append_only_properties() -> None:
    """Formal spec files should exist and describe the required invariants."""
    tla_path = REPO_ROOT / "docs" / "formal" / "OlympusAppendOnly.tla"
    cfg_path = REPO_ROOT / "docs" / "formal" / "OlympusAppendOnly.cfg"
    doc_path = REPO_ROOT / "docs" / "15_formal_spec.md"

    tla_text = tla_path.read_text(encoding="utf-8")
    cfg_text = cfg_path.read_text(encoding="utf-8")
    doc_text = doc_path.read_text(encoding="utf-8")

    assert "MODULE OlympusAppendOnly" in tla_text
    assert "CommittedDocsDoNotChange" in tla_text
    assert "ValidProofsCorrespondToCommittedDocs" in tla_text
    assert "AppendOnlyLedger" in tla_text

    assert "SPECIFICATION Spec" in cfg_text
    assert "CommittedDocsDoNotChange" in cfg_text
    assert "ValidProofsCorrespondToCommittedDocs" in cfg_text
    assert "AppendOnlyLedger" in cfg_text

    assert "No committed document can be changed" in doc_text
    assert "Every valid proof corresponds to a real document" in doc_text
    assert "The ledger is append-only" in doc_text


def test_reviewer_threat_model_doc_covers_expected_attack_classes() -> None:
    """Threat model doc should enumerate system goals, adversaries, and attacks."""
    path = REPO_ROOT / "docs" / "threat_model.md"
    text = path.read_text(encoding="utf-8")

    assert "System Goals" in text
    assert "Olympus guarantees" in text
    assert "Adversary Types" in text
    assert "Government actor" in text
    assert "Malicious node" in text
    assert "Sybil Node Attack" in text
    assert "Spam Submissions" in text
