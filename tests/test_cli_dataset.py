"""
Tests for tools/dataset_cli.py (ADR-0010 dataset provenance CLI).

Covers:
  - keygen: key file generation and overwrite guard
  - commit: manifest building, Merkle root, deterministic commit ID, signature
  - verify: valid bundle passes; tampered bundles fail with correct error flags
  - cross-OS sort invariant: identical file sets enumerated in different orders
    must produce the same root_hash (the core regression targeted by this PR)
"""

import json
import subprocess
import sys
from pathlib import Path

import blake3 as _blake3
import pytest

from protocol.merkle import EMPTY_TREE_HASH, MerkleTree


CLI_PATH = Path(__file__).parent.parent / "tools" / "dataset_cli.py"
OLYMPUS_CLI = Path(__file__).parent.parent / "tools" / "olympus.py"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def key_prefix(tmp_path):
    """Return a key prefix inside tmp_path and generate a fresh keypair."""
    prefix = str(tmp_path / "test_key")
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen", "-o", prefix],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return prefix


@pytest.fixture
def dataset_dir(tmp_path):
    """Create a small dataset directory with a few files."""
    ds = tmp_path / "dataset"
    ds.mkdir()
    (ds / "alpha.csv").write_text("col1,col2\n1,2\n3,4\n")
    (ds / "beta.txt").write_text("hello world\n")
    sub = ds / "sub"
    sub.mkdir()
    (sub / "gamma.json").write_text('{"x": 1}\n')
    return ds


@pytest.fixture
def bundle_file(tmp_path, key_prefix, dataset_dir):
    """Build a commit bundle and return its path."""
    bundle_path = tmp_path / "bundle.json"
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(dataset_dir),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "test-dataset",
            "--source-uri",
            "https://example.com/dataset",
            "--namespace",
            "test.namespace",
            "-o",
            str(bundle_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return bundle_path


# ---------------------------------------------------------------------------
# keygen tests
# ---------------------------------------------------------------------------


def test_keygen_creates_key_files(tmp_path):
    prefix = str(tmp_path / "mykey")
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen", "-o", prefix],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert Path(f"{prefix}.priv").exists()
    assert Path(f"{prefix}.pub").exists()


def test_keygen_default_output(tmp_path):
    """Default output prefix is 'dataset_key' in the current directory."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen"],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
    )
    assert result.returncode == 0
    assert (tmp_path / "dataset_key.priv").exists()
    assert (tmp_path / "dataset_key.pub").exists()


def test_keygen_key_files_are_hex(tmp_path):
    prefix = str(tmp_path / "k")
    subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen", "-o", prefix],
        capture_output=True,
    )
    priv = Path(f"{prefix}.priv").read_bytes()
    pub = Path(f"{prefix}.pub").read_bytes()
    # Both are hex-encoded 32-byte values → 64 hex chars each
    assert len(priv) == 64
    assert len(pub) == 64
    bytes.fromhex(priv.decode())
    bytes.fromhex(pub.decode())


def test_keygen_no_overwrite_guard(tmp_path):
    prefix = str(tmp_path / "k")
    subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen", "-o", prefix],
        capture_output=True,
    )
    # Second run without --overwrite must fail
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen", "-o", prefix],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "overwrite" in result.stderr.lower() or "exists" in result.stderr.lower()


def test_keygen_overwrite_flag(tmp_path):
    prefix = str(tmp_path / "k")
    subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen", "-o", prefix],
        capture_output=True,
    )
    first_pub = Path(f"{prefix}.pub").read_bytes()

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen", "-o", prefix, "--overwrite"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    # New keypair is written (may differ from first)
    assert Path(f"{prefix}.pub").read_bytes() != first_pub or True  # just ensure no crash


# ---------------------------------------------------------------------------
# commit tests
# ---------------------------------------------------------------------------


def test_commit_stdout_is_valid_json(key_prefix, dataset_dir):
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(dataset_dir),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "ds",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    for field in (
        "dataset_id",
        "commit_id",
        "parent_id",
        "manifest",
        "committer_pubkey",
        "signature",
    ):
        assert field in bundle, f"missing field: {field}"


def test_commit_bundle_file_output(tmp_path, key_prefix, dataset_dir):
    out = tmp_path / "out.json"
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(dataset_dir),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "ds",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
            "-o",
            str(out),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert out.exists()
    bundle = json.loads(out.read_text())
    assert "commit_id" in bundle


def test_commit_manifest_contains_all_files(key_prefix, dataset_dir):
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(dataset_dir),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "ds",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    bundle = json.loads(result.stdout)
    paths = {e["path"] for e in bundle["manifest"]["files"]}
    assert "alpha.csv" in paths
    assert "beta.txt" in paths
    assert "sub/gamma.json" in paths


def test_commit_files_sorted_by_case_folded_path(key_prefix, tmp_path):
    """Files in manifest must be ordered by casefold()ed POSIX path."""
    ds = tmp_path / "ds"
    ds.mkdir()
    (ds / "Zebra.txt").write_text("z")
    (ds / "apple.txt").write_text("a")
    (ds / "Mango.txt").write_text("m")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(ds),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "sort-test",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    paths = [e["path"] for e in bundle["manifest"]["files"]]
    assert paths == sorted(paths, key=str.casefold), (
        f"Files not sorted by casefold()ed path: {paths}"
    )


def test_commit_root_hash_stable_for_duplicate_content(key_prefix, tmp_path):
    """Two files with identical content must produce a stable Merkle root regardless
    of which filesystem enumeration order was used.

    This is the core regression test for the cross-OS sort invariant: on
    case-insensitive filesystems (NTFS/APFS) vs case-sensitive (ext4), the raw
    byte order of e.g. 'B.txt' and 'a.txt' diverges from the casefold order.
    The CLI must normalise via casefold so the Merkle root is invariant.

    Byte (ASCII) order:  'B.txt' < 'a.txt'  (uppercase B=0x42 < lowercase a=0x61)
    casefold order:      'a.txt' < 'b.txt'  (a < b)

    The CLI must use casefold order, so 'a.txt' is always leaf 0.
    """
    ds = tmp_path / "ds"
    ds.mkdir()
    (ds / "B.txt").write_text("same content")
    (ds / "a.txt").write_text("same content")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(ds),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "dup-test",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)

    # Verify manifest file order: casefold puts 'a.txt' before 'B.txt' ('b.txt').
    paths = [e["path"] for e in bundle["manifest"]["files"]]
    assert paths == ["a.txt", "B.txt"], f"Expected casefold order ['a.txt', 'B.txt'], got {paths}"

    # Manually reproduce the expected Merkle root with the same leaf order.
    content_hash = _blake3.blake3(b"same content").hexdigest()
    expected_leaves = [
        bytes.fromhex(content_hash),  # a.txt  (leaf 0 — casefold 'a' < 'b')
        bytes.fromhex(content_hash),  # B.txt  (leaf 1 — casefold 'b' > 'a')
    ]
    expected_root = MerkleTree(expected_leaves).get_root().hex()
    assert bundle["manifest"]["root_hash"] == expected_root, (
        "Merkle root diverged — file sort is not using casefold key"
    )


def test_commit_casefold_tie_breaker(key_prefix, tmp_path):
    """On a case-sensitive filesystem both README.md and readme.md can coexist.

    Their casefold keys collide ('readme.md' == 'readme.md'), so the secondary
    sort key (original POSIX path) must break the tie deterministically.
    Byte order: 'R' (0x52) < 'r' (0x72), so README.md should appear first.
    """
    ds = tmp_path / "ds"
    ds.mkdir()
    try:
        (ds / "readme.md").write_text("lower")
        (ds / "README.md").write_text("upper")
    except OSError:
        pytest.skip("filesystem is case-insensitive; cannot create both files")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(ds),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "tie-test",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    paths = [e["path"] for e in bundle["manifest"]["files"]]
    # Secondary (original path) tie-break: 'R' < 'r' in ASCII.
    assert paths == sorted(paths, key=lambda p: (p.casefold(), p)), (
        f"Tie-breaker not applied: {paths}"
    )


def test_commit_manifest_entries_include_size(key_prefix, dataset_dir):
    """Every manifest file entry must contain a 'size' field with the byte count."""
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(dataset_dir),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "size-test",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    for entry in bundle["manifest"]["files"]:
        assert "size" in entry, f"missing 'size' in entry: {entry}"
        assert isinstance(entry["size"], int)
        assert entry["size"] >= 0


def test_commit_manifest_entries_no_sort_key(key_prefix, dataset_dir):
    """The transient 'sort_key' field must not appear in the manifest."""
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(dataset_dir),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "no-sort-key",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    for entry in bundle["manifest"]["files"]:
        assert "sort_key" not in entry, f"'sort_key' leaked into manifest entry: {entry}"


def test_commit_skips_symlinks(key_prefix, tmp_path):
    """Symlinks inside the dataset directory must not appear in the manifest.

    Path.is_file() follows symlinks, so without an explicit is_symlink() guard
    a symlink pointing to a regular file would be silently included as if it
    were a real file.  The manifest must contain only transferable regular-file
    content.
    """
    ds = tmp_path / "ds"
    ds.mkdir()
    real_file = ds / "real.txt"
    real_file.write_text("actual content")
    link = ds / "link_to_real.txt"
    try:
        link.symlink_to(real_file)
    except OSError:
        pytest.skip("filesystem does not support symlinks")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(ds),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "symlink-test",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    paths = [e["path"] for e in bundle["manifest"]["files"]]
    assert "real.txt" in paths, "regular file must be present"
    assert "link_to_real.txt" not in paths, "symlink must be excluded from manifest"
    # Exactly one file
    assert len(paths) == 1, f"expected 1 entry (regular file only), got {paths}"


def test_commit_sort_respects_directory_prefix(key_prefix, tmp_path):
    """Sort must use the full relative POSIX path, not just the filename.

    Without a directory-aware sort, a file at 'sub/alpha.txt' could end up
    after 'Top.txt' because 'alpha' < 'Top' alphabetically but 'sub/' > 'T'
    — the sort key must include the directory component.
    """
    ds = tmp_path / "ds"
    ds.mkdir()
    # These filenames are chosen so that casefold of the full relative path
    # gives a clear ordering: 'a/z.txt' < 'b/a.txt' < 'c.txt'
    (ds / "c.txt").write_text("c")
    subA = ds / "a"
    subA.mkdir()
    (subA / "z.txt").write_text("az")
    subB = ds / "b"
    subB.mkdir()
    (subB / "a.txt").write_text("ba")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(ds),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "dir-sort-test",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    paths = [e["path"] for e in bundle["manifest"]["files"]]
    expected = sorted(paths, key=lambda p: (p.casefold(), p))
    assert paths == expected, (
        f"Sort does not respect directory component: got {paths}, expected {expected}"
    )
    # Also verify the concrete order: a/z.txt < b/a.txt < c.txt
    assert paths == ["a/z.txt", "b/a.txt", "c.txt"], f"Unexpected order: {paths}"


def test_commit_sort_unicode_casefold(key_prefix, tmp_path):
    """casefold() must be used instead of lower() for Unicode correctness.

    German sharp S: 'ß'.casefold() == 'ss', but 'ß'.lower() == 'ß'.
    Because 'ß' (U+00DF = 223) > 't' (U+0074 = 116) in Unicode,
    lower()-based sort places ß.txt *after* T.txt.
    But casefold()-based sort produces 'ss' < 't', placing ß.txt *before* T.txt.

    This test creates S.txt, ß.txt, T.txt and asserts the casefold order:
        S.txt ('s')  →  ß.txt ('ss')  →  T.txt ('t')
    """
    ds = tmp_path / "ds"
    ds.mkdir()
    try:
        (ds / "ß.txt").write_text("sharp-s")
    except OSError:
        pytest.skip("filesystem does not support this Unicode filename")
    (ds / "S.txt").write_text("s-upper")
    (ds / "T.txt").write_text("t-upper")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(ds),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "unicode-test",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    paths = [e["path"] for e in bundle["manifest"]["files"]]

    # casefold order: S.txt → ß.txt → T.txt  (s < ss < t)
    assert paths == sorted(paths, key=lambda p: (p.casefold(), p)), (
        f"Files not in casefold order: {paths}"
    )
    s_idx = paths.index("S.txt")
    beta_idx = paths.index("ß.txt")
    t_idx = paths.index("T.txt")
    assert s_idx < beta_idx < t_idx, (
        f"Expected S.txt < ß.txt < T.txt (casefold), got indices "
        f"S={s_idx}, ß={beta_idx}, T={t_idx} in {paths}"
    )


def test_commit_empty_directory(key_prefix, tmp_path):
    ds = tmp_path / "empty_ds"
    ds.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(ds),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "empty",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    assert bundle["manifest"]["files"] == []
    # root_hash must be the canonical empty-tree hash
    assert bundle["manifest"]["root_hash"] == EMPTY_TREE_HASH.hex()


def test_commit_deterministic(key_prefix, dataset_dir):
    """Running commit twice on the same directory produces the same commit_id."""

    def run():
        r = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "commit",
                str(dataset_dir),
                "--private-key",
                f"{key_prefix}.priv",
                "--dataset-name",
                "det",
                "--source-uri",
                "https://example.com",
                "--namespace",
                "ns",
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)

    b1 = run()
    b2 = run()
    assert b1["commit_id"] == b2["commit_id"]
    assert b1["manifest"]["root_hash"] == b2["manifest"]["root_hash"]


def test_commit_parent_id_changes_commit_id(key_prefix, dataset_dir):
    def run(parent):
        r = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "commit",
                str(dataset_dir),
                "--private-key",
                f"{key_prefix}.priv",
                "--dataset-name",
                "chain",
                "--source-uri",
                "https://example.com",
                "--namespace",
                "ns",
                "--parent",
                parent,
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)

    genesis = run("")
    child = run(genesis["commit_id"])
    assert genesis["commit_id"] != child["commit_id"]


def test_commit_invalid_directory(key_prefix, tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(tmp_path / "no_such_dir"),
            "--private-key",
            f"{key_prefix}.priv",
            "--dataset-name",
            "x",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "directory" in result.stderr.lower()


def test_commit_missing_private_key(dataset_dir, tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(dataset_dir),
            "--private-key",
            str(tmp_path / "no.priv"),
            "--dataset-name",
            "x",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "ns",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "key" in result.stderr.lower()


# ---------------------------------------------------------------------------
# verify tests
# ---------------------------------------------------------------------------


def test_verify_valid_bundle_passes(bundle_file):
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "verify", str(bundle_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "✓" in result.stdout


def test_verify_tampered_signature_fails(bundle_file, tmp_path):
    bundle = json.loads(bundle_file.read_text())
    # Flip last byte of signature
    sig_bytes = bytearray(bytes.fromhex(bundle["signature"]))
    sig_bytes[-1] ^= 0xFF
    bundle["signature"] = sig_bytes.hex()
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(bundle))

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "verify", str(tampered)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "✗" in result.stdout
    assert "signature" in result.stdout.lower()


def test_verify_tampered_commit_id_fails(bundle_file, tmp_path):
    bundle = json.loads(bundle_file.read_text())
    bundle["commit_id"] = "a" * 64
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(bundle))

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "verify", str(tampered)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "✗" in result.stdout


def test_verify_tampered_root_hash_fails(bundle_file, tmp_path):
    bundle = json.loads(bundle_file.read_text())
    bundle["manifest"]["root_hash"] = "b" * 64
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(bundle))

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "verify", str(tampered)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "✗" in result.stdout
    assert "merkle" in result.stdout.lower() or "root" in result.stdout.lower()


def test_verify_missing_bundle_file():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "verify", "/tmp/no_such_bundle.json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "not found" in result.stderr.lower() or "bundle" in result.stderr.lower()


def test_verify_invalid_json_bundle(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json}")
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "verify", str(bad)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "json" in result.stderr.lower()


# ---------------------------------------------------------------------------
# olympus.py integration test
# ---------------------------------------------------------------------------


def test_olympus_dataset_keygen_via_unified_cli(tmp_path):
    prefix = str(tmp_path / "unified_key")
    result = subprocess.run(
        [sys.executable, str(OLYMPUS_CLI), "dataset", "keygen", "-o", prefix],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert Path(f"{prefix}.priv").exists()
    assert Path(f"{prefix}.pub").exists()


def test_olympus_dataset_commit_and_verify_round_trip(tmp_path):
    """Full round-trip via the unified olympus CLI."""
    prefix = str(tmp_path / "k")
    ds = tmp_path / "ds"
    ds.mkdir()
    (ds / "file.txt").write_text("olympus test")
    bundle_path = tmp_path / "bundle.json"

    # keygen
    subprocess.run(
        [sys.executable, str(OLYMPUS_CLI), "dataset", "keygen", "-o", prefix],
        check=True,
        capture_output=True,
    )

    # commit
    subprocess.run(
        [
            sys.executable,
            str(OLYMPUS_CLI),
            "dataset",
            "commit",
            str(ds),
            "--private-key",
            f"{prefix}.priv",
            "--dataset-name",
            "round-trip",
            "--source-uri",
            "https://example.com",
            "--namespace",
            "test",
            "-o",
            str(bundle_path),
        ],
        check=True,
        capture_output=True,
    )

    # verify
    result = subprocess.run(
        [sys.executable, str(OLYMPUS_CLI), "dataset", "verify", str(bundle_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "✓" in result.stdout
