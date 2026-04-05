"""Tests for ZIP symlink validation in api/services/upload_validation.py"""

import io
import stat
import zipfile

import pytest
from fastapi import HTTPException

from api.services.upload_validation import validate_zip_safety


class TestZipSymlinkValidation:
    """Tests for ZIP symlink detection and rejection."""

    def test_rejects_symlink_entry(self):
        """ZIP entries with Unix symlink file modes must be rejected."""
        # Create a ZIP with a symlink entry
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            # Add a symlink entry by manually setting external_attr
            info = zipfile.ZipInfo('symlink_entry')
            info.external_attr = (stat.S_IFLNK | 0o755) << 16  # Unix symlink mode
            zf.writestr(info, 'target')

        zip_bytes = buffer.getvalue()

        # Should reject with HTTP 400
        with pytest.raises(HTTPException) as exc_info:
            validate_zip_safety(zip_bytes)

        assert exc_info.value.status_code == 400
        assert 'symlink' in exc_info.value.detail.lower()

    def test_accepts_regular_file(self):
        """ZIP entries with regular file modes should be accepted (if other checks pass)."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            # Add a regular file
            info = zipfile.ZipInfo('regular.txt')
            info.external_attr = (stat.S_IFREG | 0o644) << 16  # Unix regular file mode
            zf.writestr(info, 'hello world')

        zip_bytes = buffer.getvalue()

        # Should not raise for symlink (might raise for other checks, but not symlink)
        try:
            validate_zip_safety(zip_bytes)
        except HTTPException as e:
            # If it raises, it should not be about symlinks
            assert 'symlink' not in e.detail.lower()

    def test_accepts_entry_with_zero_external_attr(self):
        """ZIP entries with zero external_attr (common on Windows) should be accepted."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            # Add a file with zero external_attr (Windows-created ZIP)
            info = zipfile.ZipInfo('windows_file.txt')
            info.external_attr = 0
            zf.writestr(info, 'content')

        zip_bytes = buffer.getvalue()

        # Should not raise for symlink check
        try:
            validate_zip_safety(zip_bytes)
        except HTTPException as e:
            assert 'symlink' not in e.detail.lower()

    def test_symlink_check_before_path_traversal_check(self):
        """Symlink check should run before path traversal check."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            # Create a symlink with a path traversal attempt
            info = zipfile.ZipInfo('../../etc/passwd')
            info.external_attr = (stat.S_IFLNK | 0o755) << 16
            zf.writestr(info, '/etc/passwd')

        zip_bytes = buffer.getvalue()

        with pytest.raises(HTTPException) as exc_info:
            validate_zip_safety(zip_bytes)

        # Should fail on symlink check (which comes first)
        assert exc_info.value.status_code == 400
        assert 'symlink' in exc_info.value.detail.lower()

    def test_accepts_directory_entry(self):
        """ZIP directory entries should be accepted."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            # Add a directory entry
            info = zipfile.ZipInfo('my_directory/')
            info.external_attr = (stat.S_IFDIR | 0o755) << 16  # Unix directory mode
            zf.writestr(info, '')

        zip_bytes = buffer.getvalue()

        # Should not raise for symlink
        try:
            validate_zip_safety(zip_bytes)
        except HTTPException as e:
            assert 'symlink' not in e.detail.lower()
