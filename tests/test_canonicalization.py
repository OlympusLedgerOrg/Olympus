from protocol.canonical import canonicalize_text

def test_canonicalization_is_deterministic():
    text = "Hello   world\n\nThis is Olympus.\r\n"
    
    first = canonicalize_text(text)
    second = canonicalize_text(text)

    assert first == second


def test_whitespace_normalization():
    a = "Hello   world"
    b = "Hello world"

    assert canonicalize_text(a) == canonicalize_text(b)


def test_line_endings_normalized():
    unix = "line1\nline2\n"
    windows = "line1\r\nline2\r\n"

    assert canonicalize_text(unix) == canonicalize_text(windows)


def test_canonicalization_golden_vector():
    """
    Golden vector test to anchor canonicalization behavior across time.
    
    This test ensures that the canonical bytes never subtly change.
    DO NOT CHANGE the expected bytes without a protocol version bump.
    
    If this test fails, it means canonicalization semantics have changed,
    which would break all historical document proofs.
    """
    # Test case 1: Basic whitespace and line ending normalization
    raw1 = "Hello   world\r\n"
    expected1 = b"Hello world"
    assert canonicalize_text(raw1).encode('utf-8') == expected1
    
    # Test case 2: Multiple spaces and line preservation
    raw2 = "Line1\r\nLine2\r\n"
    expected2 = b"Line1\nLine2"
    assert canonicalize_text(raw2).encode('utf-8') == expected2
    
    # Test case 3: Leading/trailing whitespace removal
    raw3 = "  Trimmed  content  \r\n"
    expected3 = b"Trimmed content"
    assert canonicalize_text(raw3).encode('utf-8') == expected3
    
    # Test case 4: Complex multi-line document
    raw4 = "First   line\r\n\r\nSecond   line\r\n"
    expected4 = b"First line\n\nSecond line"
    assert canonicalize_text(raw4).encode('utf-8') == expected4
