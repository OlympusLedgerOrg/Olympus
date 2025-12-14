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
