from protocol.redaction import apply_redaction


def test_redaction_mask_semantics():
    original = "ABCDE"
    mask = [0, 1, 0, 1, 0]  # redact B and D

    redacted = apply_redaction(original, mask, replacement="█")

    assert redacted == "A█C█E"


def test_redaction_does_not_modify_kept_text():
    original = "OLYMPUS"
    mask = [0] * len(original)

    redacted = apply_redaction(original, mask, replacement="█")

    assert redacted == original
