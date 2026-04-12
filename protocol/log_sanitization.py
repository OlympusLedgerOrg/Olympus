"""
Log sanitization utilities to prevent log injection attacks.

This module provides functions to sanitize user-controlled data before logging
to prevent log injection attacks where attackers could inject newlines or
control characters to forge log entries.
"""

import re


def sanitize_for_log(value: str | int | float | None) -> str:
    """
    Sanitize a value for safe inclusion in log messages.
    
    Removes or replaces characters that could be used for log injection:
    - Newlines (\\n, \\r)
    - Control characters
    - ANSI escape sequences
    
    Args:
        value: The value to sanitize (string, number, or None).
    
    Returns:
        A sanitized string safe for logging.
    """
    if value is None:
        return "None"
    
    # Convert to string
    s = str(value)
    
    # Replace newlines and carriage returns with spaces
    s = s.replace('\n', ' ').replace('\r', ' ')
    
    # Remove ANSI escape sequences
    s = re.sub(r'\x1b\[[0-9;]*m', '', s)
    
    # Remove other control characters (except space and tab)
    s = ''.join(char if (char >= ' ' or char == '\t') and char != '\x7f' else ' ' for char in s)
    
    # Collapse multiple spaces
    s = re.sub(r'\s+', ' ', s)
    
    # Trim
    s = s.strip()
    
    return s


def sanitize_dict_for_log(data: dict[str, object]) -> dict[str, str]:
    """
    Sanitize all string values in a dictionary for safe logging.
    
    Args:
        data: Dictionary with potentially unsafe values.
    
    Returns:
        Dictionary with all values sanitized.
    """
    return {key: sanitize_for_log(str(value)) for key, value in data.items()}
