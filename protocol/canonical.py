"""
Canonical document representation for Olympus

This module implements deterministic canonicalization of documents to ensure
consistent hashing regardless of superficial formatting differences.
"""

import json
from typing import Any, Dict, List, Union


def canonicalize_json(data: Dict[str, Any]) -> str:
    """
    Canonicalize a JSON-serializable dictionary.
    
    Args:
        data: Dictionary to canonicalize
        
    Returns:
        Canonical JSON string representation
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text.
    
    Args:
        text: Input text
        
    Returns:
        Text with normalized whitespace
    """
    # Replace multiple whitespace with single space
    # Strip leading/trailing whitespace
    return ' '.join(text.split())


def canonicalize_document(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Canonicalize a document structure.
    
    This ensures deterministic ordering and formatting.
    
    Args:
        doc: Document to canonicalize
        
    Returns:
        Canonicalized document
    """
    if not isinstance(doc, dict):
        raise ValueError("Document must be a dictionary")
    
    canonical = {}
    for key in sorted(doc.keys()):
        value = doc[key]
        if isinstance(value, dict):
            canonical[key] = canonicalize_document(value)
        elif isinstance(value, list):
            canonical[key] = [
                canonicalize_document(item) if isinstance(item, dict) else item
                for item in value
            ]
        elif isinstance(value, str):
            canonical[key] = normalize_whitespace(value)
        else:
            canonical[key] = value
    
    return canonical


def document_to_bytes(doc: Dict[str, Any]) -> bytes:
    """
    Convert document to canonical byte representation.
    
    Args:
        doc: Document to convert
        
    Returns:
        Canonical bytes
    """
    canonical = canonicalize_document(doc)
    json_str = canonicalize_json(canonical)
    return json_str.encode('utf-8')
