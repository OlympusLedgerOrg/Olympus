# Sample PDF Directory

This directory contains sample PDF documents for testing Olympus canonicalization
and commitment processes.

## Contents

Sample PDF documents should be placed here for testing purposes. These documents
will be canonicalized and committed to the Olympus ledger.

## Usage

```bash
# Canonicalize a PDF document
python tools/canonicalize_cli.py examples/sample_pdf/document.json --output canonical.json

# Generate hash
python tools/canonicalize_cli.py examples/sample_pdf/document.json --hash
```

## Expected Structure

PDF documents should be pre-converted to JSON format with extracted text and metadata:

```json
{
  "title": "Sample Government Document",
  "author": "Agency Name",
  "created_at": "2024-01-01T00:00:00Z",
  "content": [
    "Paragraph 1 text...",
    "Paragraph 2 text...",
    "Paragraph 3 text..."
  ]
}
```
