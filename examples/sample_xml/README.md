# Sample XML Directory

This directory contains sample XML documents for testing Olympus canonicalization
and commitment processes.

## Contents

Sample XML documents representing government records, legislative documents,
and other structured data.

## Usage

```bash
# Canonicalize an XML document (converted to JSON)
python tools/canonicalize_cli.py examples/sample_xml/document.json --output canonical.json
```

## Expected Structure

XML documents should be pre-converted to JSON with structure preserved:

```json
{
  "document_type": "legislative_bill",
  "bill_number": "HR-1234",
  "title": "Sample Legislation",
  "sections": [
    {
      "section_id": "1",
      "title": "Purpose",
      "content": "This bill establishes..."
    }
  ]
}
```
