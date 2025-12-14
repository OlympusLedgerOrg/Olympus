# Verification Flows

This document describes the verification flows in Olympus.

## Document Existence Verification

1. Client obtains document and claimed timestamp
2. Client canonicalizes document
3. Client computes hash
4. Client queries ledger for entry
5. Client verifies Merkle proof
6. Client checks signatures

## Redaction Verification

1. Client obtains redacted document
2. Client obtains redaction proof
3. Client queries ledger for original commitment
4. Client verifies ZK proof
5. Client confirms proof matches commitment

## Fork Detection

1. Client queries multiple independent nodes
2. Client compares responses
3. Client identifies inconsistencies
4. Client raises alarm if fork detected

## Audit Trail

- All verifications are logged
- Logs are independently auditable
- Timestamp verification via NTP/GPS
- Cryptographic evidence chain
