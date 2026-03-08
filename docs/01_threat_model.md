# Threat Model

This document describes the threat model for the Olympus protocol.

For an interactive walkthrough with attack scenarios and verification exercises,
see `docs/threat_model_walkthrough.ipynb`.

## Adversaries

- Malicious document submitters
- Compromised ledger nodes
- State-level actors attempting to rewrite history
- Insider threats within government agencies

## Security Goals

- Tamper evidence
- Non-repudiation
- Fork detection
- Availability under partial failure

## Non-Goals

- Preventing document submission
- Guaranteeing completeness of records
- Protecting confidentiality of unredacted content
- Trust in any single party
