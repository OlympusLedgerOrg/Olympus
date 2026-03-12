# Ledger Vectors

Ledger chaining vectors remain in `verifiers/test_vectors/vectors.json` under
`ledger_entry_hash` and related sections. They pin the domain-separated ledger
entry hashing formula and the inclusion of previous entry hashes for chain
integrity.

Use those vectors to confirm that independent implementations produce identical
entry hashes for the same payloads and maintain correct chain linkage.
