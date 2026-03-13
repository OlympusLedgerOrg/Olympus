# Trusted Setup Ceremony Infrastructure

This directory contains the infrastructure for running and verifying Groth16
trusted setup ceremonies. Because Groth16 proofs require a trusted setup,
the security of the entire system depends on this ceremony being executed
correctly.

## Overview

Groth16 requires a two-phase trusted setup ceremony:

1. **Phase 1 (Powers of Tau)**: Universal parameters shared across all circuits
2. **Phase 2 (Circuit-Specific)**: Parameters specific to each circuit

The security model is 1-of-N honest: as long as at least one participant
destroys their toxic waste, the resulting parameters are secure.

## Directory Structure

```
ceremony/
├── transcript/           # Ceremony transcript files (append-only)
├── participant_keys/     # Public identity keys for participants
├── contributions/        # Individual contribution files
├── verification_tools/   # Python tools for verification
└── README.md             # This file
```

## Transcript Format

Each ceremony produces a reproducible transcript containing:

- Participant identities and public keys
- Contribution hashes (BLAKE3)
- Timestamps (ISO 8601)
- Beacon randomness values
- Verification proofs for each contribution

See `verification_tools/transcript.py` for the canonical format.

## Ceremony Protocol

### Phase 1 (Powers of Tau)

1. Download or generate the initial PTAU file
2. Each participant:
   a. Downloads the current PTAU file
   b. Contributes their randomness
   c. Computes the contribution hash
   d. Signs the contribution with their identity key
   e. Uploads the new PTAU file and transcript entry

### Phase 2 (Circuit-Specific)

1. Compile the circuit to R1CS
2. Initialize the zkey from the finalized PTAU
3. Each participant:
   a. Downloads the current zkey
   b. Contributes their randomness
   c. Computes the contribution hash
   d. Signs the contribution with their identity key
   e. Uploads the new zkey and transcript entry
4. Finalize the zkey and export verification key

### Beacon Randomness

To prevent grinding attacks, each contribution round incorporates
publicly verifiable randomness from a deterministic beacon:

- Source: drand mainnet (League of Entropy)
- Round selection: First beacon round after previous contribution timestamp
- Hash: SHA-256 of beacon randomness (as published by drand)

See `verification_tools/beacon.py` for the beacon integration.

## Verification

Anyone can independently verify the ceremony:

```bash
# Verify entire ceremony transcript
python -m ceremony.verification_tools.verify_ceremony ceremony/transcript/

# Verify a single contribution
python -m ceremony.verification_tools.verify_contribution \
    ceremony/contributions/<contribution_id>.json

# Verify beacon randomness for a round
python -m ceremony.verification_tools.beacon --verify-round 12345
```

## Development Transcript (non-production)

A development-only transcript is checked into this repository to prove the pipeline runs end to end:

- `transcript/dev-transcript.json` — index of artifacts and contributions
- `transcript/dev_powers_of_tau.ptau` — placeholder Phase 1 artifact (not trusted)
- `transcript/dev_redaction_validity_final.zkey` — placeholder Phase 2 artifact (not trusted)
- `contributions/dev-alpha-phase1.json` / `dev-alpha-phase2.json` — signed sample contributions
- `participant_keys/dev-alpha.json` — public key for the dev participant

⚠️ **Not production**: the signing key was generated from a deterministic seed for reproducibility and destroyed after signing. Run a fresh multi-party ceremony for any real deployment.

## Security Properties

A valid ceremony transcript guarantees:

1. **Chain integrity**: Each contribution builds on the previous one
2. **Identity binding**: All contributions are signed by known participants
3. **Beacon binding**: Randomness is anchored to public beacon values
4. **Hash consistency**: Contribution hashes match the actual artifacts

If ANY of these checks fail, the verification tools will reject the transcript.

## Public Verification

The ceremony is only trustworthy if it can be verified independently.
The verification tools require ONLY:

1. The transcript files (JSON)
2. The contribution files (or hashes)
3. Network access to drand beacon (or cached beacon values)

No secret material is needed to verify the ceremony.

## Related Documentation

- `docs/05_zk_redaction.md` - ZK proof system architecture
- `docs/adr/0002-halo2-proof-system.md` - Groth16 vs Halo2 decision
- `proofs/setup_circuits.sh` - Development setup (NOT for production)
- `tools/groth16_setup.sh` - Single-contributor setup (NOT for production)

## Non-Goals

This ceremony infrastructure does NOT:

- Generate production parameters (use only as framework)
- Store toxic waste (participants must destroy their own)
- Trust any single participant
- Assume network reliability (verification is offline-capable)
