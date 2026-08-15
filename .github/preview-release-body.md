# Olympus Ledger — PREVIEW BUILD. NOT FOR PRODUCTION USE.

Built from a **single-contributor development trusted setup**. The multi-party
ceremony has not happened yet. Proofs produced by this build carry no soundness
guarantee: whoever holds that setup's toxic waste could forge them.

Do not use this to record evidence you intend to rely on. Databases created by a
preview build are disposable and will not carry across to v1.

- Channel: `preview` · Tag: `__TAG__` · Commit: `__SHA__`
- Ceremony: `__CEREMONY_ID__` (single contributor)
- Code signing: **none** on Windows and macOS (see below)
- This build refuses to start under `OLYMPUS_ENV=production` — by design.

It installs as **Olympus Ledger Preview** with its own data directory, so it
will not collide with a production build you install later. Nothing carries
across between the two.

## Install

### Windows

Download the `.msi` (or the `.exe` NSIS installer). SmartScreen will warn that
the publisher is unknown, because these binaries are unsigned.
Click **More info** → **Run anyway**.

### macOS

Download the `.dmg` for your architecture — `aarch64` for Apple Silicon,
`x86_64` for Intel. Gatekeeper will refuse it as "damaged" or from an
unidentified developer, because these binaries are neither signed nor notarized.

Clear the quarantine attribute after dragging it to Applications:

```bash
xattr -cr "/Applications/Olympus Ledger Preview.app"
```

Then right-click the app → **Open** → **Open** in the dialog. A plain
double-click will not offer the override. Both steps are needed: clearing
quarantine handles the "damaged" message, the right-click handles the
unidentified-developer block.

### Linux

Download the `.deb`, `.rpm`, or `.AppImage`. The AppImage needs the executable
bit set:

```bash
chmod +x x86_64-unknown-linux-gnu--Olympus*.AppImage
```

## Verify what you downloaded

Checksums plus GitHub build-provenance and SBOM attestations are attached to
this release.

```bash
sha256sum -c SHA256SUMS
```

```bash
gh attestation verify <installer> --repo OlympusLedgerOrg/Olympus
```

`scripts/verify-release.sh --level 3` runs the layered check (checksums →
provenance attestation → SBOM attestation).

## Reporting

Preview-build issues are welcome:
<https://github.com/OlympusLedgerOrg/Olympus/issues>
