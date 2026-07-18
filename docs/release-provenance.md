# Release provenance

Olympus release builds publish layered verification evidence:

- Every platform installer, with target-prefixed names that cannot collide.
- `RELEASE_ASSETS.json`, which binds the release tag and source commit to the
  exact installer and SBOM names, sizes, and SHA-256 digests.
- `SHA256SUMS` for local artifact integrity checks.
- GitHub artifact attestations for build provenance.
- CycloneDX SBOMs for the Rust desktop app and public UI.
- GitHub SBOM attestations binding those SBOMs to the release artifact set.
- An optional Olympus release-manifest commitment when `OLYMPUS_API_URL` is
  configured for the release workflow.

`RELEASE_ASSETS.json` and `SHA256SUMS` establish consistency between the files
and metadata in a downloaded release set. If an attacker replaces both files
together, those checks alone do not establish where the artifacts originated.
Authenticity therefore depends on an independently trusted GitHub attestation
or another trusted release channel. This is the release-artifact form of the
[threat model's key and trust-channel boundary](threat-model.md#what-olympus-does-not-protect-against).

The release workflow refuses an empty or partial platform matrix. Tag builds
create or reuse a draft GitHub Release without replacing prior assets. A retry
accepts an existing asset name only when its checksum matches the new file;
missing, conflicting, or extra assets fail closed. The workflow then verifies
the exact downloaded set, produces attestations, and publishes only after every
check passes. Publishing triggers the Olympus anchoring workflow, which accepts
only the exact files named by `RELEASE_ASSETS.json`; missing, modified, extra,
or stale assets fail before a ledger manifest can be built.

## Signing configuration

Tagged Windows builds require real Authenticode credentials and fail closed if
any value is missing:

- `WINDOWS_CERTIFICATE_BASE64` secret: base64-encoded PFX containing exactly
  one private-key code-signing certificate.
- `WINDOWS_CERTIFICATE_PASSWORD` secret: password for that PFX.
- `WINDOWS_TIMESTAMP_URL` repository variable: absolute HTTPS timestamp-server
  URL.

CI imports the certificate into the runner's current-user certificate store,
configures Tauri with its thumbprint, and verifies the application, MSI, and
NSIS signatures and timestamps before upload. Tauri's
`TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` settings
are updater-signing values only; this workflow does not use them and they do not
produce Windows Authenticode signatures. This workflow makes no EV claim:
operators using a hardware-backed EV or modern OV service must configure
Tauri's custom `signCommand` for that provider and retain the same post-build
signature and timestamp checks.

Verify downloaded release assets locally:

```bash
scripts/verify-release.sh --dir <downloaded-assets> --level 1
```

On Windows:

```powershell
pwsh scripts/verify-release.ps1 -Dir <downloaded-assets> -Level 1
```

Levels are cumulative:

- Level 1 verifies `SHA256SUMS` and works offline.
- Level 2 also verifies GitHub artifact attestations with `gh`.
- Level 3 also requires CycloneDX SBOM JSON files and verifies attestations.
- Level 4 also runs the deployment-specific Olympus commitment check named by
  `OLYMPUS_RELEASE_PROOF_CMD`.

Level 4 is intentionally deployment-specific because Olympus nodes may use
different public API URLs, authentication policies, and release-manifest
publication conventions.
