# Release provenance

Olympus release builds publish layered verification evidence:

- `SHA256SUMS` for local artifact integrity checks.
- GitHub artifact attestations for build provenance.
- CycloneDX SBOMs for the Rust desktop app and public UI.
- GitHub SBOM attestations binding those SBOMs to the release artifact set.
- An optional Olympus release-manifest commitment when `OLYMPUS_API_URL` is
  configured for the release workflow.

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
