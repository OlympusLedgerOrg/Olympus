#!/usr/bin/env bash
# Verify Olympus release artifacts in layered mode:
#   level 1: local SHA256SUMS only
#   level 2: GitHub artifact provenance attestations
#   level 3: SBOM presence/JSON checks plus GitHub attestation verification
#   level 4: caller-provided Olympus commitment check

set -euo pipefail

REPO="${GITHUB_REPOSITORY:-OlympusLedgerOrg/Olympus}"
DIR="."
LEVEL="1"
CHECKSUM_FILE=""

usage() {
  cat <<'EOF'
Usage: scripts/verify-release.sh [--dir DIR] [--repo OWNER/REPO] [--level 1|2|3|4] [--checksums FILE]

Levels:
  1  Verify SHA256SUMS locally. This is fully offline.
  2  Also verify GitHub artifact provenance attestations with gh.
  3  Also require CycloneDX SBOM JSON files and verify attestations with gh.
  4  Also run OLYMPUS_RELEASE_PROOF_CMD, if configured.

For level 4, set OLYMPUS_RELEASE_PROOF_CMD to the exact command that verifies
the release manifest commitment for your deployment.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dir)
      DIR="${2:?missing --dir value}"
      shift 2
      ;;
    --repo)
      REPO="${2:?missing --repo value}"
      shift 2
      ;;
    --level)
      LEVEL="${2:?missing --level value}"
      shift 2
      ;;
    --checksums)
      CHECKSUM_FILE="${2:?missing --checksums value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$LEVEL" in
  1|2|3|4) ;;
  *)
    echo "--level must be 1, 2, 3, or 4" >&2
    exit 2
    ;;
esac

cd "$DIR"

if [ -z "$CHECKSUM_FILE" ]; then
  CHECKSUM_FILE="SHA256SUMS"
fi
if [ ! -f "$CHECKSUM_FILE" ]; then
  echo "missing checksum file: $CHECKSUM_FILE" >&2
  exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

while read -r digest path; do
  [ -n "${digest:-}" ] || continue
  [ "${digest#\#}" = "$digest" ] || continue
  path="${path#\*}"
  candidate="$path"
  if [ ! -f "$candidate" ]; then
    base="$(basename "$path")"
    candidate="$base"
  fi
  if [ ! -f "$candidate" ]; then
    found="$(find . -type f -name "$(basename "$path")" | head -n 2)"
    if [ "$(printf '%s\n' "$found" | sed '/^$/d' | wc -l | tr -d ' ')" = "1" ]; then
      candidate="$(printf '%s\n' "$found" | sed '/^$/d')"
    fi
  fi
  if [ ! -f "$candidate" ]; then
    echo "missing artifact for checksum entry: $path" >&2
    exit 1
  fi
  printf '%s  %s\n' "$digest" "$candidate" >> "$tmp"
done < "$CHECKSUM_FILE"

sha256sum -c "$tmp"
echo "level 1 ok: checksums verified"

artifact_files() {
  awk '{print $2}' "$tmp" \
    | grep -Ev '(^|/)(SHA256SUMS|.*\.cdx\.json)$' \
    | sort -u
}

if [ "$LEVEL" -ge 2 ]; then
  command -v gh >/dev/null 2>&1 || {
    echo "level 2 requires GitHub CLI (gh)" >&2
    exit 1
  }
  while IFS= read -r artifact; do
    [ -n "$artifact" ] || continue
    gh attestation verify "$artifact" --repo "$REPO"
  done < <(artifact_files)
  echo "level 2 ok: GitHub attestations verified"
fi

if [ "$LEVEL" -ge 3 ]; then
  sbom_count="$(find . -type f -name '*.cdx.json' | wc -l | tr -d ' ')"
  if [ "$sbom_count" = "0" ]; then
    echo "level 3 requires at least one CycloneDX SBOM (*.cdx.json)" >&2
    exit 1
  fi
  while IFS= read -r sbom; do
    [ -n "$sbom" ] || continue
    node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$sbom"
  done < <(find . -type f -name '*.cdx.json' | sort)
  while IFS= read -r artifact; do
    [ -n "$artifact" ] || continue
    gh attestation verify "$artifact" --repo "$REPO"
  done < <(artifact_files)
  echo "level 3 ok: SBOM JSON present and attestations verified"
fi

if [ "$LEVEL" -ge 4 ]; then
  if [ -z "${OLYMPUS_RELEASE_PROOF_CMD:-}" ]; then
    echo "level 4 requires OLYMPUS_RELEASE_PROOF_CMD" >&2
    exit 1
  fi
  bash -lc "$OLYMPUS_RELEASE_PROOF_CMD"
  echo "level 4 ok: Olympus release commitment check passed"
fi
