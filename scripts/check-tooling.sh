#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC
uv lock --check
uv sync --frozen --python 3.13
uv run --frozen python -m compileall -q keycloak
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
uv run --frozen pytest -q tests tests_tools --junitxml="$scratch/source.xml"
uv run --frozen python scripts/build_archive.py "$scratch"
uv run --frozen python scripts/export_release_contract.py "$scratch/controlplane-keycloak.tar.gz" --output "$scratch/contract"
# Historical qualification manifests describe their original archive. Current
# PRs validate the archive built above against this checkout and its tests.

uv export --frozen --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
(cd "$scratch/extracted" && "$scratch/venv/bin/python" -I -m pytest -q -c pyproject.toml tests tests_tools --junitxml="$scratch/archive.xml")

python3 scripts/verify-test-results.py "$scratch/source.xml" "$scratch/archive.xml"
if [[ -n "${TEST_EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$TEST_EVIDENCE_DIR"
  cp "$scratch/source.xml" "$scratch/archive.xml" "$scratch/contract/evidence.json" "$TEST_EVIDENCE_DIR/"
fi

# Retain the exact validated bytes for the release channel; never rebuild them.
if [[ -n "${RELEASE_ARTIFACT_DIR:-}" ]]; then
  mkdir -p "$RELEASE_ARTIFACT_DIR"
  cp "$scratch/controlplane-keycloak.tar.gz" "$RELEASE_ARTIFACT_DIR/"
fi
