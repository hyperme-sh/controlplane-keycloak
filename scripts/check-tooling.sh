#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC
uv lock --check
uv sync --frozen --python 3.13
uv run --frozen python -m compileall -q keycloak
uv run --frozen pytest -q
uv run --frozen pytest -q tests_tools
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
uv run --frozen python scripts/build_archive.py "$scratch"
uv run --frozen python scripts/export_release_contract.py "$scratch/controlplane-keycloak.tar.gz" --output "$scratch/contract"
if [[ -f releases/candidate/release.json ]]; then
  uv run --frozen python scripts/verify_release_candidate.py releases/candidate/release.json "$scratch/contract/contract.json" "$scratch/contract/evidence.json" controlplane-keycloak
fi
uv export --frozen --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
(cd "$scratch/extracted" && "$scratch/venv/bin/python" -I -m pytest -q -c pyproject.toml tests tests_tools)

# Retain the exact validated bytes for the release channel; never rebuild them.
if [[ -n "${RELEASE_ARTIFACT_DIR:-}" ]]; then
  mkdir -p "$RELEASE_ARTIFACT_DIR"
  cp "$scratch/controlplane-keycloak.tar.gz" "$RELEASE_ARTIFACT_DIR/"
fi
