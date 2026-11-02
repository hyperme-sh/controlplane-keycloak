#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC
uv lock --check
uv sync --frozen --python 3.13
uv run --frozen python -m compileall -q keycloak
uv run --frozen pytest -q
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
uv run --frozen python scripts/build_archive.py "$scratch"
uv export --frozen --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
(cd "$scratch/extracted" && "$scratch/venv/bin/python" -I -m pytest -q -c pyproject.toml tests)
