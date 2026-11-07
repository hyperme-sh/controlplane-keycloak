#!/usr/bin/env bash
# Separate from offline checks: only a disposable, loopback-bound Docker realm.
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC SKIP_TESTCONTAINERS
uv lock --check
uv sync --frozen --group native --python 3.13
docker info >/dev/null
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
uv run --frozen --group native pytest -q tests_native --junitxml="$scratch/native-source.xml"
uv run --frozen --group native python scripts/build_archive.py "$scratch"
uv export --frozen --group native --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
(cd "$scratch/extracted" && "$scratch/venv/bin/python" -I -m pytest -q -c pyproject.toml tests_native --junitxml="$scratch/native-archive.xml")
python3 scripts/verify-test-results.py "$scratch/native-source.xml" "$scratch/native-archive.xml"
if [[ -n "${TEST_EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$TEST_EVIDENCE_DIR"
  cp "$scratch/native-source.xml" "$scratch/native-archive.xml" "$TEST_EVIDENCE_DIR/"
fi
