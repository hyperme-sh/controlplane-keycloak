#!/usr/bin/env bash
# CI-only toolchain setup: immutable Maven bytes, no system-package mirror.
set -euo pipefail
: "${RUNNER_TEMP:?CI temporary directory required}"
: "${GITHUB_PATH:?CI path output required}"
archive=$(mktemp "$RUNNER_TEMP/maven.XXXXXX.tar.gz")
trap 'rm -f "$archive"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 120 --retry 2 \
  https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.tar.gz \
  --output "$archive"
printf '%s  %s\n' \
  bcfe4fe305c962ace56ac7b5fc7a08b87d5abd8b7e89027ab251069faebee516b0ded8961445d6d91ec1985dfe30f8153268843c89aa392733d1a3ec956c9978 \
  "$archive" | sha512sum --check --status
tar -xzf "$archive" -C "$RUNNER_TEMP"
printf '%s\n' "$RUNNER_TEMP/apache-maven-3.9.11/bin" >> "$GITHUB_PATH"
