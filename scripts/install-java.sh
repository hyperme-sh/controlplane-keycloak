#!/usr/bin/env bash
# CI-only Temurin JDK; immutable official release bytes, no added action trust.
set -euo pipefail
: "${RUNNER_TEMP:?CI temporary directory required}"
: "${GITHUB_PATH:?CI path output required}"
: "${GITHUB_ENV:?CI environment output required}"
archive=$(mktemp "$RUNNER_TEMP/java.XXXXXX.tar.gz")
java_root=''
published=false
cleanup() {
  rm -f "$archive"
  if [[ "$published" != true && -n "$java_root" ]]; then rm -rf "$java_root"; fi
}
trap cleanup EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 120 --retry 2 \
  'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13.1%2B2/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13.1_2.tar.gz' \
  --output "$archive"
printf '%s  %s\n' \
  bb8a93f9ae6e7a693b2b721e85dbeff26ae1a77447985a8d7afcdd9c7cf6222e \
  "$archive" | sha256sum --check --status
java_root=$(mktemp -d "$RUNNER_TEMP/java.XXXXXX")
tar -xzf "$archive" --strip-components=1 -C "$java_root"
"$java_root/bin/javac" --version
printf 'JAVA_HOME=%s\n' "$java_root" >> "$GITHUB_ENV"
printf '%s\n' "$java_root/bin" >> "$GITHUB_PATH"
published=true
