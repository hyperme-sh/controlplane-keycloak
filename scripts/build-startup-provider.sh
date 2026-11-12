#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -d /usr/lib/jvm/java-21-openjdk-amd64 ]]; then
  export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
  export PATH="$JAVA_HOME/bin:$PATH"
fi
mvn -B -ntp -f keycloak/startup-provider/pom.xml verify
