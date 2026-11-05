#!/usr/bin/env bash
# Deployment-blocking 18+ gate. Nonzero means the gate was not applied.
# Do not fold this into configure_idp_brokers.py exit 1. That status is a
# non-fatal client warning. This script has no other steps.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/keycloak/age_confirmation.py"
