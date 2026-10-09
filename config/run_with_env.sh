#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

set -a
source "$PROJECT_DIR/config/mysql.env"
set +a

exec "$@"
