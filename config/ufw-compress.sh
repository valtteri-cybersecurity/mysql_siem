#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ "$(/usr/bin/id -u)" == 0 ]] || { printf 'UFW logrotate compressor requires root-provided descriptors.\n' >&2; exit 1; }
cd -- /usr/local/lib/mysql_siem
# Retain only logrotate's stdin/stdout capabilities; all Python and DB work is unprivileged.
exec /usr/sbin/runuser -u mysql_siem -- \
    /usr/local/lib/mysql_siem/config/run_with_env.sh \
    /opt/mysql_siem-venv/bin/python -m ingestion.ufw_compress "$@"
