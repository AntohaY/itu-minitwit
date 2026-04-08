#!/bin/sh
set -eu

RETENTION_DAYS="${RSYSLOG_RETENTION_DAYS:-7}"
CLEANUP_INTERVAL_SECONDS="${RSYSLOG_CLEANUP_INTERVAL_SECONDS:-3600}"

mkdir -p /var/lib/rsyslog /var/log/remote

cleanup_old_logs() {
  find /var/log/remote -type f -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
}

cleanup_old_logs

while true; do
  sleep "${CLEANUP_INTERVAL_SECONDS}"
  cleanup_old_logs
done &

exec rsyslogd -n -f /etc/rsyslog.conf
