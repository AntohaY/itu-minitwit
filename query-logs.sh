#!/usr/bin/env bash
set -euo pipefail

COMPOSE_CMD="docker compose"
COLLECTOR_SERVICE="central-rsyslog"
LOG_ROOT="/var/log/remote"

usage() {
  cat <<'EOF'
Usage:
  ./query-logs.sh list
  ./query-logs.sh hosts
  ./query-logs.sh services [host]
  ./query-logs.sh path <service> [host]
  ./query-logs.sh tail <service> [n] [host]
  ./query-logs.sh follow <service> [host]
  ./query-logs.sh errors <service> [host]
  ./query-logs.sh warn <service> [host]
  ./query-logs.sh rid <request_id> <service> [host]
  ./query-logs.sh search <pattern> <service> [host]
  ./query-logs.sh count <level> <service> [host]

Examples:
  ./query-logs.sh list
  ./query-logs.sh services viktorio
  ./query-logs.sh tail itu-minitwit-webserver-1 100
  ./query-logs.sh errors itu-minitwit-webserver-1
  ./query-logs.sh rid abcd1234 itu-minitwit-webserver-1
  ./query-logs.sh count error itu-minitwit-webserver-1
EOF
}

run_in_collector() {
  $COMPOSE_CMD exec -T "$COLLECTOR_SERVICE" sh -c "$1"
}

default_host() {
  run_in_collector "ls -1 $LOG_ROOT 2>/dev/null | head -n 1"
}

require_service() {
  if [[ -z "${1:-}" ]]; then
    echo "Missing service name" >&2
    usage
    exit 1
  fi
}

resolve_host() {
  local host_arg="${1:-}"
  if [[ -n "$host_arg" ]]; then
    echo "$host_arg"
    return
  fi
  default_host
}

service_log_path() {
  local service="$1"
  local host="$2"
  echo "$LOG_ROOT/$host/$service.log"
}

cmd="${1:-}"
shift || true

case "$cmd" in
  list)
    run_in_collector "find $LOG_ROOT -type f | sort"
    ;;
  hosts)
    run_in_collector "ls -1 $LOG_ROOT | sort"
    ;;
  services)
    host="$(resolve_host "${1:-}")"
    run_in_collector "find $LOG_ROOT/$host -maxdepth 1 -type f -name '*.log' -printf '%f\n' | sed 's/\.log$//' | sort"
    ;;
  path)
    require_service "${1:-}"
    service="$1"
    host="$(resolve_host "${2:-}")"
    service_log_path "$service" "$host"
    ;;
  tail)
    require_service "${1:-}"
    service="$1"
    lines="${2:-50}"
    host="$(resolve_host "${3:-}")"
    path="$(service_log_path "$service" "$host")"
    run_in_collector "tail -n $lines '$path'"
    ;;
  follow)
    require_service "${1:-}"
    service="$1"
    host="$(resolve_host "${2:-}")"
    path="$(service_log_path "$service" "$host")"
    run_in_collector "tail -f '$path'"
    ;;
  errors)
    require_service "${1:-}"
    service="$1"
    host="$(resolve_host "${2:-}")"
    path="$(service_log_path "$service" "$host")"
    run_in_collector "grep -i '\"level\":\"error\"' '$path' | tail -n 100"
    ;;
  warn)
    require_service "${1:-}"
    service="$1"
    host="$(resolve_host "${2:-}")"
    path="$(service_log_path "$service" "$host")"
    run_in_collector "grep -i '\"level\":\"warn\"' '$path' | tail -n 100"
    ;;
  rid)
    if [[ $# -lt 2 ]]; then
      echo "Usage: ./query-logs.sh rid <request_id> <service> [host]" >&2
      exit 1
    fi
    rid="$1"
    service="$2"
    host="$(resolve_host "${3:-}")"
    path="$(service_log_path "$service" "$host")"
    run_in_collector "grep -F '$rid' '$path' | tail -n 100"
    ;;
  search)
    if [[ $# -lt 2 ]]; then
      echo "Usage: ./query-logs.sh search <pattern> <service> [host]" >&2
      exit 1
    fi
    pattern="$1"
    service="$2"
    host="$(resolve_host "${3:-}")"
    path="$(service_log_path "$service" "$host")"
    run_in_collector "grep -Ei '$pattern' '$path' | tail -n 100"
    ;;
  count)
    if [[ $# -lt 2 ]]; then
      echo "Usage: ./query-logs.sh count <level> <service> [host]" >&2
      exit 1
    fi
    level="$1"
    service="$2"
    host="$(resolve_host "${3:-}")"
    path="$(service_log_path "$service" "$host")"
    run_in_collector "grep -ic '\"level\":\"$level\"' '$path'"
    ;;
  ""|help|-h|--help)
    usage
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage
    exit 1
    ;;
esac
