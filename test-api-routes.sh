#!/usr/bin/env bash

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

BASE_URL=""
MODE="read-only"
AUTH_USER="${AUTH_USER:-simulator}"
AUTH_PASS="${AUTH_PASS:-super_safe!}"
PREFIX="${PREFIX:-apitest}"
EXISTING_USER=""
INSECURE=0
LATEST_START="${LATEST_START:-$(date +%s)}"

usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME --base-url https://your-app.example.com [options]

Options:
  --base-url URL         Base URL for the deployed app, for example https://minitwit.example.com
  --mode MODE            read-only (default) or write
  --existing-user USER   In read-only mode, also test /msgs/USER and /fllws/USER
  --prefix PREFIX        Prefix for disposable users in write mode
  --auth-user USER       Basic auth username for protected API routes
  --auth-pass PASS       Basic auth password for protected API routes
  --latest-start N       Starting value for the ?latest= query parameter
  --insecure             Pass -k to curl for self-signed TLS setups
  --help                 Show this help text

Examples:
  $SCRIPT_NAME --base-url https://minitwit.example.com
  $SCRIPT_NAME --base-url https://minitwit.example.com --mode write --prefix prodsmoke
  $SCRIPT_NAME --base-url https://minitwit.example.com --existing-user Alice

Notes:
  - read-only mode only performs GET requests and is safer for production.
  - write mode creates unique test users, posts one message, and follows/unfollows a user.
  - the script does not follow redirects, which helps expose route mismatches such as API calls
    accidentally hitting HTML handlers.
EOF
}

log() {
  printf '[info] %s\n' "$*"
}

pass() {
  printf '[pass] %s\n' "$*"
}

fail() {
  printf '[fail] %s\n' "$*" >&2
  exit 1
}

cleanup() {
  rm -f "${BODY_FILE:-}" "${HEADER_FILE:-}"
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --existing-user)
      EXISTING_USER="${2:-}"
      shift 2
      ;;
    --prefix)
      PREFIX="${2:-}"
      shift 2
      ;;
    --auth-user)
      AUTH_USER="${2:-}"
      shift 2
      ;;
    --auth-pass)
      AUTH_PASS="${2:-}"
      shift 2
      ;;
    --latest-start)
      LATEST_START="${2:-}"
      shift 2
      ;;
    --insecure)
      INSECURE=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

[[ -n "$BASE_URL" ]] || fail "Missing --base-url. Run '$SCRIPT_NAME --help' for usage."
[[ "$MODE" == "read-only" || "$MODE" == "write" ]] || fail "Invalid --mode '$MODE'. Use 'read-only' or 'write'."
[[ "$LATEST_START" =~ ^[0-9]+$ ]] || fail "--latest-start must be an integer."

BASE_URL="${BASE_URL%/}"
BODY_FILE="$(mktemp)"
HEADER_FILE="$(mktemp)"
CURRENT_STATUS=""
CURRENT_BODY=""
CURRENT_CONTENT_TYPE=""

LATEST="$LATEST_START"

next_latest() {
  local current="$LATEST"
  LATEST=$((LATEST + 1))
  printf '%s' "$current"
}

print_response() {
  local status="$1"
  local method="$2"
  local path="$3"
  local content_type="$4"

  printf '\n==> %s %s%s\n' "$method" "$BASE_URL" "$path"
  printf 'status: %s\n' "$status"
  if [[ -n "$content_type" ]]; then
    printf 'content-type: %s\n' "$content_type"
  fi

  if [[ -s "$BODY_FILE" ]]; then
    echo 'body:'
    if command -v jq >/dev/null 2>&1; then
      jq . <"$BODY_FILE" 2>/dev/null || cat "$BODY_FILE"
    else
      cat "$BODY_FILE"
    fi
  else
    echo 'body: <empty>'
  fi
}

request() {
  local method="$1"
  local path="$2"
  local expected_status="$3"
  local auth_mode="$4"
  local json_payload="${5:-}"

  local -a curl_cmd
  curl_cmd=(curl -sS -o "$BODY_FILE" -D "$HEADER_FILE" -X "$method" -H "Accept: application/json")

  if [[ "$INSECURE" -eq 1 ]]; then
    curl_cmd+=(-k)
  fi

  if [[ "$auth_mode" == "auth" ]]; then
    curl_cmd+=(-u "${AUTH_USER}:${AUTH_PASS}")
  fi

  if [[ -n "$json_payload" ]]; then
    curl_cmd+=(-H "Content-Type: application/json" --data "$json_payload")
  fi

  curl_cmd+=("${BASE_URL}${path}")

  local status
  status="$("${curl_cmd[@]}" -w '%{http_code}')"
  CURRENT_STATUS="$status"
  CURRENT_BODY="$(cat "$BODY_FILE")"
  CURRENT_CONTENT_TYPE="$(awk 'BEGIN{IGNORECASE=1} /^Content-Type:/ {sub(/\r$/, "", $2); print $2; exit}' "$HEADER_FILE")"

  print_response "$status" "$method" "$path" "$CURRENT_CONTENT_TYPE"

  if [[ "$status" != "$expected_status" ]]; then
    if [[ "$path" == /register* ]] && [[ "$status" == "200" || "$status" == "302" || "$CURRENT_CONTENT_TYPE" == text/html* ]]; then
      echo "hint: /register may have been handled by the UI route instead of the JSON API route." >&2
    fi
    fail "Expected HTTP $expected_status but got $status for $method $path"
  fi
}

assert_body_contains() {
  local needle="$1"
  if [[ "$CURRENT_BODY" != *"$needle"* ]]; then
    fail "Response body did not contain expected text: $needle"
  fi
  pass "Found expected text: $needle"
}

assert_body_not_contains() {
  local needle="$1"
  if [[ "$CURRENT_BODY" == *"$needle"* ]]; then
    fail "Response body unexpectedly contained: $needle"
  fi
  pass "Confirmed response does not contain: $needle"
}

run_read_only_tests() {
  log "Running read-only API smoke tests against $BASE_URL"

  request GET "/latest" "200" "noauth"
  assert_body_contains "\"latest\""

  request GET "/msgs?latest=$(next_latest)&no=5" "200" "auth"

  if [[ -n "$EXISTING_USER" ]]; then
    request GET "/msgs/${EXISTING_USER}?latest=$(next_latest)&no=5" "200" "auth"
    assert_body_contains "\"user\":\"${EXISTING_USER}\""

    request GET "/fllws/${EXISTING_USER}?latest=$(next_latest)&no=20" "200" "auth"
    assert_body_contains "\"follows\""
  else
    log "Skipping user-specific GET checks. Pass --existing-user USER to exercise /msgs/{username} and /fllws/{username}."
  fi
}

run_write_tests() {
  log "Running write-mode API smoke tests against $BASE_URL"

  local suffix
  suffix="$(date +%s)_$RANDOM"
  local user_one="${PREFIX}_${suffix}_a"
  local user_two="${PREFIX}_${suffix}_b"
  local email_one="${user_one}@example.test"
  local email_two="${user_two}@example.test"

  request GET "/latest" "200" "noauth"
  assert_body_contains "\"latest\""

  request POST "/register?latest=$(next_latest)" "204" "auth" "{\"username\":\"${user_one}\",\"email\":\"${email_one}\",\"pwd\":\"secret123\"}"
  request POST "/register?latest=$(next_latest)" "204" "auth" "{\"username\":\"${user_two}\",\"email\":\"${email_two}\",\"pwd\":\"secret123\"}"

  request GET "/msgs?latest=$(next_latest)&no=5" "200" "auth"

  request POST "/msgs/${user_one}?latest=$(next_latest)" "204" "auth" "{\"content\":\"api smoke test from ${user_one}\"}"
  request GET "/msgs/${user_one}?latest=$(next_latest)&no=5" "200" "auth"
  assert_body_contains "\"user\":\"${user_one}\""
  assert_body_contains "api smoke test from ${user_one}"

  request POST "/fllws/${user_one}?latest=$(next_latest)" "204" "auth" "{\"follow\":\"${user_two}\"}"
  request GET "/fllws/${user_one}?latest=$(next_latest)&no=20" "200" "auth"
  assert_body_contains "\"${user_two}\""

  request POST "/fllws/${user_one}?latest=$(next_latest)" "204" "auth" "{\"unfollow\":\"${user_two}\"}"
  request GET "/fllws/${user_one}?latest=$(next_latest)&no=20" "200" "auth"
  assert_body_not_contains "\"${user_two}\""

  log "Disposable users created during this run:"
  log "  ${user_one}"
  log "  ${user_two}"
}

if [[ "$MODE" == "read-only" ]]; then
  run_read_only_tests
else
  run_write_tests
fi

pass "API smoke test completed successfully."
