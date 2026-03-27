#!/usr/bin/env bash
# Convention: this regression overrides sourced vfio.sh helpers that are invoked indirectly.
# shellcheck disable=SC2317,SC2329
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
VFIO_SCRIPT="${PROJECT_ROOT}/vfio.sh"

if [[ ! -f "$VFIO_SCRIPT" ]]; then
  printf 'FAIL: missing vfio.sh at %s\n' "$VFIO_SCRIPT" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$VFIO_SCRIPT"

fail=0
FAILED_ASSERTIONS=()

record_failure() {
  local name="$1"
  FAILED_ASSERTIONS+=("$name")
  fail=1
}

assert_eq() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (expected="%s", got="%s")\n' "$name" "$expected" "$actual" >&2
    record_failure "$name"
  fi
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

CONF_FILE="$tmp_dir/vfio-gpu-passthrough.conf"

detect_display_manager() { echo "none"; }
display_manager_dependency_status() { echo "NOT_PRESENT"; }
xorg_stack_status() { echo "WORKS"; }
wayland_stack_status() { echo "NOT_PRESENT"; }
x11_wayland_support_status() { echo "WORKS"; }
x11_wayland_supported_mode() { echo "X11"; }
openbox_stack_status() { echo "WORKS"; }
i3_stack_status() { echo "NOT_PRESENT"; }
bspwm_stack_status() { echo "NOT_PRESENT"; }
awesome_stack_status() { echo "NOT_PRESENT"; }
dwm_stack_status() { echo "NOT_PRESENT"; }
qtile_stack_status() { echo "NOT_PRESENT"; }
xfwm4_stack_status() { echo "NOT_PRESENT"; }
accountsservice_is_present() { return 1; }
opensuse_like_detection_reason() { return 1; }
detect_bootloader() { echo "grub"; }
vfio_config_health() {
  printf 'STATUS=OK\n'
}
bls_fallback_entry_detect_status() {
  cat <<'EOF'
STATUS=NOT_APPLICABLE
REASON=
SOURCE_ENTRY=
TARGET_ENTRY=
EOF
}

json_number_for_key() {
  local key="$1" json="$2"
  printf '%s\n' "$json" | sed -nE "s/^[[:space:]]*\"${key}\":[[:space:]]*([0-9]+),?$/\\1/p" | head -n1
}

run_detect_json() {
  JSON_OUTPUT=1 detect_existing_vfio_report
}

default_retention_days="${GRAPHICS_WATCHDOG_RETENTION_DAYS_DEFAULT:-10}"
default_max_lines="${GRAPHICS_WATCHDOG_MAX_LINES_DEFAULT:-5000}"

# --- Test 1: valid persisted values are surfaced in detect JSON.
cat >"$CONF_FILE" <<'EOF'
GRAPHICS_PROTOCOL_MODE="AUTO"
VFIO_GRAPHICS_DAEMON_INTERVAL="7"
VFIO_GRAPHICS_WATCHDOG_RETENTION_DAYS="21"
VFIO_GRAPHICS_WATCHDOG_MAX_LINES="12345"
EOF

json_output="$(run_detect_json)"
assert_eq \
  "detect JSON uses persisted watchdog retention when value is valid" \
  "21" \
  "$(json_number_for_key "configured_graphics_watchdog_retention_days" "$json_output")"
assert_eq \
  "detect JSON uses persisted watchdog max-lines when value is valid" \
  "12345" \
  "$(json_number_for_key "configured_graphics_watchdog_max_lines" "$json_output")"

# --- Test 2: missing config falls back to defaults in detect JSON.
rm -f "$CONF_FILE"
json_output="$(run_detect_json)"
assert_eq \
  "detect JSON falls back to default watchdog retention when config is missing" \
  "$default_retention_days" \
  "$(json_number_for_key "configured_graphics_watchdog_retention_days" "$json_output")"
assert_eq \
  "detect JSON falls back to default watchdog max-lines when config is missing" \
  "$default_max_lines" \
  "$(json_number_for_key "configured_graphics_watchdog_max_lines" "$json_output")"

# --- Test 3: invalid persisted values fall back to defaults in detect JSON.
cat >"$CONF_FILE" <<'EOF'
GRAPHICS_PROTOCOL_MODE="AUTO"
VFIO_GRAPHICS_DAEMON_INTERVAL="7"
VFIO_GRAPHICS_WATCHDOG_RETENTION_DAYS="999"
VFIO_GRAPHICS_WATCHDOG_MAX_LINES="100"
EOF

json_output="$(run_detect_json)"
assert_eq \
  "detect JSON falls back to default watchdog retention when persisted value is out of range" \
  "$default_retention_days" \
  "$(json_number_for_key "configured_graphics_watchdog_retention_days" "$json_output")"
assert_eq \
  "detect JSON falls back to default watchdog max-lines when persisted value is out of range" \
  "$default_max_lines" \
  "$(json_number_for_key "configured_graphics_watchdog_max_lines" "$json_output")"

if (( fail != 0 )); then
  printf '\nFAIL SUMMARY (%d)\n' "${#FAILED_ASSERTIONS[@]}" >&2
  for failed_assertion in "${FAILED_ASSERTIONS[@]}"; do
    printf ' - %s\n' "$failed_assertion" >&2
  done
  exit 1
fi

printf 'Watchdog detect-default regression checks passed.\n'
