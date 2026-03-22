#!/usr/bin/env bash
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

assert_contains() {
  local name="$1" pattern="$2" file="$3"
  if grep -Fq -- "$pattern" "$file"; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (pattern not found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  fi
}

assert_not_contains() {
  local name="$1" pattern="$2" file="$3"
  if grep -Fq -- "$pattern" "$file"; then
    printf 'FAIL: %s (unexpected pattern found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  else
    printf 'PASS: %s\n' "$name"
  fi
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# Test 1: parser extracts only connected outputs.
sample_query=$'Screen 0: minimum 8 x 8, current 3840 x 2160, maximum 32767 x 32767\nHDMI-1 connected primary 1920x1080+0+0\nDP-1 connected 1920x1080+1920+0\nDP-2 disconnected\n'
parsed_outputs="$(printf '%s\n' "$sample_query" | openbox_connected_outputs_from_xrandr_query | paste -sd',' -)"
assert_eq "xrandr parser connected outputs" "HDMI-1,DP-1" "${parsed_outputs:-}"

# Test 2: activation calls xrandr --output <name> --auto for each connected output.
mock_log="${tmp_dir}/mock-xrandr.log"
mock_xrandr="${tmp_dir}/mock-xrandr.sh"
cat >"$mock_xrandr" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--query" ]]; then
  cat <<'Q'
Screen 0: minimum 8 x 8, current 4480 x 1440, maximum 32767 x 32767
HDMI-1 connected primary 2560x1440+0+0
DP-1 connected 1920x1080+2560+0
DP-2 disconnected
Q
  exit 0
fi

if [[ "${1:-}" == "--output" && -n "${2:-}" && "${3:-}" == "--auto" ]]; then
  printf '%s\n' "$2" >>"${XRANDR_LOG:?XRANDR_LOG not set}"
  exit 0
fi

exit 0
EOF
chmod +x "$mock_xrandr"
XRANDR_LOG="$mock_log" DISPLAY=:99 openbox_activate_all_connected_monitors "$mock_xrandr"
activated_outputs="$(sort "$mock_log" | paste -sd',' -)"
assert_eq "activation runs --auto for all connected outputs" "DP-1,HDMI-1" "${activated_outputs:-}"

# Test 3: autostart hook is additive + idempotent and removable.
OPENBOX_MONITOR_SCRIPT="${tmp_dir}/vfio-openbox-activate-monitors.sh"
OPENBOX_AUTOSTART_FILE="${tmp_dir}/openbox/autostart"
# shellcheck disable=SC2034
DRY_RUN=0
mkdir -p "$(dirname "$OPENBOX_AUTOSTART_FILE")"
cat >"$OPENBOX_MONITOR_SCRIPT" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$OPENBOX_MONITOR_SCRIPT"
cat >"$OPENBOX_AUTOSTART_FILE" <<'EOF'
# Existing Openbox autostart content
nm-applet &
EOF

install_openbox_autostart_hook
install_openbox_autostart_hook
assert_contains "autostart keeps existing lines" "nm-applet &" "$OPENBOX_AUTOSTART_FILE"

begin_count="$(grep -Fxc "# BEGIN VFIO OPENBOX MONITOR AUTO-ACTIVATE" "$OPENBOX_AUTOSTART_FILE" || true)"
end_count="$(grep -Fxc "# END VFIO OPENBOX MONITOR AUTO-ACTIVATE" "$OPENBOX_AUTOSTART_FILE" || true)"
assert_eq "autostart begin marker appears once" "1" "${begin_count:-0}"
assert_eq "autostart end marker appears once" "1" "${end_count:-0}"

remove_openbox_autostart_hook
assert_not_contains "remove hook clears begin marker" "# BEGIN VFIO OPENBOX MONITOR AUTO-ACTIVATE" "$OPENBOX_AUTOSTART_FILE"
assert_not_contains "remove hook clears end marker" "# END VFIO OPENBOX MONITOR AUTO-ACTIVATE" "$OPENBOX_AUTOSTART_FILE"
assert_contains "remove hook preserves existing lines" "nm-applet &" "$OPENBOX_AUTOSTART_FILE"

if (( fail != 0 )); then
  printf '\nFAIL SUMMARY (%d)\n' "${#FAILED_ASSERTIONS[@]}" >&2
  for failed_assertion in "${FAILED_ASSERTIONS[@]}"; do
    printf ' - %s\n' "$failed_assertion" >&2
  done
  exit 1
fi
printf 'Openbox monitor regression checks passed.\n'
