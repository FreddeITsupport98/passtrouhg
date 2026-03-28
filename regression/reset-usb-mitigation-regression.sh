#!/usr/bin/env bash
# Convention: this regression overrides sourced vfio.sh helpers that are invoked indirectly.
# shellcheck disable=SC2034,SC2317,SC2329
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

assert_contains_text() {
  local name="$1" pattern="$2" haystack="$3"
  if grep -Fq -- "$pattern" <<<"$haystack"; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (pattern not found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  fi
}
assert_not_contains_text() {
  local name="$1" pattern="$2" haystack="$3"
  if grep -Fq -- "$pattern" <<<"$haystack"; then
    printf 'FAIL: %s (unexpected pattern found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  else
    printf 'PASS: %s\n' "$name"
  fi
}

assert_file_exists() {
  local name="$1" file="$2"
  if [[ -f "$file" ]]; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (missing file: %s)\n' "$name" "$file" >&2
    record_failure "$name"
  fi
}
assert_file_missing() {
  local name="$1" file="$2"
  if [[ ! -f "$file" ]]; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (file unexpectedly present: %s)\n' "$name" "$file" >&2
    record_failure "$name"
  fi
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

RUN_LOG="$tmp_dir/run.log"
REQUIRE_LOG="$tmp_dir/require.log"
CONFIRM_LOG="$tmp_dir/confirm.log"
confirm_phrase_calls=0
last_confirm_prompt=""
last_confirm_phrase=""
CONFIRM_FORCE_RC=0

confirm_phrase() {
  confirm_phrase_calls=$((confirm_phrase_calls + 1))
  last_confirm_prompt="${1:-}"
  last_confirm_phrase="${2:-}"
  printf '%s\t%s\n' "$last_confirm_prompt" "$last_confirm_phrase" >>"$CONFIRM_LOG"
  return "${CONFIRM_FORCE_RC:-0}"
}

run() {
  printf '%s\n' "$*" >>"$RUN_LOG"
  local cmd="${1:-}"
  if [[ -z "$cmd" ]]; then
    return 0
  fi
  shift || true
  case "$cmd" in
    rm)
      "$cmd" "$@" 2>/dev/null || true
      ;;
    systemctl|udevadm)
      # Intentionally mocked in regression.
      return 0
      ;;
    *)
      "$cmd" "$@" 2>/dev/null || true
      ;;
  esac
}
need_cmd() {
  printf 'need_cmd %s\n' "$*" >>"$REQUIRE_LOG"
  return 0
}
require_root() {
  printf 'require_root %s\n' "$*" >>"$REQUIRE_LOG"
  return 0
}
require_systemd() {
  printf '%s\n' "require_systemd" >>"$REQUIRE_LOG"
  return 0
}
require_writable_root_or_die() {
  printf '%s\n' "require_writable_root_or_die" >>"$REQUIRE_LOG"
  return 0
}

prepare_fixture() {
  local root="$1"
  mkdir -p "$root"

  # Core VFIO artifacts (must be preserved by USB-only reset).
  CONF_FILE="$root/vfio-gpu-passthrough.conf"
  BIND_SCRIPT="$root/vfio-bind-selected-gpu.sh"
  SYSTEMD_UNIT="$root/vfio-bind-selected-gpu.service"
  MODULES_LOAD="$root/vfio.conf"
  BLACKLIST_FILE="$root/vfio-optional-blacklist.conf"
  cat >"$CONF_FILE" <<'EOF'
GUEST_GPU_BDF="0000:01:00.0"
EOF
  : >"$BIND_SCRIPT"
  : >"$SYSTEMD_UNIT"
  : >"$MODULES_LOAD"
  : >"$BLACKLIST_FILE"

  # USB mitigation artifacts (must be removed by USB-only reset).
  USB_BT_SCRIPT="$root/vfio-usb-bluetooth.sh"
  USB_BT_SYSTEMD_UNIT="$root/vfio-disable-usb-bluetooth.service"
  USB_BT_UDEV_RULE="$root/99-vfio-disable-usb-bluetooth.rules"
  USB_BT_MATCH_CONF="$root/vfio-usb-bluetooth-match.conf"
  cat >"$USB_BT_MATCH_CONF" <<'EOF'
MATCH_MODE="auto"
INCLUDE_IDS=""
EXCLUDE_IDS=""
USB_ETHERNET_EEE_OFF="1"
USB_ETHERNET_EEE_IDS="0bda:8153"
EOF
  : >"$USB_BT_SCRIPT"
  : >"$USB_BT_SYSTEMD_UNIT"
  : >"$USB_BT_UDEV_RULE"

  : >"$RUN_LOG"
  : >"$REQUIRE_LOG"
  : >"$CONFIRM_LOG"
  confirm_phrase_calls=0
  last_confirm_prompt=""
  last_confirm_phrase=""
}

# Case 1: confirmation accepted => USB artifacts removed, core VFIO preserved.
case1_root="$tmp_dir/case1"
prepare_fixture "$case1_root"
CONFIRM_FORCE_RC=0
reset_usb_mitigation_only >"$tmp_dir/case1.stdout" 2>"$tmp_dir/case1.stderr"
case1_run_log="$(cat "$RUN_LOG")"

assert_eq "case1 reset prompts exactly once for confirmation phrase" "1" "$confirm_phrase_calls"
assert_eq "case1 reset uses expected confirmation phrase text" "RESET USB MITIGATION" "$last_confirm_phrase"
assert_contains_text "case1 reset emits completion message" "USB mitigation reset complete." "$(cat "$tmp_dir/case1.stdout")"

assert_file_missing "case1 removes USB helper script" "$USB_BT_SCRIPT"
assert_file_missing "case1 removes USB systemd unit" "$USB_BT_SYSTEMD_UNIT"
assert_file_missing "case1 removes USB udev rule" "$USB_BT_UDEV_RULE"
assert_file_missing "case1 removes USB match config including EEE-off settings" "$USB_BT_MATCH_CONF"

assert_file_exists "case1 preserves core VFIO config" "$CONF_FILE"
assert_file_exists "case1 preserves core VFIO bind script" "$BIND_SCRIPT"
assert_file_exists "case1 preserves core VFIO systemd unit" "$SYSTEMD_UNIT"
assert_file_exists "case1 preserves core VFIO modules-load file" "$MODULES_LOAD"
assert_file_exists "case1 preserves core VFIO blacklist file" "$BLACKLIST_FILE"

assert_contains_text "case1 issues systemctl disable for USB mitigation service" "systemctl disable --now vfio-disable-usb-bluetooth.service" "$case1_run_log"
assert_contains_text "case1 issues rm for USB-only artifacts" "rm -f $USB_BT_SCRIPT $USB_BT_SYSTEMD_UNIT $USB_BT_UDEV_RULE $USB_BT_MATCH_CONF" "$case1_run_log"
assert_not_contains_text "case1 does not target core VFIO config for removal" "$CONF_FILE" "$case1_run_log"
assert_not_contains_text "case1 does not target core VFIO bind script for removal" "$BIND_SCRIPT" "$case1_run_log"

# Case 2: confirmation rejected => function exits non-zero and leaves artifacts intact.
case2_root="$tmp_dir/case2"
prepare_fixture "$case2_root"
CONFIRM_FORCE_RC=1
case2_rc=0
case2_err="$(
  (
    reset_usb_mitigation_only
  ) 2>&1 >/dev/null
)" || case2_rc=$?
case2_run_log="$(cat "$RUN_LOG")"

assert_eq "case2 rejected confirmation exits with code 1" "1" "$case2_rc"
assert_contains_text "case2 rejected confirmation reports cancellation" "ERROR: USB mitigation reset cancelled" "$case2_err"
assert_eq "case2 rejected confirmation performs no side-effect run commands" "" "$case2_run_log"
assert_file_exists "case2 keeps USB helper script when canceled" "$USB_BT_SCRIPT"
assert_file_exists "case2 keeps USB systemd unit when canceled" "$USB_BT_SYSTEMD_UNIT"
assert_file_exists "case2 keeps USB udev rule when canceled" "$USB_BT_UDEV_RULE"
assert_file_exists "case2 keeps USB match config when canceled" "$USB_BT_MATCH_CONF"
# Case 3: top-level CLI dispatch --reset-usb-mitigation => wired through main().
case3_root="$tmp_dir/case3"
prepare_fixture "$case3_root"
CONFIRM_FORCE_RC=0
case3_rc=0
(
  main --reset-usb-mitigation
) >"$tmp_dir/case3.stdout" 2>"$tmp_dir/case3.stderr" || case3_rc=$?
case3_run_log="$(cat "$RUN_LOG")"
case3_require_log="$(cat "$REQUIRE_LOG")"
case3_confirm_log="$(cat "$CONFIRM_LOG")"

assert_eq "case3 main reset-usb-mitigation exits with code 0" "0" "$case3_rc"
assert_contains_text "case3 main reset-usb-mitigation emits completion message" "USB mitigation reset complete." "$(cat "$tmp_dir/case3.stdout")"
assert_contains_text "case3 main reset-usb-mitigation requires root gate" "require_root --reset-usb-mitigation" "$case3_require_log"
assert_contains_text "case3 main reset-usb-mitigation requires systemd gate" "require_systemd" "$case3_require_log"
assert_contains_text "case3 main reset-usb-mitigation requires writable-root gate" "require_writable_root_or_die" "$case3_require_log"
assert_contains_text "case3 main reset-usb-mitigation reached confirmation phrase gate" "RESET USB MITIGATION" "$case3_confirm_log"

assert_file_missing "case3 main reset-usb-mitigation removes USB helper script" "$USB_BT_SCRIPT"
assert_file_missing "case3 main reset-usb-mitigation removes USB systemd unit" "$USB_BT_SYSTEMD_UNIT"
assert_file_missing "case3 main reset-usb-mitigation removes USB udev rule" "$USB_BT_UDEV_RULE"
assert_file_missing "case3 main reset-usb-mitigation removes USB match config" "$USB_BT_MATCH_CONF"
assert_file_exists "case3 main reset-usb-mitigation preserves core VFIO config" "$CONF_FILE"
assert_file_exists "case3 main reset-usb-mitigation preserves core VFIO bind script" "$BIND_SCRIPT"
assert_contains_text "case3 main reset-usb-mitigation issues systemctl disable command" "systemctl disable --now vfio-disable-usb-bluetooth.service" "$case3_run_log"
assert_contains_text "case3 main reset-usb-mitigation issues USB artifact rm command" "rm -f $USB_BT_SCRIPT $USB_BT_SYSTEMD_UNIT $USB_BT_UDEV_RULE $USB_BT_MATCH_CONF" "$case3_run_log"

if (( fail != 0 )); then
  printf '\nFAIL SUMMARY (%d)\n' "${#FAILED_ASSERTIONS[@]}" >&2
  for failed_assertion in "${FAILED_ASSERTIONS[@]}"; do
    printf ' - %s\n' "$failed_assertion" >&2
  done
  exit 1
fi
printf 'Reset USB mitigation regression checks passed.\n'
