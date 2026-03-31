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

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

usb_fake_root="$tmp_dir/usb-devices"
mkdir -p "$usb_fake_root"

write_fake_usb_device() {
  local name="$1" vid="$2" pid="$3" manufacturer="$4" product="$5"
  local d="$usb_fake_root/$name"
  mkdir -p "$d"
  printf '%s\n' "$vid" >"$d/idVendor"
  printf '%s\n' "$pid" >"$d/idProduct"
  printf '%s\n' "$manufacturer" >"$d/manufacturer"
  printf '%s\n' "$product" >"$d/product"
}

write_fake_usb_device "1-1" "aaaa" "0001" "SanDisk" "Portable SSD"
write_fake_usb_device "1-2" "bbbb" "0002" "Logitech" "USB Receiver"
write_fake_usb_device "1-4" "2357" "0604" "TP-Link" "Bluetooth USB Adapter"

if usb_sysfs_device_is_bluetooth "$usb_fake_root/1-4"; then
  case0_bt_name_detected="yes"
else
  case0_bt_name_detected="no"
fi
assert_eq "case0 bluetooth text fallback detects adapter by product/manufacturer name" "yes" "$case0_bt_name_detected"
if usb_sysfs_device_is_bluetooth "$usb_fake_root/1-2"; then
  case0_non_bt_text_detected="yes"
else
  case0_non_bt_text_detected="no"
fi
assert_eq "case0 bluetooth text fallback does not misclassify non-bluetooth receiver name" "no" "$case0_non_bt_text_detected"
rm -rf "$usb_fake_root/1-4"

# Deterministic classification for this regression fixture.
BT_USB_DEVICE_NAME=""
usb_sysfs_device_is_bluetooth() {
  [[ "$(basename "$1")" == "${BT_USB_DEVICE_NAME:-}" ]]
}
usb_sysfs_device_is_ethernet() {
  [[ "$(basename "$1")" == "1-2" ]]
}
usb_sysfs_device_is_printer() { return 1; }
usb_sysfs_device_is_storage() {
  [[ "$(basename "$1")" == "1-1" ]]
}

prompt_yn_calls=0
confirm_phrase_calls=0
last_confirm_prompt=""
last_confirm_phrase=""
PROMPT_RESPONSES=()
CONFIRM_RESPONSES=()

prompt_yn() {
  prompt_yn_calls=$((prompt_yn_calls + 1))
  local rc=1
  if (( ${#PROMPT_RESPONSES[@]} > 0 )); then
    rc="${PROMPT_RESPONSES[0]}"
    PROMPT_RESPONSES=("${PROMPT_RESPONSES[@]:1}")
  fi
  return "$rc"
}

confirm_phrase() {
  confirm_phrase_calls=$((confirm_phrase_calls + 1))
  last_confirm_prompt="${1:-}"
  last_confirm_phrase="${2:-}"
  local rc=1
  if (( ${#CONFIRM_RESPONSES[@]} > 0 )); then
    rc="${CONFIRM_RESPONSES[0]}"
    CONFIRM_RESPONSES=("${CONFIRM_RESPONSES[@]:1}")
  fi
  return "$rc"
}

make_match_conf() {
  local path="$1" match_mode="${2:-auto}" include_ids="${3:-}" exclude_ids="${4:-}"
  cat >"$path" <<EOF
MATCH_MODE="$match_mode"
INCLUDE_IDS="$include_ids"
EXCLUDE_IDS="$exclude_ids"
EOF
}

extract_exclude_ids() {
  local path="$1"
  awk -F= '/^EXCLUDE_IDS=/{gsub(/"/,"",$2); print $2; exit}' "$path"
}

run_case() {
  local case_name="$1" conf="$2" input_file="$3" out_file="$4" stdout_file="$5" stderr_file="$6" enable_color="${7:-0}"
  USB_BT_MATCH_CONF="$conf"
  VFIO_USB_SYSFS_GLOB="$usb_fake_root/*"
  VFIO_INTERACTIVE_IN="$input_file"
  VFIO_INTERACTIVE_OUT="$out_file"
  ENABLE_COLOR="$enable_color"
  configure_usb_bt_exclude_ids_interactive >"$stdout_file" 2>"$stderr_file"
  printf 'PASS: %s executed\n' "$case_name"
}

# Case 1: Interlock mode - storage selected first, choose re-entry path, then keep storage host-bound.
case1_conf="$tmp_dir/case1-match.conf"
case1_input="$tmp_dir/case1-input.txt"
case1_out="$tmp_dir/case1-prompt.txt"
case1_stdout="$tmp_dir/case1-stdout.txt"
case1_stderr="$tmp_dir/case1-stderr.txt"
make_match_conf "$case1_conf" "include_only"
cat >"$case1_input" <<'EOF'
1
2
EOF
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0 0)
CONFIRM_RESPONSES=()
run_case "case1-reenter-removes-storage" "$case1_conf" "$case1_input" "$case1_out" "$case1_stdout" "$case1_stderr"
case1_exclude_ids="$(extract_exclude_ids "$case1_conf")"
case1_stdout_text="$(cat "$case1_stdout")"
assert_eq "case1 keeps storage host-bound after re-entry" "aaaa:0001" "$case1_exclude_ids"
assert_eq "case1 prompt_yn called twice (re-enter + apply)" "2" "$prompt_yn_calls"
assert_eq "case1 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_contains_text "case1 danger warning shown" "DANGER: Some storage devices are selected as VM-eligible detach targets." "$case1_stdout_text"

# Case 2: Interlock mode - storage selected, decline re-entry, accept explicit risk phrase.
case2_conf="$tmp_dir/case2-match.conf"
case2_input="$tmp_dir/case2-input.txt"
case2_out="$tmp_dir/case2-prompt.txt"
case2_stdout="$tmp_dir/case2-stdout.txt"
case2_stderr="$tmp_dir/case2-stderr.txt"
make_match_conf "$case2_conf" "include_only"
cat >"$case2_input" <<'EOF'
1
EOF
prompt_yn_calls=0
confirm_phrase_calls=0
last_confirm_prompt=""
last_confirm_phrase=""
PROMPT_RESPONSES=(1 0)
CONFIRM_RESPONSES=(0)
run_case "case2-accept-risk-phrase" "$case2_conf" "$case2_input" "$case2_out" "$case2_stdout" "$case2_stderr"
case2_exclude_ids="$(extract_exclude_ids "$case2_conf")"
case2_stdout_text="$(cat "$case2_stdout")"
assert_eq "case2 keeps non-selected non-storage host-bound when risk accepted" "bbbb:0002" "$case2_exclude_ids"
assert_eq "case2 prompt_yn called twice (storage prompt + apply)" "2" "$prompt_yn_calls"
assert_eq "case2 confirm_phrase called once" "1" "$confirm_phrase_calls"
assert_eq "case2 confirm prompt matches expected safety warning" "Proceeding with storage devices marked VM-eligible is risky." "$last_confirm_prompt"
assert_eq "case2 confirm phrase matches expected safety phrase" "I ACCEPT STORAGE RISK" "$last_confirm_phrase"
assert_contains_text "case2 danger warning shown" "DANGER: Some storage devices are selected as VM-eligible detach targets." "$case2_stdout_text"

# Case 3: Interlock mode - storage selected, decline re-entry, reject risk phrase, then re-enter safe choice.
case3_conf="$tmp_dir/case3-match.conf"
case3_input="$tmp_dir/case3-input.txt"
case3_out="$tmp_dir/case3-prompt.txt"
case3_stdout="$tmp_dir/case3-stdout.txt"
case3_stderr="$tmp_dir/case3-stderr.txt"
make_match_conf "$case3_conf" "include_only"
cat >"$case3_input" <<'EOF'
1
2
EOF
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(1 0)
CONFIRM_RESPONSES=(1)
run_case "case3-reject-risk-then-reenter" "$case3_conf" "$case3_input" "$case3_out" "$case3_stdout" "$case3_stderr"
case3_exclude_ids="$(extract_exclude_ids "$case3_conf")"
case3_stdout_text="$(cat "$case3_stdout")"
assert_eq "case3 final exclusions keep storage host-bound after rejected risk confirmation" "aaaa:0001" "$case3_exclude_ids"
assert_eq "case3 prompt_yn called twice (storage prompt + apply)" "2" "$prompt_yn_calls"
assert_eq "case3 confirm_phrase called once" "1" "$confirm_phrase_calls"
assert_contains_text "case3 rejected-risk note shown" "Risk confirmation not accepted; please choose VM-eligible devices again." "$case3_stdout_text"
# Case 4: Color-enabled rendering colorizes entry numbers to match category priority.
case4_conf="$tmp_dir/case4-match.conf"
case4_input="$tmp_dir/case4-input.txt"
case4_out="$tmp_dir/case4-prompt.txt"
case4_stdout="$tmp_dir/case4-stdout.txt"
case4_stderr="$tmp_dir/case4-stderr.txt"
make_match_conf "$case4_conf"
cat >"$case4_input" <<'EOF'
1 2
EOF
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0)
CONFIRM_RESPONSES=()
run_case "case4-colorized-indexes" "$case4_conf" "$case4_input" "$case4_out" "$case4_stdout" "$case4_stderr" 1
case4_stdout_text="$(cat "$case4_stdout")"
case4_storage_index="${C_BOLD}${C_RED}[1]${C_RESET}"
case4_ethernet_index="${C_BOLD}${C_GREEN}[2]${C_RESET}"
assert_contains_text "case4 storage entry index uses red category color" "$case4_storage_index" "$case4_stdout_text"
assert_contains_text "case4 non-storage entry index uses green ethernet color" "$case4_ethernet_index" "$case4_stdout_text"

# Case 5: Decline apply at review, then re-enter and apply updated selection.
case5_conf="$tmp_dir/case5-match.conf"
case5_input="$tmp_dir/case5-input.txt"
case5_out="$tmp_dir/case5-prompt.txt"
case5_stdout="$tmp_dir/case5-stdout.txt"
case5_stderr="$tmp_dir/case5-stderr.txt"
make_match_conf "$case5_conf"
cat >"$case5_input" <<'EOF'
2
EOF
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(1 0)
CONFIRM_RESPONSES=()
run_case "case5-decline-apply-then-reselect" "$case5_conf" "$case5_input" "$case5_out" "$case5_stdout" "$case5_stderr"
case5_exclude_ids="$(extract_exclude_ids "$case5_conf")"
case5_stdout_text="$(cat "$case5_stdout")"
assert_eq "case5 final exclusions reflect reselection after decline" "aaaa:0001,bbbb:0002" "$case5_exclude_ids"
assert_eq "case5 prompt_yn called twice for two apply decisions" "2" "$prompt_yn_calls"
assert_eq "case5 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_contains_text "case5 reselection message shown" "Selection not applied; re-enter numbers to adjust your choices." "$case5_stdout_text"
assert_contains_text "case5 mode summary header shown" "Mode summary per listed device:" "$case5_stdout_text"
assert_contains_text "case5 host-bound mode label shown" "[HOST-BOUND]" "$case5_stdout_text"
assert_contains_text "case5 vm-eligible mode label shown" "[VM-ELIGIBLE]" "$case5_stdout_text"
# Case 6: Default Bluetooth-only policy - storage VM-selection stays informational (no hard interlock).
case6_conf="$tmp_dir/case6-match.conf"
case6_input="$tmp_dir/case6-input.txt"
case6_out="$tmp_dir/case6-prompt.txt"
case6_stdout="$tmp_dir/case6-stdout.txt"
case6_stderr="$tmp_dir/case6-stderr.txt"
make_match_conf "$case6_conf" "auto" ""
cat >"$case6_input" <<'EOF'
1
EOF
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0)
CONFIRM_RESPONSES=()
run_case "case6-default-policy-info-only" "$case6_conf" "$case6_input" "$case6_out" "$case6_stdout" "$case6_stderr"
case6_exclude_ids="$(extract_exclude_ids "$case6_conf")"
case6_stdout_text="$(cat "$case6_stdout")"
assert_eq "case6 keeps non-selected non-storage host-bound in default policy" "bbbb:0002" "$case6_exclude_ids"
assert_eq "case6 prompt_yn called once for apply only" "1" "$prompt_yn_calls"
assert_eq "case6 confirm_phrase not called in default policy" "0" "$confirm_phrase_calls"
assert_contains_text "case6 info note shown for selected storage" "Info: some storage devices are selected as VM-eligible." "$case6_stdout_text"
assert_contains_text "case6 policy note clarifies bluetooth-only behavior" "Current policy is Bluetooth-only (MATCH_MODE=auto with empty INCLUDE_IDS), so non-Bluetooth storage devices are not detach targets." "$case6_stdout_text"
assert_not_contains_text "case6 danger warning not shown in default policy" "DANGER: Some storage devices are selected as VM-eligible detach targets." "$case6_stdout_text"
# Case 7: Default Bluetooth-only policy with Bluetooth-focused view selected.
case7_conf="$tmp_dir/case7-match.conf"
case7_input="$tmp_dir/case7-input.txt"
case7_out="$tmp_dir/case7-prompt.txt"
case7_stdout="$tmp_dir/case7-stdout.txt"
case7_stderr="$tmp_dir/case7-stderr.txt"
make_match_conf "$case7_conf" "auto" ""
cat >"$case7_input" <<'EOF'
1
EOF
BT_USB_DEVICE_NAME="1-2"
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(1 0)
CONFIRM_RESPONSES=()
run_case "case7-focused-view-number-mapping" "$case7_conf" "$case7_input" "$case7_out" "$case7_stdout" "$case7_stderr"
case7_exclude_ids="$(extract_exclude_ids "$case7_conf")"
case7_stdout_text="$(cat "$case7_stdout")"
assert_eq "case7 focused view maps [1] to bluetooth entry and keeps storage host-bound" "aaaa:0001" "$case7_exclude_ids"
assert_eq "case7 prompt_yn called twice (view choice + apply)" "2" "$prompt_yn_calls"
assert_eq "case7 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_contains_text "case7 focused-view note shown" "Bluetooth-focused view is active (showing likely detach targets)." "$case7_stdout_text"
assert_contains_text "case7 focused view shows bluetooth entry" "1-2 bbbb:0002" "$case7_stdout_text"
assert_not_contains_text "case7 focused view hides non-bluetooth entry from list" "1-1 aaaa:0001" "$case7_stdout_text"

# Case 8: Default Bluetooth-only policy with full USB list selected explicitly.
case8_conf="$tmp_dir/case8-match.conf"
case8_input="$tmp_dir/case8-input.txt"
case8_out="$tmp_dir/case8-prompt.txt"
case8_stdout="$tmp_dir/case8-stdout.txt"
case8_stderr="$tmp_dir/case8-stderr.txt"
make_match_conf "$case8_conf" "auto" ""
cat >"$case8_input" <<'EOF'
1
EOF
BT_USB_DEVICE_NAME="1-2"
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0 0)
CONFIRM_RESPONSES=()
run_case "case8-full-view-available" "$case8_conf" "$case8_input" "$case8_out" "$case8_stdout" "$case8_stderr"
case8_exclude_ids="$(extract_exclude_ids "$case8_conf")"
case8_stdout_text="$(cat "$case8_stdout")"
assert_eq "case8 full view keeps non-selected non-storage host-bound after selecting [1]" "bbbb:0002" "$case8_exclude_ids"
assert_eq "case8 prompt_yn called twice (view choice + apply)" "2" "$prompt_yn_calls"
assert_eq "case8 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_not_contains_text "case8 focused-view note absent when full list chosen" "Bluetooth-focused view is active (showing likely detach targets)." "$case8_stdout_text"
assert_contains_text "case8 full view includes non-bluetooth entry" "1-1 aaaa:0001" "$case8_stdout_text"
assert_contains_text "case8 full view includes bluetooth entry" "1-2 bbbb:0002" "$case8_stdout_text"

# Case 9: Start focused, switch to full list in-loop via command, then select from expanded view.
case9_conf="$tmp_dir/case9-match.conf"
case9_input="$tmp_dir/case9-input.txt"
case9_out="$tmp_dir/case9-prompt.txt"
case9_stdout="$tmp_dir/case9-stdout.txt"
case9_stderr="$tmp_dir/case9-stderr.txt"
make_match_conf "$case9_conf" "auto" ""
cat >"$case9_input" <<'EOF'
full
1
EOF
BT_USB_DEVICE_NAME="1-2"
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(1 0)
CONFIRM_RESPONSES=()
run_case "case9-inloop-switch-to-full" "$case9_conf" "$case9_input" "$case9_out" "$case9_stdout" "$case9_stderr"
case9_exclude_ids="$(extract_exclude_ids "$case9_conf")"
case9_stdout_text="$(cat "$case9_stdout")"
assert_eq "case9 in-loop full switch allows selecting non-bluetooth entry index" "bbbb:0002" "$case9_exclude_ids"
assert_eq "case9 prompt_yn called twice (view choice + apply)" "2" "$prompt_yn_calls"
assert_eq "case9 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_contains_text "case9 switch confirmation shown" "Switched to full USB list view." "$case9_stdout_text"
assert_not_contains_text "case9 command input not treated as invalid token" "Ignoring invalid token: full" "$case9_stdout_text"
assert_contains_text "case9 expanded full view includes non-bluetooth entry" "1-1 aaaa:0001" "$case9_stdout_text"
assert_contains_text "case9 expanded full view includes bluetooth entry" "1-2 bbbb:0002" "$case9_stdout_text"

# Case 10: Decline apply while toggle-capable view is active should print quick command reminder.
case10_conf="$tmp_dir/case10-match.conf"
case10_input="$tmp_dir/case10-input.txt"
case10_out="$tmp_dir/case10-prompt.txt"
case10_stdout="$tmp_dir/case10-stdout.txt"
case10_stderr="$tmp_dir/case10-stderr.txt"
make_match_conf "$case10_conf" "auto" ""
cat >"$case10_input" <<'EOF'
1
1
EOF
BT_USB_DEVICE_NAME="1-2"
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(1 1 0)
CONFIRM_RESPONSES=()
run_case "case10-decline-shows-toggle-reminder" "$case10_conf" "$case10_input" "$case10_out" "$case10_stdout" "$case10_stderr"
case10_exclude_ids="$(extract_exclude_ids "$case10_conf")"
case10_stdout_text="$(cat "$case10_stdout")"
assert_eq "case10 final exclusions after decline/reselect in focused view" "aaaa:0001" "$case10_exclude_ids"
assert_eq "case10 prompt_yn called three times (view choice + decline apply + accept apply)" "3" "$prompt_yn_calls"
assert_eq "case10 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_contains_text "case10 post-decline quick toggle reminder shown" "Quick view switch: type 'full' for all USB devices or 'focus' for Bluetooth-focused entries." "$case10_stdout_text"

# Case 11: Missing match config should be auto-recreated and saved without crashing.
case11_conf="$tmp_dir/case11-match.conf"
case11_input="$tmp_dir/case11-input.txt"
case11_out="$tmp_dir/case11-prompt.txt"
case11_stdout="$tmp_dir/case11-stdout.txt"
case11_stderr="$tmp_dir/case11-stderr.txt"
rm -f "$case11_conf"
cat >"$case11_input" <<'EOF'
1
EOF
BT_USB_DEVICE_NAME=""
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0)
CONFIRM_RESPONSES=()
run_case "case11-missing-config-autorecover" "$case11_conf" "$case11_input" "$case11_out" "$case11_stdout" "$case11_stderr"
case11_exclude_ids="$(extract_exclude_ids "$case11_conf")"
case11_stdout_text="$(cat "$case11_stdout")"
if [[ -f "$case11_conf" ]]; then
  case11_conf_present="yes"
else
  case11_conf_present="no"
fi
assert_eq "case11 recreated missing match config" "yes" "$case11_conf_present"
assert_eq "case11 persisted exclusions after recreate" "bbbb:0002" "$case11_exclude_ids"
assert_eq "case11 prompt_yn called once for apply" "1" "$prompt_yn_calls"
assert_eq "case11 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_contains_text "case11 recreate note shown" "USB Bluetooth match config was missing; recreating defaults at:" "$case11_stdout_text"
BT_USB_DEVICE_NAME=""
# Case 12: Unchanged VM-eligible selection should keep EXCLUDE_IDS unchanged and skip write.
case12_conf="$tmp_dir/case12-match.conf"
case12_input="$tmp_dir/case12-input.txt"
case12_out="$tmp_dir/case12-prompt.txt"
case12_stdout="$tmp_dir/case12-stdout.txt"
case12_stderr="$tmp_dir/case12-stderr.txt"
make_match_conf "$case12_conf" "auto" "" "aaaa:0001"
cat >"$case12_input" <<'EOF'
2
EOF
BT_USB_DEVICE_NAME=""
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0)
CONFIRM_RESPONSES=()
run_case "case12-idempotent-unchanged-selection" "$case12_conf" "$case12_input" "$case12_out" "$case12_stdout" "$case12_stderr"
case12_exclude_ids="$(extract_exclude_ids "$case12_conf")"
case12_stdout_text="$(cat "$case12_stdout")"
assert_eq "case12 keeps EXCLUDE_IDS unchanged when selection is unchanged" "aaaa:0001" "$case12_exclude_ids"
assert_eq "case12 marks USB_BT_EXCLUDE_CHANGED as unchanged" "0" "${USB_BT_EXCLUDE_CHANGED:-}"
assert_eq "case12 prompt_yn called once for apply" "1" "$prompt_yn_calls"
assert_eq "case12 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_contains_text "case12 unchanged-selection note shown" "EXCLUDE_IDS unchanged; skipping write." "$case12_stdout_text"

# Case 13: Installer rerun should keep unchanged helper/unit/rule files untouched and avoid immediate restart.
case13_root="$tmp_dir/case13-installer"
case13_helper="$case13_root/vfio-usb-bluetooth.sh"
case13_unit="$case13_root/vfio-disable-usb-bluetooth.service"
case13_rule="$case13_root/99-vfio-disable-usb-bluetooth.rules"
case13_conf="$case13_root/vfio-usb-bluetooth-match.conf"
case13_run1_stdout="$tmp_dir/case13-run1-stdout.txt"
case13_run1_stderr="$tmp_dir/case13-run1-stderr.txt"
case13_run2_stdout="$tmp_dir/case13-run2-stdout.txt"
case13_run2_stderr="$tmp_dir/case13-run2-stderr.txt"
case13_write_log="$tmp_dir/case13-write.log"
case13_run_log="$tmp_dir/case13-run.log"
mkdir -p "$case13_root"
: >"$case13_write_log"
: >"$case13_run_log"

USB_BT_SCRIPT="$case13_helper"
USB_BT_SYSTEMD_UNIT="$case13_unit"
USB_BT_UDEV_RULE="$case13_rule"
USB_BT_MATCH_CONF="$case13_conf"
DRY_RUN=0

run() {
  printf '%s\n' "$*" >>"$case13_run_log"
  return 0
}
write_file_atomic_if_changed() {
  local dst="$1" mode="$2" tmp
  : "${3:-}"
  : "${4:-}"
  tmp="$(mktemp)"
  cat >"$tmp"
  mkdir -p "$(dirname "$dst")"
  if [[ -f "$dst" ]] && cmp -s "$tmp" "$dst"; then
    rm -f "$tmp" || true
    return 1
  fi
  install -m "$mode" "$tmp" "$dst"
  rm -f "$tmp" || true
  printf '%s\n' "$dst" >>"$case13_write_log"
  return 0
}

PROMPT_RESPONSES=(1)
CONFIRM_RESPONSES=()
prompt_yn_calls=0
confirm_phrase_calls=0
: >"$case13_run_log"
install_usb_bluetooth_disable >"$case13_run1_stdout" 2>"$case13_run1_stderr"
if [[ -f "$case13_helper" ]]; then
  case13_helper_present="yes"
else
  case13_helper_present="no"
fi
if bash -n "$case13_helper" >/dev/null 2>&1; then
  case13_helper_syntax="ok"
else
  case13_helper_syntax="bad"
fi
case13_helper_text="$(cat "$case13_helper")"
assert_eq "case13 generated helper script file exists" "yes" "$case13_helper_present"
assert_eq "case13 generated helper script passes bash syntax check" "ok" "$case13_helper_syntax"
assert_contains_text "case13 helper uses generic driver unbind path" "/sys/bus/usb/drivers/\$drv/unbind" "$case13_helper_text"
assert_contains_text "case13 helper uses generic USB drivers_probe rebind path" "/sys/bus/usb/drivers_probe" "$case13_helper_text"
assert_contains_text "case13 helper keeps include_only detach gate" "[[ \"\$MATCH_MODE\" == \"include_only\" ]]" "$case13_helper_text"
assert_contains_text "case13 helper emits scope marker for matched devices" "scope=\${target_scope}" "$case13_helper_text"
assert_contains_text "case13 helper includes bluetooth text fallback detection" "grep -Eq '(bluetooth)' <<<\"\$text_hint\"" "$case13_helper_text"
assert_contains_text "case13 helper normalizes bluetooth-service toggle flag" "USB_BT_STOP_BLUETOOTH_SERVICE=\"\$(normalize_bool_flag \"\${USB_BT_STOP_BLUETOOTH_SERVICE:-1}\")\"" "$case13_helper_text"
assert_contains_text "case13 helper normalizes hard-block toggle flag" "USB_BT_HARD_BLOCK=\"\$(normalize_bool_flag \"\${USB_BT_HARD_BLOCK:-0}\")\"" "$case13_helper_text"
assert_contains_text "case13 helper includes hard-block policy matcher" "device_matches_usb_bt_hard_block_policy()" "$case13_helper_text"
assert_contains_text "case13 helper includes USB authorized-state helper" "set_usb_device_authorized_state()" "$case13_helper_text"
assert_contains_text "case13 helper includes bluetooth service transition helper" "maybe_toggle_bluetooth_service()" "$case13_helper_text"
assert_contains_text "case13 helper emits hard_block state marker for matched devices" "hard_block=\${hard_block_state}" "$case13_helper_text"
case13_conf_text_after_first="$(cat "$case13_conf")"
assert_contains_text "case13 match config includes stop-bluetooth-service key" "USB_BT_STOP_BLUETOOTH_SERVICE=\"1\"" "$case13_conf_text_after_first"
assert_contains_text "case13 match config includes hard-block key" "USB_BT_HARD_BLOCK=\"0\"" "$case13_conf_text_after_first"
assert_contains_text "case13 match config includes hard-block IDs key" "USB_BT_HARD_BLOCK_IDS=\"\"" "$case13_conf_text_after_first"
case13_helper_write_count_after_first="$(grep -Fc -- "$case13_helper" "$case13_write_log" || true)"
case13_unit_write_count_after_first="$(grep -Fc -- "$case13_unit" "$case13_write_log" || true)"
case13_rule_write_count_after_first="$(grep -Fc -- "$case13_rule" "$case13_write_log" || true)"
assert_eq "case13 first run writes helper once" "1" "$case13_helper_write_count_after_first"
assert_eq "case13 first run writes unit once" "1" "$case13_unit_write_count_after_first"
assert_eq "case13 first run writes udev rule once" "1" "$case13_rule_write_count_after_first"
case13_run1_log_text="$(cat "$case13_run_log")"
case13_run1_stdout_text="$(cat "$case13_run1_stdout")"
assert_contains_text "case13 first run enables and starts service" "systemctl enable --now vfio-disable-usb-bluetooth.service" "$case13_run1_log_text"
assert_contains_text "case13 first run prints bluetooth-service integration summary" "Configured bluetooth.service stop/start integration: <enabled>" "$case13_run1_stdout_text"
assert_contains_text "case13 first run prints hard-block summary" "Configured aggressive USB hard-block IDs: <disabled>" "$case13_run1_stdout_text"
# Seed a preconfigured exclusion policy to simulate real rerun state.
make_match_conf "$case13_conf" "auto" "" "aaaa:0001"

PROMPT_RESPONSES=(1)
CONFIRM_RESPONSES=()
prompt_yn_calls=0
confirm_phrase_calls=0
: >"$case13_run_log"
install_usb_bluetooth_disable >"$case13_run2_stdout" 2>"$case13_run2_stderr"
case13_helper_write_count_after_second="$(grep -Fc -- "$case13_helper" "$case13_write_log" || true)"
case13_unit_write_count_after_second="$(grep -Fc -- "$case13_unit" "$case13_write_log" || true)"
case13_rule_write_count_after_second="$(grep -Fc -- "$case13_rule" "$case13_write_log" || true)"
assert_eq "case13 second run does not rewrite unchanged helper" "1" "$case13_helper_write_count_after_second"
assert_eq "case13 second run does not rewrite unchanged unit" "1" "$case13_unit_write_count_after_second"
assert_eq "case13 second run does not rewrite unchanged udev rule" "1" "$case13_rule_write_count_after_second"
assert_eq "case13 second run asks only preconfigured reconfigure prompt" "1" "$prompt_yn_calls"
assert_eq "case13 second run does not use confirm_phrase" "0" "$confirm_phrase_calls"
case13_run2_log_text="$(cat "$case13_run_log")"
case13_run2_stdout_text="$(cat "$case13_run2_stdout")"
assert_contains_text "case13 second run keeps service enabled without immediate run" "systemctl enable vfio-disable-usb-bluetooth.service" "$case13_run2_log_text"
assert_not_contains_text "case13 second run does not issue enable --now when unchanged" "systemctl enable --now vfio-disable-usb-bluetooth.service" "$case13_run2_log_text"
assert_contains_text "case13 second run prints unchanged-start skip note" "USB Bluetooth settings unchanged; skipping immediate service run." "$case13_run2_stdout_text"
assert_contains_text "case13 second run detects existing preconfigured policy" "Detected existing USB Bluetooth mitigation configuration in:" "$case13_run2_stdout_text"
assert_contains_text "case13 second run keeps preconfigured policy when reconfigure declined" "Keeping existing USB Bluetooth exclusions/policy without reconfiguration." "$case13_run2_stdout_text"
assert_not_contains_text "case13 second run does not enter picker when reconfigure declined" "USB Bluetooth mitigation exclusions" "$case13_run2_stdout_text"
# Case 14: Hard-block interactive flow enables scoped VID:PID patterns and ignores invalid tokens.
case14_conf="$tmp_dir/case14-hard-block.conf"
case14_input="$tmp_dir/case14-hard-block-input.txt"
case14_out="$tmp_dir/case14-hard-block-prompt.txt"
case14_stdout="$tmp_dir/case14-hard-block-stdout.txt"
case14_stderr="$tmp_dir/case14-hard-block-stderr.txt"
cat >"$case14_conf" <<'EOF'
MATCH_MODE="auto"
INCLUDE_IDS=""
EXCLUDE_IDS=""
USB_BT_STOP_BLUETOOTH_SERVICE="1"
USB_BT_HARD_BLOCK="0"
USB_BT_HARD_BLOCK_IDS=""
USB_ETHERNET_EEE_OFF="0"
USB_ETHERNET_EEE_IDS=""
EOF
cat >"$case14_input" <<'EOF'
aaaa:0001 bbbb:* invalid-token
EOF
USB_BT_MATCH_CONF="$case14_conf"
VFIO_INTERACTIVE_IN="$case14_input"
VFIO_INTERACTIVE_OUT="$case14_out"
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0)
CONFIRM_RESPONSES=()
configure_usb_bt_hard_block_interactive >"$case14_stdout" 2>"$case14_stderr"
case14_hard_block="$(awk -F= '/^USB_BT_HARD_BLOCK=/{gsub(/"/,"",$2); print $2; exit}' "$case14_conf")"
case14_hard_block_ids="$(awk -F= '/^USB_BT_HARD_BLOCK_IDS=/{gsub(/"/,"",$2); print $2; exit}' "$case14_conf")"
case14_stdout_text="$(cat "$case14_stdout")"
assert_eq "case14 hard-block interactive enables hard-block flag" "1" "$case14_hard_block"
assert_eq "case14 hard-block interactive persists normalized scoped IDs" "aaaa:0001,bbbb:*" "$case14_hard_block_ids"
assert_eq "case14 hard-block interactive marks changed state" "1" "${USB_BT_HARD_BLOCK_CHANGED:-}"
assert_eq "case14 hard-block interactive uses one yes/no prompt" "1" "$prompt_yn_calls"
assert_contains_text "case14 hard-block interactive prints configured scope summary" "Configured aggressive USB hard-block IDs: aaaa:0001,bbbb:*" "$case14_stdout_text"
assert_contains_text "case14 hard-block interactive reports invalid token skip" "Ignoring invalid token: invalid-token" "$case14_stdout_text"

# Case 15: Installer summary should reflect non-default bluetooth-service/hard-block policy values.
case15_root="$tmp_dir/case15-installer-summary"
case15_helper="$case15_root/vfio-usb-bluetooth.sh"
case15_unit="$case15_root/vfio-disable-usb-bluetooth.service"
case15_rule="$case15_root/99-vfio-disable-usb-bluetooth.rules"
case15_conf="$case15_root/vfio-usb-bluetooth-match.conf"
case15_stdout="$tmp_dir/case15-installer-stdout.txt"
case15_stderr="$tmp_dir/case15-installer-stderr.txt"
mkdir -p "$case15_root"
cat >"$case15_conf" <<'EOF'
MATCH_MODE="auto"
INCLUDE_IDS=""
EXCLUDE_IDS=""
USB_BT_STOP_BLUETOOTH_SERVICE="0"
USB_BT_HARD_BLOCK="1"
USB_BT_HARD_BLOCK_IDS="aaaa:0001"
USB_ETHERNET_EEE_OFF="0"
USB_ETHERNET_EEE_IDS=""
EOF
touch "$case15_unit"
USB_BT_SCRIPT="$case15_helper"
USB_BT_SYSTEMD_UNIT="$case15_unit"
USB_BT_UDEV_RULE="$case15_rule"
USB_BT_MATCH_CONF="$case15_conf"
VFIO_USB_SYSFS_GLOB="$usb_fake_root/*"
BT_USB_DEVICE_NAME="1-2"
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(1)
CONFIRM_RESPONSES=()
install_usb_bluetooth_disable >"$case15_stdout" 2>"$case15_stderr"
case15_stdout_text="$(cat "$case15_stdout")"
assert_eq "case15 installer summary asks one reconfigure prompt when preconfigured policy exists" "1" "$prompt_yn_calls"
assert_contains_text "case15 installer summary reports bluetooth.service integration disabled" "Configured bluetooth.service stop/start integration: <disabled>" "$case15_stdout_text"
assert_contains_text "case15 installer summary reports scoped hard-block IDs" "Configured aggressive USB hard-block IDs: aaaa:0001" "$case15_stdout_text"
assert_contains_text "case15 installer summary still reports EEE-off disabled state" "Configured USB Ethernet EEE-off IDs: <disabled>" "$case15_stdout_text"
assert_contains_text "case15 installer summary prints effective target section" "==== USB mitigation effective targets ====" "$case15_stdout_text"
assert_contains_text "case15 effective target list includes mitigate-tagged bluetooth device" "[MITIGATE]" "$case15_stdout_text"
assert_contains_text "case15 effective target summary totals are present" "Summary totals: scanned=" "$case15_stdout_text"

# Case 16: bluetooth.service guard interactive flow should allow disabling integration.
case16_conf="$tmp_dir/case16-service-guard.conf"
case16_input="$tmp_dir/case16-service-guard-input.txt"
case16_out="$tmp_dir/case16-service-guard-prompt.txt"
case16_stdout="$tmp_dir/case16-service-guard-stdout.txt"
case16_stderr="$tmp_dir/case16-service-guard-stderr.txt"
cat >"$case16_conf" <<'EOF'
MATCH_MODE="auto"
INCLUDE_IDS=""
EXCLUDE_IDS=""
USB_BT_STOP_BLUETOOTH_SERVICE="1"
USB_BT_HARD_BLOCK="0"
USB_BT_HARD_BLOCK_IDS=""
USB_ETHERNET_EEE_OFF="0"
USB_ETHERNET_EEE_IDS=""
EOF
: >"$case16_input"
USB_BT_MATCH_CONF="$case16_conf"
VFIO_INTERACTIVE_IN="$case16_input"
VFIO_INTERACTIVE_OUT="$case16_out"
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(1)
CONFIRM_RESPONSES=()
configure_usb_bt_service_guard_interactive >"$case16_stdout" 2>"$case16_stderr"
case16_service_guard="$(awk -F= '/^USB_BT_STOP_BLUETOOTH_SERVICE=/{gsub(/"/,"",$2); print $2; exit}' "$case16_conf")"
case16_stdout_text="$(cat "$case16_stdout")"
assert_eq "case16 service-guard interactive disables bluetooth.service integration" "0" "$case16_service_guard"
assert_eq "case16 service-guard interactive marks changed state" "1" "${USB_BT_SERVICE_GUARD_CHANGED:-}"
assert_eq "case16 service-guard interactive uses one yes/no prompt" "1" "$prompt_yn_calls"
assert_contains_text "case16 service-guard interactive prints disabled summary" "Configured bluetooth.service stop/start integration: <disabled>" "$case16_stdout_text"

# Case 17: Hard-block picker lists mitigation targets and supports numbered selection like other USB flows.
case17_conf="$tmp_dir/case17-hard-block-numbered.conf"
case17_input="$tmp_dir/case17-hard-block-numbered-input.txt"
case17_out="$tmp_dir/case17-hard-block-numbered-prompt.txt"
case17_stdout="$tmp_dir/case17-hard-block-numbered-stdout.txt"
case17_stderr="$tmp_dir/case17-hard-block-numbered-stderr.txt"
cat >"$case17_conf" <<'EOF'
MATCH_MODE="include_only"
INCLUDE_IDS="aaaa:0001,bbbb:0002"
EXCLUDE_IDS=""
USB_BT_STOP_BLUETOOTH_SERVICE="1"
USB_BT_HARD_BLOCK="0"
USB_BT_HARD_BLOCK_IDS=""
USB_ETHERNET_EEE_OFF="0"
USB_ETHERNET_EEE_IDS=""
EOF
cat >"$case17_input" <<'EOF'
2
EOF
USB_BT_MATCH_CONF="$case17_conf"
VFIO_USB_SYSFS_GLOB="$usb_fake_root/*"
VFIO_INTERACTIVE_IN="$case17_input"
VFIO_INTERACTIVE_OUT="$case17_out"
BT_USB_DEVICE_NAME="1-2"
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0)
CONFIRM_RESPONSES=()
configure_usb_bt_hard_block_interactive >"$case17_stdout" 2>"$case17_stderr"
case17_hard_block="$(awk -F= '/^USB_BT_HARD_BLOCK=/{gsub(/"/,"",$2); print $2; exit}' "$case17_conf")"
case17_hard_block_ids="$(awk -F= '/^USB_BT_HARD_BLOCK_IDS=/{gsub(/"/,"",$2); print $2; exit}' "$case17_conf")"
case17_stdout_text="$(cat "$case17_stdout")"
assert_eq "case17 hard-block numbered picker enables hard-block flag" "1" "$case17_hard_block"
assert_eq "case17 hard-block numbered picker persists selected listed ID" "bbbb:0002" "$case17_hard_block_ids"
assert_eq "case17 hard-block numbered picker uses one yes/no prompt" "1" "$prompt_yn_calls"
assert_contains_text "case17 hard-block numbered picker prints target list heading" "Detected mitigation-eligible USB targets under current policy:" "$case17_stdout_text"
assert_contains_text "case17 hard-block numbered picker shows first listed target line" "[1] 1-1 aaaa:0001 SanDisk Portable SSD [danger: Storage]" "$case17_stdout_text"
assert_contains_text "case17 hard-block numbered picker shows bluetooth hint for listed target" "[2] 1-2 bbbb:0002 Logitech USB Receiver [hint: Bluetooth detected] [keep-bound: Ethernet]" "$case17_stdout_text"
assert_contains_text "case17 hard-block numbered picker confirms selected ID" "Configured aggressive USB hard-block IDs: bbbb:0002" "$case17_stdout_text"
# Case 18: Effective target summary should never show [HARD-BLOCK] on host-bound devices.
case18_conf="$tmp_dir/case18-hard-block-summary.conf"
case18_stdout="$tmp_dir/case18-hard-block-summary-stdout.txt"
case18_stderr="$tmp_dir/case18-hard-block-summary-stderr.txt"
cat >"$case18_conf" <<'EOF'
MATCH_MODE="include_only"
INCLUDE_IDS="bbbb:0002"
EXCLUDE_IDS="aaaa:0001"
USB_BT_STOP_BLUETOOTH_SERVICE="1"
USB_BT_HARD_BLOCK="1"
USB_BT_HARD_BLOCK_IDS=""
USB_ETHERNET_EEE_OFF="0"
USB_ETHERNET_EEE_IDS=""
EOF
USB_BT_MATCH_CONF="$case18_conf"
VFIO_USB_SYSFS_GLOB="$usb_fake_root/*"
BT_USB_DEVICE_NAME="1-2"
ENABLE_COLOR=0
print_usb_bt_mitigation_target_summary >"$case18_stdout" 2>"$case18_stderr"
case18_stdout_text="$(cat "$case18_stdout")"
assert_contains_text "case18 summary keeps host-bound storage untagged by hard-block" "[HOST-BOUND] 1-1 aaaa:0001 SanDisk Portable SSD" "$case18_stdout_text"
assert_not_contains_text "case18 summary does not emit host-bound hard-block tag" "[HOST-BOUND][HARD-BLOCK]" "$case18_stdout_text"
assert_contains_text "case18 summary marks include-only target with mitigate+hard-block tags" "[MITIGATE][HARD-BLOCK] 1-2 bbbb:0002 Logitech USB Receiver" "$case18_stdout_text"
assert_contains_text "case18 summary totals count only mitigation-scoped hard-block targets" "Summary totals: scanned=2 mitigate=1 hard-block=1 eee-off=0" "$case18_stdout_text"
# Case 19: bluetooth.service guard unchanged branch should report explicit status.
case19_conf="$tmp_dir/case19-service-guard-unchanged.conf"
case19_input="$tmp_dir/case19-service-guard-input.txt"
case19_out="$tmp_dir/case19-service-guard-prompt.txt"
case19_stdout="$tmp_dir/case19-service-guard-stdout.txt"
case19_stderr="$tmp_dir/case19-service-guard-stderr.txt"
cat >"$case19_conf" <<'EOF'
MATCH_MODE="auto"
INCLUDE_IDS=""
EXCLUDE_IDS=""
USB_BT_STOP_BLUETOOTH_SERVICE="1"
USB_BT_HARD_BLOCK="0"
USB_BT_HARD_BLOCK_IDS=""
USB_ETHERNET_EEE_OFF="0"
USB_ETHERNET_EEE_IDS=""
EOF
: >"$case19_input"
USB_BT_MATCH_CONF="$case19_conf"
VFIO_INTERACTIVE_IN="$case19_input"
VFIO_INTERACTIVE_OUT="$case19_out"
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0)
CONFIRM_RESPONSES=()
configure_usb_bt_service_guard_interactive >"$case19_stdout" 2>"$case19_stderr"
case19_stdout_text="$(cat "$case19_stdout")"
assert_eq "case19 service-guard unchanged keeps changed flag cleared" "0" "${USB_BT_SERVICE_GUARD_CHANGED:-}"
assert_eq "case19 service-guard unchanged uses one yes/no prompt" "1" "$prompt_yn_calls"
assert_contains_text "case19 service-guard unchanged reports current enabled state" "Current status: bluetooth.service stop/start integration is enabled." "$case19_stdout_text"
assert_contains_text "case19 service-guard unchanged reports explicit unchanged status" "bluetooth.service stop/start integration remains <enabled>." "$case19_stdout_text"
# Case 20: Effective target summary should colorize state tags and legend when color output is enabled.
case20_conf="$tmp_dir/case20-colorized-summary.conf"
case20_stdout="$tmp_dir/case20-colorized-summary-stdout.txt"
case20_stderr="$tmp_dir/case20-colorized-summary-stderr.txt"
cat >"$case20_conf" <<EOF
MATCH_MODE="include_only"
INCLUDE_IDS="bbbb:0002"
EXCLUDE_IDS="aaaa:0001"
USB_BT_STOP_BLUETOOTH_SERVICE="1"
USB_BT_HARD_BLOCK="1"
USB_BT_HARD_BLOCK_IDS=""
USB_ETHERNET_EEE_OFF="1"
USB_ETHERNET_EEE_IDS="bbbb:0002"
EOF
USB_BT_MATCH_CONF="$case20_conf"
VFIO_USB_SYSFS_GLOB="$usb_fake_root/*"
BT_USB_DEVICE_NAME="1-2"
ENABLE_COLOR=1
print_usb_bt_mitigation_target_summary >"$case20_stdout" 2>"$case20_stderr"
case20_stdout_text="$(cat "$case20_stdout")"
case20_tag_mitigate="[${C_BOLD}${C_YELLOW}MITIGATE${C_RESET}]"
case20_tag_host_bound="[${C_BOLD}${C_GREEN}HOST-BOUND${C_RESET}]"
case20_tag_hard_block="[${C_BOLD}${C_RED}HARD-BLOCK${C_RESET}]"
case20_tag_eee_off="[${C_BOLD}${C_BLUE}EEE-OFF${C_RESET}]"
case20_total_mitigate="${C_BOLD}${C_YELLOW}1${C_RESET}"
case20_total_hard_block="${C_BOLD}${C_RED}1${C_RESET}"
case20_total_eee_off="${C_BOLD}${C_BLUE}1${C_RESET}"
assert_contains_text "case20 summary legend renders colorized mitigate tag" "${case20_tag_mitigate}=detach target" "$case20_stdout_text"
assert_contains_text "case20 summary legend renders colorized host-bound tag" "${case20_tag_host_bound}=not detached" "$case20_stdout_text"
assert_contains_text "case20 summary legend renders colorized hard-block tag" "${case20_tag_hard_block}=authorized 0/1 target" "$case20_stdout_text"
assert_contains_text "case20 summary legend renders colorized eee-off tag" "${case20_tag_eee_off}=USB ethernet ethtool target" "$case20_stdout_text"
assert_contains_text "case20 summary colorizes host-bound device status" "${case20_tag_host_bound} 1-1 aaaa:0001 SanDisk Portable SSD" "$case20_stdout_text"
assert_contains_text "case20 summary colorizes stacked mitigate hard-block and eee-off tags" "${case20_tag_mitigate}${case20_tag_hard_block}${case20_tag_eee_off} 1-2 bbbb:0002 Logitech USB Receiver" "$case20_stdout_text"
assert_contains_text "case20 summary totals remain correct with colorized counters" "Summary totals: scanned=2 mitigate=${case20_total_mitigate} hard-block=${case20_total_hard_block} eee-off=${case20_total_eee_off}" "$case20_stdout_text"


if (( fail != 0 )); then
  printf '\nFAIL SUMMARY (%d)\n' "${#FAILED_ASSERTIONS[@]}" >&2
  for failed_assertion in "${FAILED_ASSERTIONS[@]}"; do
    printf ' - %s\n' "$failed_assertion" >&2
  done
  exit 1
fi
printf 'USB storage exclusion regression checks passed.\n'
