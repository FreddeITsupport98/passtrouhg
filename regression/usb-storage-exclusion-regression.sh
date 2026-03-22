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

assert_eq() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (expected="%s", got="%s")\n' "$name" "$expected" "$actual" >&2
    fail=1
  fi
}

assert_contains_text() {
  local name="$1" pattern="$2" haystack="$3"
  if grep -Fq -- "$pattern" <<<"$haystack"; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (pattern not found: %s)\n' "$name" "$pattern" >&2
    fail=1
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

# Deterministic classification for this regression fixture.
usb_sysfs_device_is_bluetooth() { return 1; }
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
  local path="$1"
  cat >"$path" <<'EOF'
MATCH_MODE="auto"
INCLUDE_IDS=""
EXCLUDE_IDS=""
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

# Case 1: Missing storage at first, choose re-entry path, then include storage.
case1_conf="$tmp_dir/case1-match.conf"
case1_input="$tmp_dir/case1-input.txt"
case1_out="$tmp_dir/case1-prompt.txt"
case1_stdout="$tmp_dir/case1-stdout.txt"
case1_stderr="$tmp_dir/case1-stderr.txt"
make_match_conf "$case1_conf"
cat >"$case1_input" <<'EOF'
2
1 2
EOF
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(0 0)
CONFIRM_RESPONSES=()
run_case "case1-reenter-includes-storage" "$case1_conf" "$case1_input" "$case1_out" "$case1_stdout" "$case1_stderr"
case1_exclude_ids="$(extract_exclude_ids "$case1_conf")"
case1_stdout_text="$(cat "$case1_stdout")"
assert_eq "case1 excludes both ids after re-entry" "aaaa:0001,bbbb:0002" "$case1_exclude_ids"
assert_eq "case1 prompt_yn called twice (re-enter + apply)" "2" "$prompt_yn_calls"
assert_eq "case1 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_contains_text "case1 danger warning shown" "DANGER: Some storage devices are NOT excluded from unbind." "$case1_stdout_text"

# Case 2: Missing storage, decline re-entry, accept explicit risk phrase.
case2_conf="$tmp_dir/case2-match.conf"
case2_input="$tmp_dir/case2-input.txt"
case2_out="$tmp_dir/case2-prompt.txt"
case2_stdout="$tmp_dir/case2-stdout.txt"
case2_stderr="$tmp_dir/case2-stderr.txt"
make_match_conf "$case2_conf"
cat >"$case2_input" <<'EOF'
2
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
assert_eq "case2 keeps non-storage-only exclusion when risk accepted" "bbbb:0002" "$case2_exclude_ids"
assert_eq "case2 prompt_yn called twice (storage prompt + apply)" "2" "$prompt_yn_calls"
assert_eq "case2 confirm_phrase called once" "1" "$confirm_phrase_calls"
assert_eq "case2 confirm prompt matches expected safety warning" "Proceeding without excluding all storage devices is risky." "$last_confirm_prompt"
assert_eq "case2 confirm phrase matches expected safety phrase" "I ACCEPT STORAGE RISK" "$last_confirm_phrase"
assert_contains_text "case2 danger warning shown" "DANGER: Some storage devices are NOT excluded from unbind." "$case2_stdout_text"

# Case 3: Missing storage, decline re-entry, reject risk phrase, then re-enter and include storage.
case3_conf="$tmp_dir/case3-match.conf"
case3_input="$tmp_dir/case3-input.txt"
case3_out="$tmp_dir/case3-prompt.txt"
case3_stdout="$tmp_dir/case3-stdout.txt"
case3_stderr="$tmp_dir/case3-stderr.txt"
make_match_conf "$case3_conf"
cat >"$case3_input" <<'EOF'
2
1 2
EOF
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(1 0)
CONFIRM_RESPONSES=(1)
run_case "case3-reject-risk-then-reenter" "$case3_conf" "$case3_input" "$case3_out" "$case3_stdout" "$case3_stderr"
case3_exclude_ids="$(extract_exclude_ids "$case3_conf")"
case3_stdout_text="$(cat "$case3_stdout")"
assert_eq "case3 final exclusions include storage after rejected risk confirmation" "aaaa:0001,bbbb:0002" "$case3_exclude_ids"
assert_eq "case3 prompt_yn called twice (storage prompt + apply)" "2" "$prompt_yn_calls"
assert_eq "case3 confirm_phrase called once" "1" "$confirm_phrase_calls"
assert_contains_text "case3 rejected-risk note shown" "Risk confirmation not accepted; please choose exclusions again." "$case3_stdout_text"
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
1 2
1
EOF
prompt_yn_calls=0
confirm_phrase_calls=0
PROMPT_RESPONSES=(1 0)
CONFIRM_RESPONSES=()
run_case "case5-decline-apply-then-reselect" "$case5_conf" "$case5_input" "$case5_out" "$case5_stdout" "$case5_stderr"
case5_exclude_ids="$(extract_exclude_ids "$case5_conf")"
case5_stdout_text="$(cat "$case5_stdout")"
assert_eq "case5 final exclusions reflect reselection after decline" "aaaa:0001" "$case5_exclude_ids"
assert_eq "case5 prompt_yn called twice for two apply decisions" "2" "$prompt_yn_calls"
assert_eq "case5 confirm_phrase not called" "0" "$confirm_phrase_calls"
assert_contains_text "case5 reselection message shown" "Selection not applied; re-enter numbers to adjust your choices." "$case5_stdout_text"
assert_contains_text "case5 mode summary header shown" "Mode summary per listed device:" "$case5_stdout_text"
assert_contains_text "case5 host-bound mode label shown" "[HOST-BOUND]" "$case5_stdout_text"
assert_contains_text "case5 vm-eligible mode label shown" "[VM-ELIGIBLE]" "$case5_stdout_text"

if (( fail != 0 )); then
  exit 1
fi
printf 'USB storage exclusion regression checks passed.\n'
