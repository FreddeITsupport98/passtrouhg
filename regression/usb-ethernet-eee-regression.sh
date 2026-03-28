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
assert_not_contains_text() {
  local name="$1" pattern="$2" haystack="$3"
  if grep -Fq -- "$pattern" <<<"$haystack"; then
    printf 'FAIL: %s (unexpected pattern found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  else
    printf 'PASS: %s\n' "$name"
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

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

usb_fake_root="$tmp_dir/usb-devices"
mkdir -p "$usb_fake_root"
usb_eth_dev="$usb_fake_root/4-3.4"
mkdir -p "$usb_eth_dev"
printf '%s\n' "0bda" >"$usb_eth_dev/idVendor"
printf '%s\n' "8153" >"$usb_eth_dev/idProduct"
printf '%s\n' "Realtek" >"$usb_eth_dev/manufacturer"
printf '%s\n' "USB 10/100/1000 LAN" >"$usb_eth_dev/product"

usb_sysfs_device_is_ethernet() {
  [[ "$(basename "$1")" == "4-3.4" ]]
}

prompt_yn_calls=0
PROMPT_RESPONSES=()
prompt_yn() {
  prompt_yn_calls=$((prompt_yn_calls + 1))
  local rc=1
  if (( ${#PROMPT_RESPONSES[@]} > 0 )); then
    rc="${PROMPT_RESPONSES[0]}"
    PROMPT_RESPONSES=("${PROMPT_RESPONSES[@]:1}")
  fi
  return "$rc"
}

USB_BT_MATCH_CONF="$tmp_dir/vfio-usb-bluetooth-match.conf"
write_match_conf_defaults() {
  cat >"$USB_BT_MATCH_CONF" <<'EOF'
MATCH_MODE="auto"
INCLUDE_IDS=""
EXCLUDE_IDS=""
USB_ETHERNET_EEE_OFF="0"
USB_ETHERNET_EEE_IDS=""
EOF
}


VFIO_USB_SYSFS_GLOB="$usb_fake_root/*"

# Case 1: color enabled picker output.
write_match_conf_defaults
prompt_yn_calls=0
input_file_case1="$tmp_dir/eee-input-case1.txt"
stdout_file_case1="$tmp_dir/eee-stdout-case1.txt"
stderr_file_case1="$tmp_dir/eee-stderr-case1.txt"
prompt_out_file_case1="$tmp_dir/eee-prompt-case1.txt"
printf '%s\n' "1" >"$input_file_case1"
VFIO_INTERACTIVE_IN="$input_file_case1"
VFIO_INTERACTIVE_OUT="$prompt_out_file_case1"
ENABLE_COLOR=1
PROMPT_RESPONSES=(0)
configure_usb_bt_ethernet_eee_interactive >"$stdout_file_case1" 2>"$stderr_file_case1"
stdout_text_case1="$(cat "$stdout_file_case1")"
match_conf_text_case1="$(cat "$USB_BT_MATCH_CONF")"
expected_idx="${C_BOLD}${C_GREEN}[1]${C_RESET}"
assert_eq "case1 asks enable prompt once" "1" "$prompt_yn_calls"
assert_contains_text "case1 prints colorized ethernet index" "$expected_idx" "$stdout_text_case1"
assert_contains_text "case1 persists USB_ETHERNET_EEE_OFF enabled" "USB_ETHERNET_EEE_OFF=\"1\"" "$match_conf_text_case1"
assert_contains_text "case1 persists selected USB_ETHERNET_EEE_IDS" "USB_ETHERNET_EEE_IDS=\"0bda:8153\"" "$match_conf_text_case1"

# Case 2: color disabled picker output fallback.
write_match_conf_defaults
prompt_yn_calls=0
input_file_case2="$tmp_dir/eee-input-case2.txt"
stdout_file_case2="$tmp_dir/eee-stdout-case2.txt"
stderr_file_case2="$tmp_dir/eee-stderr-case2.txt"
prompt_out_file_case2="$tmp_dir/eee-prompt-case2.txt"
printf '%s\n' "1" >"$input_file_case2"
VFIO_INTERACTIVE_IN="$input_file_case2"
VFIO_INTERACTIVE_OUT="$prompt_out_file_case2"
ENABLE_COLOR=0
PROMPT_RESPONSES=(0)
configure_usb_bt_ethernet_eee_interactive >"$stdout_file_case2" 2>"$stderr_file_case2"
stdout_text_case2="$(cat "$stdout_file_case2")"
match_conf_text_case2="$(cat "$USB_BT_MATCH_CONF")"
assert_eq "case2 asks enable prompt once" "1" "$prompt_yn_calls"
assert_contains_text "case2 prints plain ethernet index" "[1] 4-3.4 0bda:8153 Realtek USB 10/100/1000 LAN" "$stdout_text_case2"
assert_not_contains_text "case2 does not print colorized ethernet index" "$expected_idx" "$stdout_text_case2"
assert_contains_text "case2 persists USB_ETHERNET_EEE_OFF enabled" "USB_ETHERNET_EEE_OFF=\"1\"" "$match_conf_text_case2"
assert_contains_text "case2 persists selected USB_ETHERNET_EEE_IDS" "USB_ETHERNET_EEE_IDS=\"0bda:8153\"" "$match_conf_text_case2"

if (( fail != 0 )); then
  printf '\nFAIL SUMMARY (%d)\n' "${#FAILED_ASSERTIONS[@]}" >&2
  for failed_assertion in "${FAILED_ASSERTIONS[@]}"; do
    printf ' - %s\n' "$failed_assertion" >&2
  done
  exit 1
fi
printf 'USB Ethernet EEE regression checks passed.\n'
