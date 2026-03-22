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

assert_contains() {
  local name="$1" pattern="$2" haystack="$3"
  if grep -Fq -- "$pattern" <<<"$haystack"; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (pattern not found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  fi
}

assert_not_contains() {
  local name="$1" pattern="$2" haystack="$3"
  if grep -Fq -- "$pattern" <<<"$haystack"; then
    printf 'FAIL: %s (unexpected pattern found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  else
    printf 'PASS: %s\n' "$name"
  fi
}

first_two_pci_bdfs() {
  local -a bdfs=()
  local d
  for d in /sys/bus/pci/devices/*; do
    [[ -e "$d" ]] || continue
    bdfs+=("$(basename "$d")")
    if (( ${#bdfs[@]} >= 2 )); then
      break
    fi
  done
  if (( ${#bdfs[@]} < 2 )); then
    return 1
  fi
  printf '%s\n' "${bdfs[0]}"
  printf '%s\n' "${bdfs[1]}"
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mapfile -t test_bdfs < <(first_two_pci_bdfs || true)
if (( ${#test_bdfs[@]} < 2 )); then
  printf 'FAIL: could not discover two PCI devices under /sys/bus/pci/devices\n' >&2
  exit 1
fi

host_bdf="${test_bdfs[0]}"
guest_bdf="${test_bdfs[1]}"

CONF_FILE="${tmp_dir}/vfio-gpu-passthrough.conf"
# shellcheck disable=SC2034
SYSTEMD_UNIT="${tmp_dir}/vfio-bind-selected-gpu.service"
# shellcheck disable=SC2034
MODULES_LOAD="${tmp_dir}/vfio-modules.conf"
# shellcheck disable=SC2034
BLACKLIST_FILE="${tmp_dir}/vfio-blacklist.conf"
# shellcheck disable=SC2034
BIND_SCRIPT="${tmp_dir}/vfio-bind-selected-gpu.sh"
# shellcheck disable=SC2034
DRY_RUN=0

# Keep health output deterministic and focused on Boot-VGA policy checks.
is_service_enabled() { return 1; }
write_file_atomic() {
  local dst="$1" mode="$2" owner_group="$3"
  : "$owner_group"
  cat >"$dst"
  chmod "$mode" "$dst" 2>/dev/null || true
}

# Test 1: write_conf auto-default writes VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1 when helper says host-assisted path is safe.
host_assisted_boot_vga_policy_default() { echo "1"; }
write_conf "$host_bdf" "" "" "$guest_bdf" "" "1002"
assert_contains \
  "write_conf host-assisted default writes value 1" \
  'VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU="1"' \
  "$(cat "$CONF_FILE")"

# Test 2: write_conf writes 0 when host-assisted default says disabled.
host_assisted_boot_vga_policy_default() { echo "0"; }
write_conf "$host_bdf" "" "" "$guest_bdf" "" "1002"
assert_contains \
  "write_conf host-assisted default writes value 0" \
  'VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU="0"' \
  "$(cat "$CONF_FILE")"
assert_contains \
  "write_conf writes Boot-VGA policy mode AUTO by default" \
  'VFIO_BOOT_VGA_POLICY="AUTO"' \
  "$(cat "$CONF_FILE")"

# Test 2b: write_conf accepts explicit Boot-VGA policy override (STRICT).
write_conf "$host_bdf" "" "" "$guest_bdf" "" "1002" "AUTO" "STRICT"
assert_contains \
  "write_conf persists explicit Boot-VGA policy STRICT" \
  'VFIO_BOOT_VGA_POLICY="STRICT"' \
  "$(cat "$CONF_FILE")"

# Test 2c: parser helper accepts case-insensitive policy values.
assert_eq \
  "normalize_boot_vga_policy_arg accepts strict" \
  "STRICT" \
  "$(normalize_boot_vga_policy_arg strict)"
assert_eq \
  "normalize_boot_vga_policy_arg accepts AUTO" \
  "AUTO" \
  "$(normalize_boot_vga_policy_arg AUTO)"
if normalize_boot_vga_policy_arg invalid >/dev/null 2>&1; then
  printf 'FAIL: normalize_boot_vga_policy_arg rejects invalid values\\n' >&2
  record_failure "normalize_boot_vga_policy_arg rejects invalid values"
else
  printf 'PASS: normalize_boot_vga_policy_arg rejects invalid values\\n'
fi

# Test 3: vfio_config_health warns when host-assisted conditions are true but config flag is disabled.
cat >"$CONF_FILE" <<EOF
HOST_GPU_BDF="$host_bdf"
GUEST_GPU_BDF="$guest_bdf"
HOST_AUDIO_BDFS_CSV=""
GUEST_AUDIO_BDFS_CSV=""
VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU="0"
EOF
host_assisted_boot_vga_policy_default() { echo "1"; }
health_out="$(vfio_config_health)"
assert_contains "health status is WARN when host-assisted flag is disabled" "STATUS=WARN" "$health_out"
assert_contains \
  "health warns about missing VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1" \
  "Guest GPU is Boot VGA while HOST_GPU_BDF has boot_vga=0; set VFIO_BOOT_VGA_POLICY=AUTO (recommended) or VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1" \
  "$health_out"

# Test 4: vfio_config_health does not emit the Boot-VGA warning when config flag is enabled.
cat >"$CONF_FILE" <<EOF
HOST_GPU_BDF="$host_bdf"
GUEST_GPU_BDF="$guest_bdf"
HOST_AUDIO_BDFS_CSV=""
GUEST_AUDIO_BDFS_CSV=""
VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU="1"
EOF
health_out_enabled="$(vfio_config_health)"
assert_not_contains \
  "health warning disappears when VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1" \
  "Guest GPU is Boot VGA while HOST_GPU_BDF has boot_vga=0; set VFIO_BOOT_VGA_POLICY=AUTO (recommended) or VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1" \
  "$health_out_enabled"
assert_eq "health status is OK when only Boot-VGA warning condition is resolved" "STATUS=OK" "$(grep -m1 '^STATUS=' <<<"$health_out_enabled")"

# Test 5: vfio_config_health does not emit strict warning when AUTO policy is enabled.
cat >"$CONF_FILE" <<EOF
HOST_GPU_BDF="$host_bdf"
GUEST_GPU_BDF="$guest_bdf"
HOST_AUDIO_BDFS_CSV=""
GUEST_AUDIO_BDFS_CSV=""
VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU="0"
VFIO_BOOT_VGA_POLICY="AUTO"
EOF
health_out_auto="$(vfio_config_health)"
assert_not_contains \
  "health warning is suppressed when VFIO_BOOT_VGA_POLICY=AUTO" \
  "Guest GPU is Boot VGA while HOST_GPU_BDF has boot_vga=0; set VFIO_BOOT_VGA_POLICY=AUTO (recommended) or VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1" \
  "$health_out_auto"
assert_eq "health status is OK when AUTO Boot-VGA policy is enabled" "STATUS=OK" "$(grep -m1 '^STATUS=' <<<"$health_out_auto")"

# Test 6: print_effective_config reports SKIP_BIND in STRICT mode when host-assisted topology exists but no opt-in is enabled.
pci_boot_vga_flag() {
  case "${1:-}" in
    "$guest_bdf") echo "1" ;;
    "$host_bdf") echo "0" ;;
    *) echo "unknown" ;;
  esac
}
host_assisted_boot_vga_policy_default() { echo "1"; }
cat >"$CONF_FILE" <<EOF
HOST_GPU_BDF="$host_bdf"
GUEST_GPU_BDF="$guest_bdf"
VFIO_ALLOW_BOOT_VGA="0"
VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU="0"
VFIO_BOOT_VGA_POLICY="STRICT"
EOF
effective_out_strict_skip="$(print_effective_config)"
assert_contains \
  "print_effective_config strict mode without opt-in reports SKIP_BIND" \
  "SKIP_BIND" \
  "$effective_out_strict_skip"
assert_contains \
  "print_effective_config strict mode without opt-in reports host-assisted-not-enabled reason" \
  "host_assisted_available_but_not_enabled" \
  "$effective_out_strict_skip"

# Test 7: print_effective_config reports ALLOW_BIND with AUTO policy when host-assisted topology is safe.
cat >"$CONF_FILE" <<EOF
HOST_GPU_BDF="$host_bdf"
GUEST_GPU_BDF="$guest_bdf"
VFIO_ALLOW_BOOT_VGA="0"
VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU="0"
VFIO_BOOT_VGA_POLICY="AUTO"
EOF
effective_out_auto_allow="$(print_effective_config)"
assert_contains \
  "print_effective_config AUTO policy reports ALLOW_BIND" \
  "ALLOW_BIND" \
  "$effective_out_auto_allow"
assert_contains \
  "print_effective_config AUTO policy reports auto_detect reason" \
  "auto_detect" \
  "$effective_out_auto_allow"

# Test 8: print_effective_config reports ALLOW_BIND in STRICT mode when explicit host-assisted opt-in is enabled.
cat >"$CONF_FILE" <<EOF
HOST_GPU_BDF="$host_bdf"
GUEST_GPU_BDF="$guest_bdf"
VFIO_ALLOW_BOOT_VGA="0"
VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU="1"
VFIO_BOOT_VGA_POLICY="STRICT"
EOF
effective_out_strict_opt_in="$(print_effective_config)"
assert_contains \
  "print_effective_config strict mode with explicit opt-in reports ALLOW_BIND" \
  "ALLOW_BIND" \
  "$effective_out_strict_opt_in"
assert_contains \
  "print_effective_config strict mode with explicit opt-in reports explicit_opt_in reason" \
  "explicit_opt_in" \
  "$effective_out_strict_opt_in"

if (( fail != 0 )); then
  printf '\nFAIL SUMMARY (%d)\n' "${#FAILED_ASSERTIONS[@]}" >&2
  for failed_assertion in "${FAILED_ASSERTIONS[@]}"; do
    printf ' - %s\n' "$failed_assertion" >&2
  done
  exit 1
fi
printf 'Boot-VGA policy regression checks passed.\n'
