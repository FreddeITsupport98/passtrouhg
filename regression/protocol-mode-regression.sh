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

# --- Test 1: write_conf persists GRAPHICS_PROTOCOL_MODE with normalization.
CONF_FILE="$tmp_dir/vfio-gpu-passthrough.conf"
backup_file() { :; }
write_file_atomic() {
  local dst="$1" mode="$2" owner_group="$3"
  : "$owner_group"
  cat >"$dst"
  chmod "$mode" "$dst" 2>/dev/null || true
}
host_assisted_boot_vga_policy_default() { echo "0"; }

write_conf "0000:00:01.0" "" "" "0000:01:00.0" "" "1002" "x11"
assert_contains_text \
  "write_conf stores X11 protocol mode" \
  'GRAPHICS_PROTOCOL_MODE="X11"' \
  "$(cat "$CONF_FILE")"

write_conf "0000:00:01.0" "" "" "0000:01:00.0" "" "1002" "wayland"
assert_contains_text \
  "write_conf stores WAYLAND protocol mode" \
  'GRAPHICS_PROTOCOL_MODE="WAYLAND"' \
  "$(cat "$CONF_FILE")"

write_conf "0000:00:01.0" "" "" "0000:01:00.0" "" "1002" "invalid-mode"
assert_contains_text \
  "write_conf falls back to AUTO on invalid protocol mode" \
  'GRAPHICS_PROTOCOL_MODE="AUTO"' \
  "$(cat "$CONF_FILE")"

# --- Test 2: package mapping helper returns expected apt mappings.
have_cmd() {
  [[ "${1:-}" == "apt-get" ]]
}

mapfile -t x11_pkgs < <(protocol_runtime_packages_for_mode "X11")
assert_eq \
  "protocol_runtime_packages_for_mode maps X11 packages for apt-get" \
  "xserver-xorg xinit x11-xserver-utils" \
  "${x11_pkgs[*]}"

mapfile -t wayland_pkgs < <(protocol_runtime_packages_for_mode "WAYLAND")
assert_eq \
  "protocol_runtime_packages_for_mode maps Wayland packages for apt-get" \
  "weston wayland-protocols" \
  "${wayland_pkgs[*]}"

# Restore generic command detection for the remaining tests.
have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# --- Test 3: mode-specific apply path behavior.
x11_prompt_calls=0
remove_calls=0
maybe_offer_xorg_explicit_prompt() {
  x11_prompt_calls=$((x11_prompt_calls + 1))
}
remove_xorg_host_gpu_pinning() {
  remove_calls=$((remove_calls + 1))
}
prompt_yn() {
  return 0
}

CTX["graphics_protocol_mode"]="X11"
apply_selected_graphics_protocol_mode "0000:00:01.0" "0000:01:00.0"
assert_eq "X11 mode calls explicit Xorg prompt path once" "1" "$x11_prompt_calls"

XORG_HOST_GPU_CONF="$tmp_dir/20-vfio-host-gpu.conf"
LIGHTDM_HOST_GPU_CONF="$tmp_dir/90-vfio-host-gpu.conf"
: >"$XORG_HOST_GPU_CONF"
: >"$LIGHTDM_HOST_GPU_CONF"
x11_prompt_calls=0
remove_calls=0
CTX["graphics_protocol_mode"]="WAYLAND"
apply_selected_graphics_protocol_mode "0000:00:01.0" "0000:01:00.0"
assert_eq "WAYLAND mode does not call Xorg prompt path" "0" "$x11_prompt_calls"
assert_eq "WAYLAND mode can trigger Xorg pinning cleanup path" "1" "$remove_calls"

# --- Test 4: selection helper auto-selects single WORKS protocol mode.
xorg_stack_status() { echo "WORKS"; }
wayland_stack_status() { echo "NOT_PRESENT"; }
x11_wayland_support_status() { echo "WORKS"; }
x11_wayland_supported_mode() { echo "X11"; }
ensure_graphics_protocol_runtime() { return 0; }
select_and_prepare_graphics_protocol_mode >/dev/null 2>&1 || true
assert_eq "auto mode selection picks X11 when only X11 is WORKS" "X11" "${CTX[graphics_protocol_mode]:-}"

xorg_stack_status() { echo "NOT_PRESENT"; }
wayland_stack_status() { echo "WORKS"; }
x11_wayland_support_status() { echo "WORKS"; }
x11_wayland_supported_mode() { echo "WAYLAND"; }
select_and_prepare_graphics_protocol_mode >/dev/null 2>&1 || true
assert_eq "auto mode selection picks WAYLAND when only Wayland is WORKS" "WAYLAND" "${CTX[graphics_protocol_mode]:-}"
# --- Test 5: detect JSON includes persisted configured graphics protocol key.
vfio_source="$(cat "$VFIO_SCRIPT")"
assert_contains_text \
  "detect JSON output includes configured_graphics_protocol_mode key" \
  'configured_graphics_protocol_mode' \
  "$vfio_source"

# --- Test 6: removed disabled legacy Xorg helper definitions stay absent.
legacy_hits="$(grep -nE '_legacy_(xorg_busid_from_bdf_disabled|install_xorg_host_gpu_pinning_disabled|install_lightdm_host_gpu_isolation_disabled|maybe_offer_xorg_explicit_prompt_disabled)' "$VFIO_SCRIPT" || true)"
assert_eq \
  "disabled legacy Xorg helper definitions are absent from vfio.sh" \
  "" \
  "$legacy_hits"

if (( fail != 0 )); then
  printf '\nFAIL SUMMARY (%d)\n' "${#FAILED_ASSERTIONS[@]}" >&2
  for failed_assertion in "${FAILED_ASSERTIONS[@]}"; do
    printf ' - %s\n' "$failed_assertion" >&2
  done
  exit 1
fi

printf 'Protocol-mode regression checks passed.\n'
