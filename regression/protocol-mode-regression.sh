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

assert_not_contains_text() {
  local name="$1" pattern="$2" haystack="$3"
  if grep -Fq -- "$pattern" <<<"$haystack"; then
    printf 'FAIL: %s (unexpected pattern found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  else
    printf 'PASS: %s\n' "$name"
  fi
}

assert_line_order() {
  local name="$1" file="$2" earlier_pattern="$3" later_pattern="$4"
  local earlier_line later_line
  earlier_line="$(grep -nF -- "$earlier_pattern" "$file" | awk -F: 'NR==1{print $1}')"
  later_line="$(grep -nF -- "$later_pattern" "$file" | awk -F: 'NR==1{print $1}')"

  if [[ -z "$earlier_line" || -z "$later_line" ]]; then
    printf 'FAIL: %s (missing pattern(s): "%s" or "%s")\n' "$name" "$earlier_pattern" "$later_pattern" >&2
    record_failure "$name"
    return
  fi

  if (( later_line > earlier_line )); then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (line order mismatch: %s <= %s)\n' "$name" "$later_line" "$earlier_line" >&2
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

# --- Test 3: mode-specific apply path behavior is deferred-only.
x11_prompt_calls=0
remove_calls=0
install_calls=0
lightdm_calls=0
captured_notes=()

say() { :; }
hdr() { :; }
note() {
  captured_notes+=("$*")
}
maybe_offer_xorg_explicit_prompt() {
  x11_prompt_calls=$((x11_prompt_calls + 1))
}
remove_xorg_host_gpu_pinning() {
  remove_calls=$((remove_calls + 1))
}
install_xorg_host_gpu_pinning() {
  install_calls=$((install_calls + 1))
}
maybe_offer_lightdm_isolatedevice() {
  lightdm_calls=$((lightdm_calls + 1))
}
prompt_yn() {
  return 0
}

CTX["graphics_protocol_mode"]="X11"
apply_selected_graphics_protocol_mode "0000:00:01.0" "0000:01:00.0"
x11_notes="$(printf '%s\n' "${captured_notes[@]}")"
assert_eq "X11 mode does not call Xorg prompt path during install" "0" "$x11_prompt_calls"
assert_eq "X11 mode does not install live Xorg pinning during install" "0" "$install_calls"
assert_eq "X11 mode does not run LightDM isolate-device helper during install" "0" "$lightdm_calls"
assert_eq "X11 mode does not remove live Xorg pinning during install" "0" "$remove_calls"
assert_contains_text "X11 mode reports selected mode" "X11 mode selected." "$x11_notes"
assert_contains_text "X11 mode reports deferred activation to next boot" "Protocol adaptation is deferred to next boot." "$x11_notes"
assert_contains_text "X11 mode reports no live switching in installer" "No live Wayland/X11 switching is performed during this install run." "$x11_notes"

x11_prompt_calls=0
remove_calls=0
install_calls=0
lightdm_calls=0
captured_notes=()
CTX["graphics_protocol_mode"]="WAYLAND"
apply_selected_graphics_protocol_mode "0000:00:01.0" "0000:01:00.0"
wayland_notes="$(printf '%s\n' "${captured_notes[@]}")"
assert_eq "WAYLAND mode does not call Xorg prompt path during install" "0" "$x11_prompt_calls"
assert_eq "WAYLAND mode does not install live Xorg pinning during install" "0" "$install_calls"
assert_eq "WAYLAND mode does not run LightDM isolate-device helper during install" "0" "$lightdm_calls"
assert_eq "WAYLAND mode does not remove live Xorg pinning during install" "0" "$remove_calls"
assert_contains_text "WAYLAND mode reports selected mode" "Wayland mode selected." "$wayland_notes"
assert_contains_text "WAYLAND mode reports deferred activation to next boot" "Protocol adaptation is deferred to next boot." "$wayland_notes"
assert_contains_text "WAYLAND mode reports no live switching in installer" "No live Wayland/X11 switching is performed during this install run." "$wayland_notes"

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
# --- Test 6: daemon install keeps next-boot activation semantics (enable only, no enable --now).
assert_contains_text \
  "graphics protocol daemon install uses systemctl enable without --now" \
  'run systemctl enable vfio-graphics-protocold.service' \
  "$vfio_source"
assert_not_contains_text \
  "graphics protocol daemon install does not use immediate enable --now" \
  'run systemctl enable --now vfio-graphics-protocold.service' \
  "$vfio_source"
assert_not_contains_text \
  "graphics protocol daemon template does not reference undefined host_gpu_bdf no-op" \
  ": \"\$host_gpu_bdf\" \"\$guest_gpu_bdf\"" \
  "$vfio_source"

# --- Test 7: protocol-mode scheduling message remains at end of install flow.
assert_line_order \
  "apply_configuration runs protocol scheduling after host-audio user-unit prompt block" \
  "$VFIO_SCRIPT" \
  'Install a user systemd unit to set the host default audio sink after login?' \
  "apply_selected_graphics_protocol_mode \"\$host_gpu\" \"\$guest_gpu\""

# --- Test 8: removed disabled legacy Xorg helper definitions stay absent.
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
