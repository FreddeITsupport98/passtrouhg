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

assert_contains_file() {
  local name="$1" pattern="$2" file="$3"
  if grep -Fq -- "$pattern" "$file"; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (pattern not found: %s)\n' "$name" "$pattern" >&2
    fail=1
  fi
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# Test 1: token dedup behavior stays additive via add_param_once.
base_cmdline="quiet iommu=pt"
with_added="$(add_param_once "$base_cmdline" "amd_iommu=on")"
with_dedup="$(add_param_once "$with_added" "amd_iommu=on")"
assert_eq \
  "add_param_once keeps additive token order and deduplicates repeats" \
  "quiet iommu=pt amd_iommu=on" \
  "$with_dedup"

# Test 2: helper no-change path (declined prompt) returns pure cmdline on stdout.
# shellcheck disable=SC2329
prompt_yn() { return 1; }
declined_result="$(add_custom_kernel_params_interactive "quiet iommu=pt" "GRUB cmdline" 2>"$tmp_dir/decline.stderr")"
assert_eq \
  "add_custom_kernel_params_interactive decline path keeps cmdline unchanged" \
  "quiet iommu=pt" \
  "$declined_result"

# Test 3: helper implementation keeps UI text redirected away from stdout.
helper_block="$(sed -n '/^add_custom_kernel_params_interactive()/,/^}/p' "$VFIO_SCRIPT")"
assert_contains_text \
  "helper header is redirected to output stream" \
  "hdr \"Custom kernel parameters (optional)\" >\"\$out\"" \
  "$helper_block"
assert_contains_text \
  "helper guidance note is redirected to output stream" \
  "note \"Leave blank to keep defaults.\" >\"\$out\"" \
  "$helper_block"
assert_contains_text \
  "helper empty-input branch returns unchanged cmdline" \
  "if [[ -z \"\$extra\" ]]; then" \
  "$helper_block"
assert_contains_text \
  "helper emits final cmdline on stdout" \
  "printf '%s\\n' \"\$updated\"" \
  "$helper_block"

unredirected_ui_lines="$(printf '%s\n' "$helper_block" | awk '
  /^[[:space:]]*(hdr|note)[[:space:]]/ {
    if ($0 !~ />"\$out"[[:space:]]*$/) {
      print
    }
  }
')"
assert_eq \
  "helper has no unredirected hdr/note UI lines inside command-substitution path" \
  "" \
  "$unredirected_ui_lines"

# Test 4: call-site wiring coverage for all boot-option flows.
preview_rc=0
preview_cmdline_change_interactive "quiet iommu=pt" "quiet iommu=pt amd_iommu=on" "GRUB kernel cmdline" >/dev/null 2>"$tmp_dir/preview.stderr" || preview_rc=$?
assert_eq \
  "preview_cmdline_change_interactive decline path returns non-zero" \
  "1" \
  "$preview_rc"

# Test 5: call-site wiring coverage for all boot-option flows.
assert_contains_file \
  "preview helper function exists" \
  "preview_cmdline_change_interactive()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "openSUSE persistence flow calls preview helper" \
  "preview_cmdline_change_interactive \"\$cmdline_content\" \"\$new_cmdline\" \"/etc/kernel/cmdline (persistence)\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "systemd-boot current-entry flow calls preview helper" \
  "preview_cmdline_change_interactive \"\$current_opts\" \"\$new_opts\" \"systemd-boot entry options\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "GRUB flow calls preview helper" \
  "preview_cmdline_change_interactive \"\$current\" \"\$new\" \"GRUB kernel cmdline\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "openSUSE persistence flow calls custom-kernel helper" \
  "add_custom_kernel_params_interactive \"\$new_cmdline\" \"/etc/kernel/cmdline (persistence)\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "systemd-boot current-entry flow calls custom-kernel helper" \
  "add_custom_kernel_params_interactive \"\$new_opts\" \"systemd-boot entry\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "GRUB flow calls custom-kernel helper" \
  "add_custom_kernel_params_interactive \"\$new\" \"GRUB cmdline\"" \
  "$VFIO_SCRIPT"

if (( fail != 0 )); then
  exit 1
fi
printf 'Custom kernel parameter regression checks passed.\n'
