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

assert_contains_file() {
  local name="$1" pattern="$2" file="$3"
  if grep -Fq -- "$pattern" "$file"; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (pattern not found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  fi
}
assert_not_contains_file() {
  local name="$1" pattern="$2" file="$3"
  if grep -Fq -- "$pattern" "$file"; then
    printf 'FAIL: %s (unexpected pattern found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  else
    printf 'PASS: %s\n' "$name"
  fi
}
assert_cmdline_has_token() {
  local name="$1" token="$2" cmdline="$3"
  local found=0 tok
  for tok in $cmdline; do
    if [[ "$tok" == "$token" ]]; then
      found=1
      break
    fi
  done
  if (( found )); then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (missing token: %s)\n' "$name" "$token" >&2
    record_failure "$name"
  fi
}
assert_cmdline_lacks_token() {
  local name="$1" token="$2" cmdline="$3"
  local tok
  for tok in $cmdline; do
    if [[ "$tok" == "$token" ]]; then
      printf 'FAIL: %s (unexpected token present: %s)\n' "$name" "$token" >&2
      record_failure "$name"
      return
    fi
  done
  printf 'PASS: %s\n' "$name"
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
# Test 5: Boot-VGA helper behavior stays additive-first and falls back when risk is detected.
first_boot_vga_probe_bdf() {
  local f
  for f in /sys/bus/pci/devices/*/boot_vga; do
    [[ -f "$f" ]] || continue
    basename "$(dirname "$f")"
    return 0
  done
  return 1
}

simulated_boot_vga_bdf="$(first_boot_vga_probe_bdf || true)"
if [[ -z "$simulated_boot_vga_bdf" ]]; then
  printf 'FAIL: no PCI boot_vga probe path found under /sys/bus/pci/devices/*/boot_vga\n' >&2
  record_failure "boot_vga probe path exists under /sys/bus/pci/devices/*/boot_vga"
else
  simulated_boot_vga_path="/sys/bus/pci/devices/$simulated_boot_vga_bdf/boot_vga"
  shim_dir="$tmp_dir/shim-bin"
  mkdir -p "$shim_dir"
  cat_bin="$(command -v cat)"
  cat >"$shim_dir/cat" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "$simulated_boot_vga_path" ]]; then
  printf '1\n'
  exit 0
fi
exec "$cat_bin" "\$@"
EOF
  chmod +x "$shim_dir/cat"

  old_path="$PATH"
  PATH="$shim_dir:$PATH"

  CTX["guest_vfio_ids"]="10de:1b80,10de:10f0"
  CTX["guest_gpu"]="$simulated_boot_vga_bdf"
  CTX["kernel_vfio_risk"]=0
  CTX["kernel_vfio_log_error"]=0
  CTX["guest_vfio_ids_fallback"]=0

  append_guest_vfio_ids_with_detect_fallback "quiet iommu=pt" "custom-regression target" >"$tmp_dir/boot-vga-add.stdout" 2>"$tmp_dir/boot-vga-add.stderr"
  add_only_result="$(cat "$tmp_dir/boot-vga-add.stdout")"
  assert_eq \
    "Boot-VGA helper add-first path appends vfio-pci.ids when no risk is detected" \
    "quiet iommu=pt vfio-pci.ids=10de:1b80,10de:10f0" \
    "$add_only_result"
  assert_eq \
    "Boot-VGA helper keeps fallback marker unset when no risk is detected" \
    "0" \
    "${CTX[guest_vfio_ids_fallback]:-0}"

  CTX["kernel_vfio_risk"]=1
  CTX["kernel_vfio_log_error"]=0
  CTX["guest_vfio_ids_fallback"]=0

  append_guest_vfio_ids_with_detect_fallback "quiet iommu=pt" "custom-regression target" >"$tmp_dir/boot-vga-fallback.stdout" 2>"$tmp_dir/boot-vga-fallback.stderr"
  fallback_result="$(cat "$tmp_dir/boot-vga-fallback.stdout")"
  assert_eq \
    "Boot-VGA helper fallback removes vfio-pci.ids when risk is detected" \
    "quiet iommu=pt" \
    "$fallback_result"
  assert_eq \
    "Boot-VGA helper sets fallback marker when risk-triggered removal occurs" \
    "1" \
    "${CTX[guest_vfio_ids_fallback]:-0}"

  PATH="$old_path"
fi
# Test 6: BLS sync keeps snapshot root metadata while applying persisted cmdline baseline.
bls_dir="$tmp_dir/bls-entries"
mkdir -p "$bls_dir"
cmdline_fixture="$tmp_dir/kernel-cmdline"
cat >"$cmdline_fixture" <<'EOF'
quiet iommu=pt rd.driver.pre=vfio-pci selinux=0 apparmor=0
EOF

entry_a="$bls_dir/system-opensuse-a.conf"
entry_b="$bls_dir/system-opensuse-b.conf"
cat >"$entry_a" <<'EOF'
title openSUSE entry A
linux /vmlinuz-a
initrd /initrd-a
options splash=silent oldopt=1 root=UUID=ROOTA rootflags=subvol=@/.snapshots/40/snapshot rootfstype=btrfs resume=/dev/disk/by-uuid/SWAPA ro
EOF
cat >"$entry_b" <<'EOF'
title openSUSE entry B
linux /vmlinuz-b
initrd /initrd-b
options quiet legacy=1 root=UUID=ROOTB rootflags=subvol=@/.snapshots/38/snapshot rw
EOF

is_opensuse_like() { return 0; }
detect_bootloader() { printf 'grub2-bls\n'; }
systemd_boot_entries_dir() { printf '%s\n' "$bls_dir"; }
kernel_cmdline_persistence_file() { printf '%s\n' "$cmdline_fixture"; }

sync_bls_entries_from_kernel_cmdline >"$tmp_dir/bls-sync.stdout" 2>"$tmp_dir/bls-sync.stderr"

opts_a="$(grep -m1 -E '^options[[:space:]]+' "$entry_a" | sed -E 's/^options[[:space:]]+//')"
opts_b="$(grep -m1 -E '^options[[:space:]]+' "$entry_b" | sed -E 's/^options[[:space:]]+//')"

assert_cmdline_has_token \
  "BLS sync preserves entry A root token" \
  "root=UUID=ROOTA" \
  "$opts_a"
assert_cmdline_has_token \
  "BLS sync preserves entry A rootflags token" \
  "rootflags=subvol=@/.snapshots/40/snapshot" \
  "$opts_a"
assert_cmdline_has_token \
  "BLS sync preserves entry A rootfstype token" \
  "rootfstype=btrfs" \
  "$opts_a"
assert_cmdline_has_token \
  "BLS sync preserves entry A resume token" \
  "resume=/dev/disk/by-uuid/SWAPA" \
  "$opts_a"
assert_cmdline_has_token \
  "BLS sync preserves entry A ro token" \
  "ro" \
  "$opts_a"
assert_cmdline_has_token \
  "BLS sync applies baseline iommu=pt token to entry A" \
  "iommu=pt" \
  "$opts_a"
assert_cmdline_has_token \
  "BLS sync applies baseline rd.driver.pre token to entry A" \
  "rd.driver.pre=vfio-pci" \
  "$opts_a"
assert_cmdline_lacks_token \
  "BLS sync removes stale entry A token" \
  "oldopt=1" \
  "$opts_a"
assert_cmdline_lacks_token \
  "BLS sync removes stale entry A splash token" \
  "splash=silent" \
  "$opts_a"

assert_cmdline_has_token \
  "BLS sync preserves entry B root token" \
  "root=UUID=ROOTB" \
  "$opts_b"
assert_cmdline_has_token \
  "BLS sync preserves entry B rootflags token" \
  "rootflags=subvol=@/.snapshots/38/snapshot" \
  "$opts_b"
assert_cmdline_has_token \
  "BLS sync preserves entry B rw token" \
  "rw" \
  "$opts_b"
assert_cmdline_has_token \
  "BLS sync applies baseline selinux=0 token to entry B" \
  "selinux=0" \
  "$opts_b"
assert_cmdline_has_token \
  "BLS sync applies baseline apparmor=0 token to entry B" \
  "apparmor=0" \
  "$opts_b"
assert_cmdline_lacks_token \
  "BLS sync removes stale entry B token" \
  "legacy=1" \
  "$opts_b"
# Test 7: sdbootutil failure still triggers direct BLS option synchronization fallback.
fallback_bls_dir="$tmp_dir/bls-fallback-entries"
mkdir -p "$fallback_bls_dir"
fallback_cmdline_fixture="$tmp_dir/kernel-cmdline-fallback"
cat >"$fallback_cmdline_fixture" <<'EOF'
quiet iommu=pt rd.driver.pre=vfio-pci selinux=0 apparmor=0
EOF

fallback_entry="$fallback_bls_dir/system-opensuse-sync-failure.conf"
cat >"$fallback_entry" <<'EOF'
title openSUSE fallback entry
linux /vmlinuz-fallback
initrd /initrd-fallback
options splash=silent legacy=1 root=UUID=ROOTF rootflags=subvol=@/.snapshots/52/snapshot rw
EOF

sdbootutil_shim_dir="$tmp_dir/sdbootutil-shim-bin"
mkdir -p "$sdbootutil_shim_dir"
sdbootutil_invocation_log="$tmp_dir/sdbootutil-invocations.log"
cat >"$sdbootutil_shim_dir/sdbootutil" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$sdbootutil_invocation_log"
exit 1
EOF
chmod +x "$sdbootutil_shim_dir/sdbootutil"

old_path="$PATH"
PATH="$sdbootutil_shim_dir:$PATH"

is_opensuse_like() { return 0; }
detect_bootloader() { printf 'grub2-bls\n'; }
systemd_boot_entries_dir() { printf '%s\n' "$fallback_bls_dir"; }
kernel_cmdline_persistence_file() { printf '%s\n' "$fallback_cmdline_fixture"; }

opensuse_sdbootutil_update_all_entries >"$tmp_dir/bls-fallback-sync.stdout" 2>"$tmp_dir/bls-fallback-sync.stderr"

PATH="$old_path"

sdbootutil_log_contents="$(cat "$sdbootutil_invocation_log" 2>/dev/null || true)"
assert_contains_text \
  "fallback path attempts sdbootutil add-all-kernels before direct sync" \
  "add-all-kernels" \
  "$sdbootutil_log_contents"

fallback_opts="$(grep -m1 -E '^options[[:space:]]+' "$fallback_entry" | sed -E 's/^options[[:space:]]+//')"
assert_cmdline_has_token \
  "sdbootutil failure fallback preserves root token" \
  "root=UUID=ROOTF" \
  "$fallback_opts"
assert_cmdline_has_token \
  "sdbootutil failure fallback preserves rootflags token" \
  "rootflags=subvol=@/.snapshots/52/snapshot" \
  "$fallback_opts"
assert_cmdline_has_token \
  "sdbootutil failure fallback preserves rw token" \
  "rw" \
  "$fallback_opts"
assert_cmdline_has_token \
  "sdbootutil failure fallback applies baseline rd.driver.pre token" \
  "rd.driver.pre=vfio-pci" \
  "$fallback_opts"
assert_cmdline_lacks_token \
  "sdbootutil failure fallback removes stale legacy token" \
  "legacy=1" \
  "$fallback_opts"
assert_cmdline_lacks_token \
  "sdbootutil failure fallback removes stale splash token" \
  "splash=silent" \
  "$fallback_opts"
# Test 8: partial sdbootutil failure still triggers direct BLS option synchronization fallback.
partial_bls_dir="$tmp_dir/bls-partial-fallback-entries"
mkdir -p "$partial_bls_dir"
partial_cmdline_fixture="$tmp_dir/kernel-cmdline-partial-fallback"
cat >"$partial_cmdline_fixture" <<'EOF'
quiet iommu=pt rd.driver.pre=vfio-pci selinux=0 apparmor=0
EOF

partial_entry="$partial_bls_dir/system-opensuse-sync-partial-failure.conf"
cat >"$partial_entry" <<'EOF'
title openSUSE partial fallback entry
linux /vmlinuz-partial-fallback
initrd /initrd-partial-fallback
options splash=silent partiallegacy=1 root=UUID=ROOTP rootflags=subvol=@/.snapshots/61/snapshot rw
EOF

partial_sdbootutil_shim_dir="$tmp_dir/sdbootutil-partial-shim-bin"
mkdir -p "$partial_sdbootutil_shim_dir"
partial_sdbootutil_invocation_log="$tmp_dir/sdbootutil-partial-invocations.log"
cat >"$partial_sdbootutil_shim_dir/sdbootutil" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$partial_sdbootutil_invocation_log"
if [[ "\${1:-}" == "add-all-kernels" ]]; then
  exit 0
fi
if [[ "\${1:-}" == "update-all-entries" ]]; then
  exit 1
fi
exit 1
EOF
chmod +x "$partial_sdbootutil_shim_dir/sdbootutil"

old_path="$PATH"
PATH="$partial_sdbootutil_shim_dir:$PATH"

is_opensuse_like() { return 0; }
detect_bootloader() { printf 'grub2-bls\n'; }
systemd_boot_entries_dir() { printf '%s\n' "$partial_bls_dir"; }
kernel_cmdline_persistence_file() { printf '%s\n' "$partial_cmdline_fixture"; }

opensuse_sdbootutil_update_all_entries >"$tmp_dir/bls-partial-fallback-sync.stdout" 2>"$tmp_dir/bls-partial-fallback-sync.stderr"

PATH="$old_path"

partial_sdbootutil_log_contents="$(cat "$partial_sdbootutil_invocation_log" 2>/dev/null || true)"
assert_contains_text \
  "partial fallback path invokes sdbootutil add-all-kernels" \
  "add-all-kernels" \
  "$partial_sdbootutil_log_contents"
assert_contains_text \
  "partial fallback path invokes sdbootutil update-all-entries" \
  "update-all-entries" \
  "$partial_sdbootutil_log_contents"

partial_opts="$(grep -m1 -E '^options[[:space:]]+' "$partial_entry" | sed -E 's/^options[[:space:]]+//')"
assert_cmdline_has_token \
  "partial sdbootutil failure fallback preserves root token" \
  "root=UUID=ROOTP" \
  "$partial_opts"
assert_cmdline_has_token \
  "partial sdbootutil failure fallback preserves rootflags token" \
  "rootflags=subvol=@/.snapshots/61/snapshot" \
  "$partial_opts"
assert_cmdline_has_token \
  "partial sdbootutil failure fallback preserves rw token" \
  "rw" \
  "$partial_opts"
assert_cmdline_has_token \
  "partial sdbootutil failure fallback applies baseline rd.driver.pre token" \
  "rd.driver.pre=vfio-pci" \
  "$partial_opts"
assert_cmdline_lacks_token \
  "partial sdbootutil failure fallback removes stale partiallegacy token" \
  "partiallegacy=1" \
  "$partial_opts"
assert_cmdline_lacks_token \
  "partial sdbootutil failure fallback removes stale splash token" \
  "splash=silent" \
  "$partial_opts"

# Test 9: call-site wiring coverage for all boot-option flows.
# Test 5: call-site wiring coverage for all boot-option flows.
assert_contains_file \
  "preview helper function exists" \
  "preview_cmdline_change_interactive()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "kernel cmdline persistence helper exists" \
  "kernel_cmdline_persistence_file()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "BLS key-value token helper exists" \
  "cmdline_get_key_value_token()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "BLS synchronization helper exists" \
  "sync_bls_entries_from_kernel_cmdline()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "BLS synchronization helper reads kernel-cmdline path via helper" \
  "cmdline_file=\"\$(kernel_cmdline_persistence_file 2>/dev/null || true)\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "openSUSE sdbootutil helper calls BLS synchronization helper" \
  "  sync_bls_entries_from_kernel_cmdline" \
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
  "GRUB reset cleanup removes rhgb token" \
  "new=\"\$(remove_param_all \"\$new\" \"rhgb\")\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "openSUSE persistence reset cleanup removes rhgb token" \
  "knew=\"\$(remove_param_all \"\$knew\" \"rhgb\")\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "openSUSE persistence flow calls custom-kernel helper" \
  "add_custom_kernel_params_interactive \"\$new_cmdline\" \"/etc/kernel/cmdline (persistence)\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "openSUSE persistence flow preserves root metadata from existing kernel cmdline" \
  "cmdline_add_boot_metadata_tokens_from_options \"\$new_cmdline\" \"\$cmdline_content\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "openSUSE persistence flow includes current-mount root fallback tokens" \
  "mount_root_tok=\"\$(bls_current_mount_root_token 2>/dev/null || true)\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "BLS synchronization includes current-mount root fallback tokens" \
  "base_cmdline=\"\$(cmdline_set_key_value_token \"\$base_cmdline\" \"\$mount_root_tok\")\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "systemd-boot current-entry flow calls custom-kernel helper" \
  "add_custom_kernel_params_interactive \"\$new_opts\" \"systemd-boot entry\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "GRUB flow calls custom-kernel helper" \
  "add_custom_kernel_params_interactive \"\$new\" \"GRUB cmdline\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "Boot-VGA vfio ids helper function exists" \
  "append_guest_vfio_ids_with_detect_fallback()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "Boot-VGA helper checks VFIO risk markers" \
  "if [[ \"\${CTX[kernel_vfio_risk]:-0}\" == \"1\" || \"\${CTX[kernel_vfio_log_error]:-0}\" == \"1\" ]]; then" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "Boot-VGA helper fallback removes vfio-pci.ids on detected risk" \
  "updated=\"\$(remove_param_all \"\$updated\" \"vfio-pci.ids=\$guest_ids\")\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "openSUSE persistence flow uses Boot-VGA helper for vfio-pci.ids" \
  "append_guest_vfio_ids_with_detect_fallback \"\$new_cmdline\" \"/etc/kernel/cmdline (persistence)\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "systemd-boot flow uses Boot-VGA helper for vfio-pci.ids" \
  "append_guest_vfio_ids_with_detect_fallback \"\$new_opts\" \"systemd-boot entry options\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "GRUB flow uses Boot-VGA helper for vfio-pci.ids" \
  "append_guest_vfio_ids_with_detect_fallback \"\$new\" \"GRUB kernel cmdline\"" \
  "$VFIO_SCRIPT"
assert_not_contains_file \
  "legacy Boot-VGA hard-skip message removed" \
  "Skipping vfio-pci.ids for" \
  "$VFIO_SCRIPT"

if (( fail != 0 )); then
  printf '\nFAIL SUMMARY (%d)\n' "${#FAILED_ASSERTIONS[@]}" >&2
  for failed_assertion in "${FAILED_ASSERTIONS[@]}"; do
    printf ' - %s\n' "$failed_assertion" >&2
  done
  exit 1
fi
printf 'Custom kernel parameter regression checks passed.\n'
