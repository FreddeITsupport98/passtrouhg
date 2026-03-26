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
  local IFS=$' \t\n'
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
  local IFS=$' \t\n'
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

# Test 4: detect_bootloader keeps openSUSE GRUB+BLS fallback classification.
detect_block="$(sed -n '/^detect_bootloader()/,/^}/p' "$VFIO_SCRIPT")"
assert_contains_text \
  "detect_bootloader checks /etc/kernel/cmdline in openSUSE GRUB+BLS heuristic" \
  "if is_opensuse_like && [[ -f /etc/kernel/cmdline ]] && [[ -d /boot/grub || -d /boot/grub2 ]]; then" \
  "$detect_block"
assert_contains_text \
  "detect_bootloader openSUSE GRUB+BLS heuristic inspects BLS options lines for root token" \
  "grep -qE '^options[[:space:]]+.*\\<root='" \
  "$detect_block"
assert_contains_text \
  "detect_bootloader openSUSE GRUB+BLS heuristic resolves to grub2-bls" \
  "echo \"grub2-bls\"" \
  "$detect_block"

# Test 5: call-site wiring coverage for all boot-option flows.
preview_rc=0
preview_cmdline_change_interactive "quiet iommu=pt" "quiet iommu=pt amd_iommu=on" "GRUB kernel cmdline" >/dev/null 2>"$tmp_dir/preview.stderr" || preview_rc=$?
assert_eq \
  "preview_cmdline_change_interactive decline path returns non-zero" \
  "1" \
  "$preview_rc"
# Test 6: Boot-VGA helper behavior stays additive-first and falls back when risk is detected.
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
# Test 7: BLS sync keeps snapshot root metadata while applying persisted cmdline baseline.
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
# Test 8: sdbootutil failure still triggers direct BLS option synchronization fallback.
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
# Test 9: partial sdbootutil failure still triggers direct BLS option synchronization fallback.
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

# Test 10: BLS sync falls back to /proc/cmdline root metadata when other sources are unavailable.
proc_bls_dir="$tmp_dir/bls-proc-root-recovery-entries"
mkdir -p "$proc_bls_dir"
proc_cmdline_fixture="$tmp_dir/kernel-cmdline-proc-root-recovery"
cat >"$proc_cmdline_fixture" <<'EOF'
quiet iommu=pt rd.driver.pre=vfio-pci selinux=0 apparmor=0
EOF

proc_entry="$proc_bls_dir/system-opensuse-proc-root-recovery.conf"
cat >"$proc_entry" <<'EOF'
title openSUSE proc-root recovery entry
linux /vmlinuz-proc-root-recovery
initrd /initrd-proc-root-recovery
options splash=silent proclegacy=1 rw
EOF

proc_cmdline_cat_shim_dir="$tmp_dir/proc-cmdline-cat-shim-bin"
mkdir -p "$proc_cmdline_cat_shim_dir"
cat_bin="$(command -v cat)"
cat >"$proc_cmdline_cat_shim_dir/cat" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "/proc/cmdline" ]]; then
  printf '%s\n' 'mitigations=auto quiet root=UUID=PROCR rootflags=subvol=@/.snapshots/99/snapshot ro'
  exit 0
fi
exec "$cat_bin" "\$@"
EOF
chmod +x "$proc_cmdline_cat_shim_dir/cat"

old_path="$PATH"
PATH="$proc_cmdline_cat_shim_dir:$PATH"

is_opensuse_like() { return 0; }
detect_bootloader() { printf 'grub2-bls\n'; }
systemd_boot_entries_dir() { printf '%s\n' "$proc_bls_dir"; }
kernel_cmdline_persistence_file() { printf '%s\n' "$proc_cmdline_fixture"; }
bls_find_boot_metadata_options() { return 1; }
bls_current_mount_root_token() { return 1; }
bls_current_mount_rootflags_token() { return 1; }

proc_sync_rc=0
sync_bls_entries_from_kernel_cmdline >"$tmp_dir/proc-root-sync.stdout" 2>"$tmp_dir/proc-root-sync.stderr" || proc_sync_rc=$?

PATH="$old_path"

assert_eq \
  "proc-cmdline fallback sync exits successfully when other root metadata sources are unavailable" \
  "0" \
  "$proc_sync_rc"

proc_opts="$(grep -m1 -E '^options[[:space:]]+' "$proc_entry" | sed -E 's/^options[[:space:]]+//')"
assert_cmdline_has_token \
  "proc-cmdline fallback applies recovered root token to BLS entry" \
  "root=UUID=PROCR" \
  "$proc_opts"
assert_cmdline_has_token \
  "proc-cmdline fallback applies recovered rootflags token to BLS entry" \
  "rootflags=subvol=@/.snapshots/99/snapshot" \
  "$proc_opts"
assert_cmdline_has_token \
  "proc-cmdline fallback applies baseline iommu token to BLS entry" \
  "iommu=pt" \
  "$proc_opts"
assert_cmdline_has_token \
  "proc-cmdline fallback applies baseline rd.driver.pre token to BLS entry" \
  "rd.driver.pre=vfio-pci" \
  "$proc_opts"
assert_cmdline_lacks_token \
  "proc-cmdline fallback removes stale proclegacy token from BLS entry" \
  "proclegacy=1" \
  "$proc_opts"
assert_cmdline_lacks_token \
  "proc-cmdline fallback removes stale splash token from BLS entry" \
  "splash=silent" \
  "$proc_opts"
# Test 11: BLS sync continues safely using per-entry root metadata when global root sources are unavailable.
entry_root_bls_dir="$tmp_dir/bls-entry-root-fallback-entries"
mkdir -p "$entry_root_bls_dir"
entry_root_cmdline_fixture="$tmp_dir/kernel-cmdline-entry-root-fallback"
cat >"$entry_root_cmdline_fixture" <<'EOF'
quiet iommu=pt rd.driver.pre=vfio-pci selinux=0 apparmor=0
EOF

entry_root_entry="$entry_root_bls_dir/system-opensuse-entry-root-recovery.conf"
cat >"$entry_root_entry" <<'EOF'
title openSUSE entry-root fallback entry
linux /vmlinuz-entry-root-fallback
initrd /initrd-entry-root-fallback
options splash=silent entrylegacy=1 root=UUID=ENTRYROOT rootflags=subvol=@/.snapshots/77/snapshot rw
EOF

entry_root_cat_shim_dir="$tmp_dir/entry-root-cat-shim-bin"
mkdir -p "$entry_root_cat_shim_dir"
cat_bin="$(command -v cat)"
cat >"$entry_root_cat_shim_dir/cat" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "/proc/cmdline" ]]; then
  printf '%s\n' 'mitigations=auto quiet loglevel=3'
  exit 0
fi
exec "$cat_bin" "\$@"
EOF
chmod +x "$entry_root_cat_shim_dir/cat"

old_path="$PATH"
PATH="$entry_root_cat_shim_dir:$PATH"

is_opensuse_like() { return 0; }
detect_bootloader() { printf 'grub2-bls\n'; }
systemd_boot_entries_dir() { printf '%s\n' "$entry_root_bls_dir"; }
kernel_cmdline_persistence_file() { printf '%s\n' "$entry_root_cmdline_fixture"; }
bls_find_boot_metadata_options() { return 1; }
bls_current_mount_root_token() { return 1; }
bls_current_mount_rootflags_token() { return 1; }

entry_root_sync_rc=0
sync_bls_entries_from_kernel_cmdline >"$tmp_dir/entry-root-sync.stdout" 2>"$tmp_dir/entry-root-sync.stderr" || entry_root_sync_rc=$?

PATH="$old_path"

assert_eq \
  "entry-root fallback sync exits successfully when global root metadata sources are unavailable" \
  "0" \
  "$entry_root_sync_rc"

entry_root_opts="$(grep -m1 -E '^options[[:space:]]+' "$entry_root_entry" | sed -E 's/^options[[:space:]]+//')"
assert_cmdline_has_token \
  "entry-root fallback preserves root token from entry options" \
  "root=UUID=ENTRYROOT" \
  "$entry_root_opts"
assert_cmdline_has_token \
  "entry-root fallback preserves rootflags token from entry options" \
  "rootflags=subvol=@/.snapshots/77/snapshot" \
  "$entry_root_opts"
assert_cmdline_has_token \
  "entry-root fallback applies baseline iommu token to entry" \
  "iommu=pt" \
  "$entry_root_opts"
assert_cmdline_has_token \
  "entry-root fallback applies baseline rd.driver.pre token to entry" \
  "rd.driver.pre=vfio-pci" \
  "$entry_root_opts"
assert_cmdline_lacks_token \
  "entry-root fallback removes stale legacy token from entry" \
  "entrylegacy=1" \
  "$entry_root_opts"
assert_cmdline_lacks_token \
  "entry-root fallback removes stale splash token from entry" \
  "splash=silent" \
  "$entry_root_opts"
# Test 12: BLS sync remains root-metadata-aware even when global IFS is non-default.
ifs_bls_dir="$tmp_dir/bls-ifs-root-recovery-entries"
mkdir -p "$ifs_bls_dir"
ifs_cmdline_fixture="$tmp_dir/kernel-cmdline-ifs-root-recovery"
cat >"$ifs_cmdline_fixture" <<'EOF'
quiet iommu=pt rd.driver.pre=vfio-pci root=UUID=IFSROOT rootflags=subvol=@/.snapshots/88/snapshot
EOF

ifs_entry="$ifs_bls_dir/system-opensuse-ifs-root-recovery.conf"
cat >"$ifs_entry" <<'EOF'
title openSUSE ifs-root recovery entry
linux /vmlinuz-ifs-root-recovery
initrd /initrd-ifs-root-recovery
options splash=silent ifslegacy=1 root=UUID=IFSROOT rootflags=subvol=@/.snapshots/88/snapshot rw
EOF

is_opensuse_like() { return 0; }
detect_bootloader() { printf 'grub2-bls\n'; }
systemd_boot_entries_dir() { printf '%s\n' "$ifs_bls_dir"; }
kernel_cmdline_persistence_file() { printf '%s\n' "$ifs_cmdline_fixture"; }
bls_find_boot_metadata_options() { return 1; }
bls_current_mount_root_token() { return 1; }
bls_current_mount_rootflags_token() { return 1; }

old_ifs="$IFS"
IFS=','
ifs_sync_rc=0
sync_bls_entries_from_kernel_cmdline >"$tmp_dir/ifs-root-sync.stdout" 2>"$tmp_dir/ifs-root-sync.stderr" || ifs_sync_rc=$?
IFS="$old_ifs"

assert_eq \
  "IFS-hardened BLS sync exits successfully when shell IFS omits spaces" \
  "0" \
  "$ifs_sync_rc"

ifs_opts="$(grep -m1 -E '^options[[:space:]]+' "$ifs_entry" | sed -E 's/^options[[:space:]]+//')"
assert_cmdline_has_token \
  "IFS-hardened BLS sync preserves entry root token" \
  "root=UUID=IFSROOT" \
  "$ifs_opts"
assert_cmdline_has_token \
  "IFS-hardened BLS sync preserves entry rootflags token" \
  "rootflags=subvol=@/.snapshots/88/snapshot" \
  "$ifs_opts"
assert_cmdline_has_token \
  "IFS-hardened BLS sync applies baseline iommu token" \
  "iommu=pt" \
  "$ifs_opts"
assert_cmdline_has_token \
  "IFS-hardened BLS sync applies baseline rd.driver.pre token" \
  "rd.driver.pre=vfio-pci" \
  "$ifs_opts"
assert_cmdline_lacks_token \
  "IFS-hardened BLS sync removes stale legacy token" \
  "ifslegacy=1" \
  "$ifs_opts"
assert_cmdline_lacks_token \
  "IFS-hardened BLS sync removes stale splash token" \
  "splash=silent" \
  "$ifs_opts"
# Test 13: debug-cmdline-tokens mode traces root/rootflags source selection without writing entry files.
debug_bls_dir="$tmp_dir/bls-debug-token-trace-entries"
mkdir -p "$debug_bls_dir"
debug_cmdline_fixture="$tmp_dir/kernel-cmdline-debug-token-trace"
cat >"$debug_cmdline_fixture" <<'EOF'
quiet iommu=pt rd.driver.pre=vfio-pci root=UUID=DBGBASE rootflags=subvol=@/.snapshots/11/snapshot
EOF

debug_entry_a="$debug_bls_dir/system-opensuse-debug-a.conf"
debug_entry_b="$debug_bls_dir/system-opensuse-debug-b.conf"
cat >"$debug_entry_a" <<'EOF'
title openSUSE debug token trace entry A
linux /vmlinuz-debug-a
initrd /initrd-debug-a
options splash=silent dbglegacy=1 root=UUID=DBGENTRY rootflags=subvol=@/.snapshots/44/snapshot rw
EOF
cat >"$debug_entry_b" <<'EOF'
title openSUSE debug token trace entry B
linux /vmlinuz-debug-b
initrd /initrd-debug-b
options splash=silent dbglegacy=2 rw
EOF

debug_opts_a_before="$(grep -m1 -E '^options[[:space:]]+' "$debug_entry_a" | sed -E 's/^options[[:space:]]+//')"
debug_opts_b_before="$(grep -m1 -E '^options[[:space:]]+' "$debug_entry_b" | sed -E 's/^options[[:space:]]+//')"

debug_mode_rc=0
(
  is_opensuse_like() { return 0; }
  detect_bootloader() { printf 'grub2-bls\n'; }
  systemd_boot_entries_dir() { printf '%s\n' "$debug_bls_dir"; }
  kernel_cmdline_persistence_file() { printf '%s\n' "$debug_cmdline_fixture"; }
  bls_find_boot_metadata_options() { return 1; }
  debug_bls_cmdline_tokens
) >"$tmp_dir/debug-cmdline-tokens.stdout" 2>"$tmp_dir/debug-cmdline-tokens.stderr" || debug_mode_rc=$?

assert_eq \
  "debug-cmdline-tokens mode exits successfully" \
  "0" \
  "$debug_mode_rc"

debug_trace_output="$(cat "$tmp_dir/debug-cmdline-tokens.stdout")"
assert_contains_text \
  "debug-cmdline-tokens mode prints read-only trace banner" \
  "Tracing root/rootflags source selection in read-only dry-run mode." \
  "$debug_trace_output"
assert_contains_text \
  "debug-cmdline-tokens reports baseline root source from kernel cmdline file" \
  "DEBUG[BLS baseline]: root source=kernel_cmdline_file token=root=UUID=DBGBASE" \
  "$debug_trace_output"
assert_contains_text \
  "debug-cmdline-tokens reports baseline rootflags source from kernel cmdline file" \
  "DEBUG[BLS baseline]: rootflags source=kernel_cmdline_file token=rootflags=subvol=@/.snapshots/11/snapshot" \
  "$debug_trace_output"
assert_contains_text \
  "debug-cmdline-tokens reports per-entry root source from entry options when present" \
  "DEBUG[BLS entry system-opensuse-debug-a.conf]: root source=entry_options token=root=UUID=DBGENTRY" \
  "$debug_trace_output"
assert_contains_text \
  "debug-cmdline-tokens reports per-entry root source fallback to baseline when entry root is missing" \
  "DEBUG[BLS entry system-opensuse-debug-b.conf]: root source=baseline_cmdline token=root=UUID=DBGBASE" \
  "$debug_trace_output"
assert_contains_text \
  "debug-cmdline-tokens reports per-entry rootflags fallback to baseline when entry rootflags are missing" \
  "DEBUG[BLS entry system-opensuse-debug-b.conf]: rootflags source=baseline_cmdline token=rootflags=subvol=@/.snapshots/11/snapshot" \
  "$debug_trace_output"

debug_opts_a_after="$(grep -m1 -E '^options[[:space:]]+' "$debug_entry_a" | sed -E 's/^options[[:space:]]+//')"
debug_opts_b_after="$(grep -m1 -E '^options[[:space:]]+' "$debug_entry_b" | sed -E 's/^options[[:space:]]+//')"
assert_eq \
  "debug-cmdline-tokens mode keeps entry A options unchanged (dry-run)" \
  "$debug_opts_a_before" \
  "$debug_opts_a_after"
assert_eq \
  "debug-cmdline-tokens mode keeps entry B options unchanged (dry-run)" \
  "$debug_opts_b_before" \
  "$debug_opts_b_after"
# Test 14: debug-cmdline-tokens JSON output honors --entry filtering and stays machine-readable.
debug_json_mode_rc=0
(
  is_opensuse_like() { return 0; }
  detect_bootloader() { printf 'grub2-bls\n'; }
  systemd_boot_entries_dir() { printf '%s\n' "$debug_bls_dir"; }
  kernel_cmdline_persistence_file() { printf '%s\n' "$debug_cmdline_fixture"; }
  bls_find_boot_metadata_options() { return 1; }
  JSON_OUTPUT=1
  DEBUG_CMDLINE_TOKENS_ENTRY_FILTER="system-opensuse-debug-b.conf"
  : "$JSON_OUTPUT" "$DEBUG_CMDLINE_TOKENS_ENTRY_FILTER"
  debug_bls_cmdline_tokens
) >"$tmp_dir/debug-cmdline-tokens-json.stdout" 2>"$tmp_dir/debug-cmdline-tokens-json.stderr" || debug_json_mode_rc=$?

assert_eq \
  "debug-cmdline-tokens JSON mode exits successfully" \
  "0" \
  "$debug_json_mode_rc"

debug_json_output="$(cat "$tmp_dir/debug-cmdline-tokens-json.stdout")"
assert_contains_text \
  "debug-cmdline-tokens JSON output includes mode field" \
  "\"mode\": \"debug-cmdline-tokens\"" \
  "$debug_json_output"
assert_contains_text \
  "debug-cmdline-tokens JSON output includes entry filter field" \
  "\"entry_filter\": \"system-opensuse-debug-b.conf\"" \
  "$debug_json_output"
assert_contains_text \
  "debug-cmdline-tokens JSON output includes filtered entry debug line" \
  "DEBUG[BLS entry system-opensuse-debug-b.conf]: root source=baseline_cmdline token=root=UUID=DBGBASE" \
  "$debug_json_output"
assert_not_contains_text \
  "debug-cmdline-tokens JSON output excludes non-matching entry debug lines under --entry filter" \
  "DEBUG[BLS entry system-opensuse-debug-a.conf]:" \
  "$debug_json_output"
# Test 15: parse_args rejects empty --entry values in debug token mode.
entry_empty_equals_rc=0
entry_empty_equals_err="$(
  (
    parse_args --debug-cmdline-tokens --entry=
  ) 2>&1 >/dev/null
)" || entry_empty_equals_rc=$?
assert_eq \
  "parse_args rejects empty --entry= value for debug token mode" \
  "1" \
  "$entry_empty_equals_rc"
assert_contains_text \
  "parse_args empty --entry= emits non-empty pattern error" \
  "expected non-empty basename glob pattern, example: system-*.conf" \
  "$entry_empty_equals_err"

entry_empty_split_rc=0
entry_empty_split_err="$(
  (
    parse_args --debug-cmdline-tokens --entry ""
  ) 2>&1 >/dev/null
)" || entry_empty_split_rc=$?
assert_eq \
  "parse_args rejects empty --entry value when provided as next argument" \
  "1" \
  "$entry_empty_split_rc"
assert_contains_text \
  "parse_args empty split --entry emits non-empty pattern error" \
  "expected non-empty basename glob pattern, example: system-*.conf" \
  "$entry_empty_split_err"
# Test 16: parse_args rejects whitespace-only --entry values in debug token mode.
entry_whitespace_split_rc=0
entry_whitespace_split_err="$(
  (
    parse_args --debug-cmdline-tokens --entry "   "
  ) 2>&1 >/dev/null
)" || entry_whitespace_split_rc=$?
assert_eq \
  "parse_args rejects whitespace-only --entry value when provided as next argument" \
  "1" \
  "$entry_whitespace_split_rc"
assert_contains_text \
  "parse_args whitespace-only --entry emits non-empty pattern error" \
  "expected non-empty basename glob pattern, example: system-*.conf" \
  "$entry_whitespace_split_err"

# Test 17: call-site wiring coverage for all boot-option flows.
# Test 16: call-site wiring coverage for all boot-option flows.
# Test 15: call-site wiring coverage for all boot-option flows.
# Test 11: call-site wiring coverage for all boot-option flows.
# Test 11: call-site wiring coverage for all boot-option flows.
assert_contains_file \
  "preview helper function exists" \
  "preview_cmdline_change_interactive()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "--entry empty-value validation error message is present" \
  "expected non-empty basename glob pattern, example: system-*.conf" \
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
  "debug-cmdline-tokens mode function exists" \
  "debug_bls_cmdline_tokens()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "debug entry filter normalization helper exists" \
  "normalize_debug_cmdline_entry_filter_arg()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "debug-cmdline-tokens argument parsing sets dedicated mode" \
  "--debug-cmdline-tokens)" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "--entry argument parsing branch exists" \
  "--entry)" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "--entry argument parsing stores entry filter value" \
  "DEBUG_CMDLINE_TOKENS_ENTRY_FILTER=\"\$(normalize_debug_cmdline_entry_filter_arg \"\$1\")\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "--entry is validated as debug-mode-only option" \
  "die \"--entry is supported only with --debug-cmdline-tokens\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "--json validation allows debug-cmdline-tokens mode" \
  "die \"--json is currently supported only with --detect or --debug-cmdline-tokens\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "debug token JSON formatter helper exists" \
  "debug_cmdline_tokens_print_json_lines()" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "debug-cmdline-tokens mode dispatch exists in main flow" \
  "if [[ \"\$MODE\" == \"debug-cmdline-tokens\" ]]; then" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "debug-cmdline-tokens mode dispatch executes debug token tracer" \
  "    debug_bls_cmdline_tokens" \
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
  "openSUSE persistence flow includes /proc/cmdline root fallback tokens" \
  "new_cmdline=\"\$(cmdline_add_boot_metadata_tokens_from_options \"\$new_cmdline\" \"\$running_boot_opts\")\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "BLS synchronization includes current-mount root fallback tokens" \
  "base_cmdline=\"\$(cmdline_set_key_value_token \"\$base_cmdline\" \"\$mount_root_tok\")\"" \
  "$VFIO_SCRIPT"
assert_contains_file \
  "BLS synchronization includes /proc/cmdline root fallback tokens" \
  "base_cmdline=\"\$(cmdline_add_boot_metadata_tokens_from_options \"\$base_cmdline\" \"\$running_boot_opts\")\"" \
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
