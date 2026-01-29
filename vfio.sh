#!/usr/bin/env bash
set -euo pipefail

# vfio-gpu-passthrough-setup.sh
# Interactive multi-vendor (AMD/NVIDIA/Intel) GPU passthrough helper.
#
# Design goals (safety first):
# - Bind ONLY the selected guest GPU (and selected associated PCI functions) to vfio-pci.
# - Prefer PCI addresses (BDF) over vendor:device IDs to avoid repeated-ID traps.
#   Example: BOTH AMD HDMI audio controllers can share the same PCI ID (1002:ab28).
# - Optional driver blacklisting (explicit user choice).
# - Adaptive kernel IOMMU params (intel_iommu=on vs amd_iommu=on).
# - Optional user-systemd unit to force the host default audio sink after login.
#
# “Bulletproof” behaviors:
# - Atomic writes for generated files (no partial writes).
# - GRUB edits: modify ONLY the existing cmdline line (no adding new lines), and avoid dup params.
# - Sanity checks before writing config / enabling services.

SCRIPT_NAME="$(basename "$0")"

# --- Configuration ---
CONF_FILE="/etc/vfio-gpu-passthrough.conf"
BIND_SCRIPT="/usr/local/sbin/vfio-bind-selected-gpu.sh"
AUDIO_SCRIPT="/usr/local/bin/vfio-set-host-audio.sh"
SYSTEMD_UNIT="/etc/systemd/system/vfio-bind-selected-gpu.service"
MODULES_LOAD="/etc/modules-load.d/vfio.conf"
BLACKLIST_FILE="/etc/modprobe.d/vfio-optional-blacklist.conf"
DRACUT_VFIO_CONF="/etc/dracut.conf.d/10-vfio.conf"

DEBUG=0
DRY_RUN=0
MODE="install"   # install | verify
RUN_TS="$(date +%Y%m%d-%H%M%S)"

# Color output (ANSI). Set NO_COLOR=1 to disable.
ENABLE_COLOR=1
if [[ -n "${NO_COLOR:-}" ]]; then
  ENABLE_COLOR=0
fi

CSI=$'\033['
C_RESET="${CSI}0m"
C_BOLD="${CSI}1m"
C_DIM="${CSI}2m"
C_RED="${CSI}31m"
C_GREEN="${CSI}32m"
C_YELLOW="${CSI}33m"
C_BLUE="${CSI}34m"
C_CYAN="${CSI}36m"

# Track backups for rollback script generation
declare -A BACKUP_MAP=()
BACKUP_ENTRIES=()

say() { printf '%s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

run() {
  # Print commands in debug mode; honor DRY_RUN.
  if (( DEBUG )); then
    say "+ $*"
  fi
  if (( DRY_RUN )); then
    return 0
  fi
  "$@"
}

prompt_yn() {
  # prompt_yn "Question" default(Y/N)
  local q="$1"; local def="${2:-Y}"; local ans

  # IMPORTANT: don't rely on stdin/stdout being connected to a TTY (sudo/fish/GUI terminals).
  # Also avoid printing prompts to stdout (some callers may capture stdout).
  local in="/dev/stdin"
  local out="/dev/stderr"
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    in="/dev/tty"
    out="/dev/tty"
  fi

  while true; do
    if [[ "$def" =~ ^[Yy]$ ]]; then
      printf '%s [Y/n] ' "$q" >"$out"
    else
      printf '%s [y/N] ' "$q" >"$out"
    fi
    read -r ans <"$in" || return 1
    ans="${ans:-$def}"
    case "$ans" in
      y|Y) return 0;;
      n|N) return 1;;
      *) printf '%s\n' "Please answer y or n." >"$out";;
    esac
  done
}

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [--debug] [--dry-run] [--verify] [--detect] [--self-test] [--reset]

  --debug      Enable verbose debug logging (and bash xtrace).
  --dry-run    Show actions but do not write files / run system-changing commands.
  --verify     Do not change anything; validate an existing setup (reads $CONF_FILE).
  --detect     Print a detailed report of existing VFIO/passthrough configuration and exit.
  --self-test  Run automated checks for common issues (awk compatibility, PipeWire access) and exit.
  --reset      Reset/remove VFIO passthrough settings installed by this script (systemd/modprobe/grub/initramfs/user units).
EOF
}

parse_args() {
  while (( $# )); do
    case "$1" in
      --debug)
        DEBUG=1
        set -x
        ;;
      --dry-run)
        DRY_RUN=1
        ;;
      --verify)
        MODE="verify"
        ;;
      --detect)
        MODE="detect"
        ;;
      --self-test)
        MODE="self-test"
        ;;
      --reset)
        MODE="reset"
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1 (try --help)"
        ;;
    esac
    shift
  done

  # verify/detect/self-test implies dry-run
  if [[ "$MODE" == "verify" || "$MODE" == "detect" || "$MODE" == "self-test" ]]; then
    DRY_RUN=1
  fi
}

write_file_atomic() {
  # write_file_atomic /path mode owner:group
  local dst="$1" mode="$2" owner_group="$3"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if (( DRY_RUN )); then
    rm -f "$tmp" || true
    return 0
  fi
  install -o "${owner_group%%:*}" -g "${owner_group##*:}" -m "$mode" "$tmp" "$dst"
  rm -f "$tmp" || true
}

assert_pci_bdf_exists() {
  local bdf="$1"
  [[ -n "$bdf" ]] || die "Empty PCI BDF"
  [[ -d "/sys/bus/pci/devices/$bdf" ]] || die "PCI device not present in sysfs: $bdf"
}

assert_not_equal() {
  local a="$1" b="$2" msg="$3"
  [[ "$a" != "$b" ]] || die "$msg"
}

confirm_phrase() {
  # confirm_phrase "Prompt" "PHRASE"
  local prompt="$1" phrase="$2" ans

  # IMPORTANT: do not print prompts to stdout (stdout may be captured).
  local in="/dev/stdin"
  local out="/dev/stderr"
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    in="/dev/tty"
    out="/dev/tty"
  fi

  printf '%s\n' "$prompt" >"$out"
  printf '%s\n' "Type exactly: $phrase" >"$out"
  printf '> ' >"$out"

  read -r ans <"$in"
  [[ "$ans" == "$phrase" ]]
}

pci_slot_of_bdf() {
  # 0000:06:00.1 -> 0000:06:00
  echo "${1%.*}"
}

iommu_group_of_bdf() {
  local bdf="$1"
  local link
  link="/sys/bus/pci/devices/$bdf/iommu_group"
  [[ -e "$link" ]] || return 1
  basename "$(readlink -f "$link")"
}

list_iommu_group_devices() {
  # list_iommu_group_devices <group_num>
  local group="$1"
  local d
  for d in /sys/kernel/iommu_groups/"$group"/devices/*; do
    basename "$d"
  done
}

bdf_driver_name() {
  local bdf="$1"
  local sys="/sys/bus/pci/devices/$bdf/driver"
  [[ -L "$sys" ]] || { echo "<none>"; return 0; }
  basename "$(readlink -f "$sys")"
}

drm_card_for_bdf() {
  # Print matching /dev/dri/cardX for a given BDF.
  local bdf="$1" card
  for card in /sys/class/drm/card*; do
    [[ -e "$card/device" ]] || continue
    if [[ "$(basename "$(readlink -f "$card/device")")" == "$bdf" ]]; then
      echo "/dev/dri/${card##*/}"
      return 0
    fi
  done
  return 1
}

gpu_in_use_preflight() {
  local bdf="$1"
  
  # 1. Check for standard DRM drivers (existing logic)
  local drv
  drv="$(bdf_driver_name "$bdf")"
  [[ "$drv" == "vfio-pci" ]] && return 0
  [[ "$drv" == "<none>" ]] && return 0

  local card
  if card="$(drm_card_for_bdf "$bdf" 2>/dev/null)"; then
    say "WARN: Guest GPU $bdf is currently a DRM device: $card (driver: $drv)"
    if command -v lsof >/dev/null 2>&1; then
      if lsof "$card" >/dev/null 2>&1; then
        say "WARN: $card is currently opened by some process(es)."
      fi
    fi

    # 1.5 Check if the HDMI Audio associated with this GPU is in use
    local slot="${bdf%.*}"
    local audio_bdf="${slot}.1"  # Commonly function 1 is the HDMI audio function
    if [[ -d "/sys/bus/pci/devices/$audio_bdf" ]]; then
      local snd snd_card_path card_id
      for snd in /sys/bus/pci/devices/$audio_bdf/sound/card*; do
        [[ -d "$snd" ]] || continue
        card_id="${snd##*/card}"
        if command -v fuser >/dev/null 2>&1; then
          if fuser -v /dev/snd/pcmC"${card_id}"D* >/dev/null 2>&1; then
            say "${C_YELLOW}WARN: HDMI Audio device ($audio_bdf) for this GPU appears to be in use (ALSA card $card_id).${C_RESET}"
            note "      PulseAudio/PipeWire is likely holding the HDMI audio device open."
            if ! confirm_phrase "Binding this GPU may crash or restart your audio server. Continue?" "I UNDERSTAND"; then
              die "Aborted due to active audio device lock."
            fi
          fi
        fi
      done
    fi

    if ! confirm_phrase "Refusing to continue by default (binding an in-use GPU can crash your desktop)." "I UNDERSTAND"; then
      die "Aborted: guest GPU appears to be in use"
    fi
  fi

  # 2. Check for EFI/Simple Framebuffer attachment on Boot VGA.
  if [[ -f "/sys/bus/pci/devices/$bdf/boot_vga" ]]; then
    local is_boot_vga
    is_boot_vga="$(cat "/sys/bus/pci/devices/$bdf/boot_vga")"
    
    if [[ "$is_boot_vga" == "1" ]]; then
      # Check if a framebuffer driver is active in iomem
      if grep -qiE '(efifb|simple-framebuffer|vesafb)' /proc/iomem 2>/dev/null; then
        say "${C_YELLOW}WARN: This GPU is marked as Boot VGA and a framebuffer is active.${C_RESET}"
        note "      This can lock the GPU memory, causing VFIO binding to fail ("Header type 127" / hangs)."
        
        local fb_param=""
        if grep -qi "simple-framebuffer" /proc/iomem 2>/dev/null; then
          fb_param="video=simplefb:off"
        elif grep -qi "efifb" /proc/iomem 2>/dev/null; then
          fb_param="video=efifb:off"
        else
          fb_param="video=vesafb:off"
        fi

        if prompt_yn "Add '$fb_param' to GRUB kernel parameters to disable this framebuffer?" Y; then
          export GRUB_EXTRA_PARAMS="${GRUB_EXTRA_PARAMS:-} ${fb_param}"
          say "Queued '$fb_param' for GRUB update. It will be applied if you enable IOMMU/GRUB editing."
        else
          if ! prompt_yn "Continue without fixing (higher risk of passthrough failure)?" N; then
            die "Aborted due to active framebuffer lock."
          fi
        fi
      fi
    fi
  fi
}

wpctl_cmd() {
  # Run wpctl as the desktop user if invoked via sudo, so it can connect to the user PipeWire instance.
  if have_cmd wpctl; then
    if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" ]] && have_cmd runuser; then
      local uid
      uid="$(id -u "$SUDO_USER")"
      # XDG_RUNTIME_DIR is required for PipeWire socket access.
      runuser -u "$SUDO_USER" -- env XDG_RUNTIME_DIR="/run/user/$uid" wpctl "$@"
      return $?
    fi
    wpctl "$@"
    return $?
  fi
  return 127
}

pipewire_sinks_for_pci_bdf() {
  # Emits TSV: NODE_NAME \t LABEL for sinks that match the PCI tag of this BDF.
  local bdf="$1"
  have_cmd wpctl || return 1

  local pci_tag
  pci_tag="$(echo "$bdf" | sed -E 's/^0000:/pci-0000_/; s/:/_/g')"

  local sid sname slabel
  while IFS=$'\t' read -r sid sname slabel; do
    if wpctl_cmd inspect "$sid" 2>/dev/null | grep -Fq "$pci_tag"; then
      printf '%s\t%s\n' "$sname" "$slabel"
    fi
  done < <(pipewire_sinks_discover)
}

print_kv() {
  # print_kv "Key" "Value"
  printf '  %-28s %s\n' "${1}:" "${2}"
}

readable_file() {
  [[ -f "$1" && -r "$1" ]]
}

csv_each() {
  # csv_each "a,b,c" -> prints one per line
  local csv="${1:-}"
  local IFS=','
  local -a arr=()
  read -r -a arr <<<"$csv"
  printf '%s\n' "${arr[@]}"
}

is_service_enabled() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl is-enabled "$unit" >/dev/null 2>&1
}

is_service_active() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl is-active "$unit" >/dev/null 2>&1
}

grub_cmdline_value() {
  # Returns the configured grub cmdline (GRUB_CMDLINE_LINUX_DEFAULT or GRUB_CMDLINE_LINUX)
  [[ -f /etc/default/grub ]] || return 1
  local key
  key="$(grub_get_key 2>/dev/null || true)"
  [[ -n "$key" ]] || return 1
  grub_read_cmdline "$key" 2>/dev/null
}

grub_has_vfio_params() {
  local cmd
  cmd="$(grub_cmdline_value 2>/dev/null || true)"
  [[ -n "$cmd" ]] || return 1
  grep -Eq '(^|[[:space:]])(amd_iommu=on|intel_iommu=on|iommu=pt|pcie_acs_override=downstream,multifunction)([[:space:]]|$)' <<<"$cmd"
}

# CPU virtualization / Secure Boot helpers (non-fatal diagnostics)
check_cpu_features() {
  say
  hdr "CPU Virtualization Support"

  local cpu_flags
  cpu_flags="$(grep -m1 -E '^flags' /proc/cpuinfo 2>/dev/null || true)"

  if echo "$cpu_flags" | grep -qwE 'vmx|svm'; then
    say "OK: CPU virtualization extensions (vmx/svm) detected."
  else
    say "WARN: CPU virtualization extensions (vmx/svm) NOT detected."
    say "      Ensure VT-x (Intel) or SVM/AMD-V (AMD) is enabled in BIOS/UEFI."
  fi
}

check_secure_boot() {
  # Only relevant on UEFI systems.
  if [[ ! -d /sys/firmware/efi/efivars ]]; then
    return 0
  fi

  if command -v mokutil >/dev/null 2>&1; then
    if mokutil --sb-state 2>/dev/null | grep -qi "SecureBoot enabled"; then
      say "WARN: Secure Boot is ENABLED."
      note "      Strict Secure Boot policies may block unsigned modules or lock down the kernel."
      note "      If vfio modules fail to load, consider testing with Secure Boot temporarily disabled."
    fi
  fi
}

iommu_enabled_or_die() {
  # Best-effort check that IOMMU groups exist on this boot.
  # This requires both firmware support (VT-d / AMD-Vi) and
  # correct kernel parameters (intel_iommu=on or amd_iommu=on).
  if [[ -d /sys/kernel/iommu_groups ]]; then
    local d
    for d in /sys/kernel/iommu_groups/*; do
      if [[ -d "$d" ]]; then
        # At least one group directory exists → IOMMU active.
        return 0
      fi
    done
  fi

  say
  hdr "IOMMU required for GPU passthrough"
  note "No active IOMMU groups were detected under /sys/kernel/iommu_groups."
  note "This usually means VT-d (Intel) or IOMMU/AMD-Vi (AMD) is disabled in firmware, or kernel parameters are missing."
  note "Enable IOMMU in BIOS/UEFI and ensure kernel parameters like 'intel_iommu=on iommu=pt' or 'amd_iommu=on iommu=pt' are set."
  die "IOMMU must be enabled before running this VFIO GPU passthrough setup."
}

vfio_config_health() {
  # Prints:
  #   STATUS=OK|BAD|WARN
  #   REASON=... (0+)
  #
  # BAD means "very likely broken / dangerous" and should prompt reset.
  local status="OK"

  add_reason() {
    local sev="$1" msg="$2"
    printf 'REASON_SEV=%s\n' "$sev"
    printf 'REASON=%s\n' "$msg"
    if [[ "$sev" == "BAD" ]]; then
      status="BAD"
    elif [[ "$sev" == "WARN" && "$status" != "BAD" ]]; then
      status="WARN"
    fi
  }

  # If nothing is present, it's OK (unless GRUB still has VFIO/IOMMU params).
  local any=0
  readable_file "$CONF_FILE" && any=1
  readable_file "$SYSTEMD_UNIT" && any=1
  readable_file "$MODULES_LOAD" && any=1
  readable_file "$BLACKLIST_FILE" && any=1

  if (( ! any )); then
    if grub_has_vfio_params; then
      add_reason WARN "GRUB cmdline still contains VFIO/IOMMU params (amd_iommu/intel_iommu, iommu=pt, ACS override). Consider reset to remove."
      printf 'STATUS=%s\n' "$status"
      return 0
    fi
    printf 'STATUS=OK\n'
    return 0
  fi

  # systemd service sanity
  if is_service_enabled vfio-bind-selected-gpu.service; then
    if [[ ! -f "$BIND_SCRIPT" ]]; then
      add_reason BAD "vfio-bind-selected-gpu.service is enabled but $BIND_SCRIPT is missing"
    fi
    if [[ ! -f "$CONF_FILE" ]]; then
      add_reason BAD "vfio-bind-selected-gpu.service is enabled but $CONF_FILE is missing"
    fi
  fi

  # Config sanity
  if readable_file "$CONF_FILE"; then
    # shellcheck disable=SC1090
    . "$CONF_FILE"

    if [[ -z "${HOST_GPU_BDF:-}" || -z "${GUEST_GPU_BDF:-}" ]]; then
      add_reason BAD "$CONF_FILE exists but HOST_GPU_BDF or GUEST_GPU_BDF is empty"
    fi

    if [[ -n "${HOST_GPU_BDF:-}" && -n "${GUEST_GPU_BDF:-}" && "$HOST_GPU_BDF" == "$GUEST_GPU_BDF" ]]; then
      add_reason BAD "HOST_GPU_BDF equals GUEST_GPU_BDF ($HOST_GPU_BDF)"
    fi

    if [[ -n "${HOST_GPU_BDF:-}" && ! -d "/sys/bus/pci/devices/$HOST_GPU_BDF" ]]; then
      add_reason BAD "Configured HOST_GPU_BDF not present in sysfs: $HOST_GPU_BDF"
    fi
    if [[ -n "${GUEST_GPU_BDF:-}" && ! -d "/sys/bus/pci/devices/$GUEST_GPU_BDF" ]]; then
      add_reason BAD "Configured GUEST_GPU_BDF not present in sysfs: $GUEST_GPU_BDF"
    fi

    if [[ -n "${HOST_AUDIO_BDFS_CSV:-}" ]]; then
      local d
      while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        if [[ ! -d "/sys/bus/pci/devices/$d" ]]; then
          add_reason BAD "Configured HOST_AUDIO_BDFS_CSV device not present in sysfs: $d"
        fi
      done < <(csv_each "$HOST_AUDIO_BDFS_CSV")
    fi

    if [[ -n "${GUEST_AUDIO_BDFS_CSV:-}" ]]; then
      local d
      while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        if [[ ! -d "/sys/bus/pci/devices/$d" ]]; then
          add_reason BAD "Configured GUEST_AUDIO_BDFS_CSV device not present in sysfs: $d"
        fi
      done < <(csv_each "$GUEST_AUDIO_BDFS_CSV")
    fi

    # Host/guest audio overlap check
    if [[ -n "${HOST_AUDIO_BDFS_CSV:-}" && -n "${GUEST_AUDIO_BDFS_CSV:-}" ]]; then
      local h g
      while IFS= read -r h; do
        [[ -n "$h" ]] || continue
        while IFS= read -r g; do
          [[ -n "$g" ]] || continue
          if [[ "$h" == "$g" ]]; then
            add_reason BAD "Host audio and guest audio overlap (same PCI device selected): $h"
          fi
        done < <(csv_each "$GUEST_AUDIO_BDFS_CSV")
      done < <(csv_each "$HOST_AUDIO_BDFS_CSV")
    fi

    # Runtime binding mismatch hints
    if [[ -n "${GUEST_GPU_BDF:-}" ]]; then
      if [[ "$(bdf_driver_name "$GUEST_GPU_BDF")" != "vfio-pci" ]] && is_service_enabled vfio-bind-selected-gpu.service; then
        add_reason WARN "Service is enabled but guest GPU is not currently bound to vfio-pci (likely needs reboot): $GUEST_GPU_BDF"
      fi
    fi
    if [[ -n "${HOST_AUDIO_BDFS_CSV:-}" ]]; then
      local ha="${HOST_AUDIO_BDFS_CSV%%,*}"
      if [[ "$(bdf_driver_name "$ha")" == "vfio-pci" ]]; then
        add_reason BAD "Host audio is currently bound to vfio-pci (host sound will break): $ha"
      fi
    fi
  else
    # If we see other installed artifacts but no config, treat as bad.
    if readable_file "$SYSTEMD_UNIT" || readable_file "$MODULES_LOAD" || readable_file "$BLACKLIST_FILE"; then
      add_reason BAD "VFIO files exist but $CONF_FILE is missing (partial install)"
    fi
  fi

  printf 'STATUS=%s\n' "$status"
}

self_test() {
  say
  hdr "Self-test"

  local fail=0

  # Basic interpreter / syntax
  if bash -n "$0" >/dev/null 2>&1; then
    print_kv "bash -n" "OK"
  else
    print_kv "bash -n" "FAIL"
    fail=1
  fi

  # awk compatibility: ensure our state-var awk pattern works (ins=1)
  if printf 'Sinks:\n  1. foo\nSources:\n' | awk '/Sinks:/{ins=1;next} /Sources:/{ins=0} ins{print}' >/dev/null 2>&1; then
    print_kv "awk (ins state var)" "OK"
  else
    print_kv "awk (ins state var)" "FAIL"
    fail=1
  fi

  # /dev/tty availability (menus rely on this under sudo)
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    print_kv "/dev/tty" "OK"
  else
    print_kv "/dev/tty" "WARN (menus may be invisible under sudo)"
  fi

  # PipeWire: best-effort
  if have_cmd wpctl; then
    if wpctl_cmd status >/dev/null 2>&1; then
      print_kv "PipeWire/wpctl" "OK"
    else
      print_kv "PipeWire/wpctl" "WARN (wpctl cannot connect in current context)"
    fi
  else
    print_kv "PipeWire/wpctl" "SKIP (wpctl not installed)"
  fi

  # GPU discovery (sysfs-based)
  local count
  count="$(gpu_discover_all_sysfs | wc -l | tr -d ' ')"
  print_kv "GPU discovery" "Found ${count} GPU(s)"

  # CPU virtualization + Secure Boot checks (non-fatal)
  check_cpu_features
  check_secure_boot

  if (( fail )); then
    say "Self-test result: FAIL"
    return 1
  fi
  say "Self-test result: OK"
  return 0
}

detect_existing_vfio_report() {
  say
  say "==== Existing VFIO / Passthrough Detection Report ===="

  # Basic host state
  print_kv "Kernel" "$(uname -r)"
  print_kv "Current cmdline" "$(cat /proc/cmdline 2>/dev/null || true)"
  print_kv "Bootloader" "$(detect_bootloader)"

  # Health check
  say
  say "-- Health check --"
  local hc
  hc="$(vfio_config_health)"
  local status
  status="$(printf '%s\n' "$hc" | awk -F= '/^STATUS=/{print $2; exit}')"
  print_kv "Health" "${status:-UNKNOWN}"
  printf '%s\n' "$hc" | awk -F= '/^REASON=/{print "  - " $2}'

  # Our config
  if readable_file "$CONF_FILE"; then
    print_kv "Config" "$CONF_FILE (present)"
    # shellcheck disable=SC1090
    . "$CONF_FILE"
    print_kv "Configured host GPU" "${HOST_GPU_BDF:-<unset>}"
    print_kv "Configured guest GPU" "${GUEST_GPU_BDF:-<unset>}"
    print_kv "Configured host audio" "${HOST_AUDIO_BDFS_CSV:-<unset>}"
    print_kv "Configured guest audio" "${GUEST_AUDIO_BDFS_CSV:-<unset>}"
  else
    print_kv "Config" "$CONF_FILE (missing)"
  fi

  # systemd unit
  if readable_file "$SYSTEMD_UNIT"; then
    print_kv "Systemd unit" "$SYSTEMD_UNIT (present)"
    if command -v systemctl >/dev/null 2>&1; then
      print_kv "Unit enabled" "$(systemctl is-enabled vfio-bind-selected-gpu.service 2>/dev/null || true)"
      print_kv "Unit active" "$(systemctl is-active vfio-bind-selected-gpu.service 2>/dev/null || true)"
      print_kv "Unit status" "$(systemctl show -p ExecStart vfio-bind-selected-gpu.service 2>/dev/null | sed 's/^ExecStart=//' || true)"
    fi
  else
    print_kv "Systemd unit" "$SYSTEMD_UNIT (missing)"
  fi

  # modules-load
  if readable_file "$MODULES_LOAD"; then
    print_kv "Modules-load" "$MODULES_LOAD (present)"
    print_kv "Modules-load content" "$(tr '\n' ' ' <"$MODULES_LOAD" 2>/dev/null || true)"
  else
    print_kv "Modules-load" "$MODULES_LOAD (missing)"
  fi

  # modprobe configs
  local hits=""
  if [[ -d /etc/modprobe.d ]]; then
    hits="$(grep -RIn --no-messages -E 'vfio-pci|vfio_pci|driver_override|blacklist (amdgpu|nouveau|nvidia|i915|radeon)' /etc/modprobe.d 2>/dev/null | head -n 50 || true)"
  fi
  if [[ -n "$hits" ]]; then
    say
    say "-- /etc/modprobe.d matches (first 50) --"
    printf '%s\n' "$hits"
  else
    say
    say "-- /etc/modprobe.d matches --"
    say "  (none found)"
  fi

  # initramfs hints
  say
  say "-- initramfs tooling detected --"
  print_kv "update-initramfs" "$(command -v update-initramfs >/dev/null 2>&1 && echo yes || echo no)"
  print_kv "mkinitcpio" "$(command -v mkinitcpio >/dev/null 2>&1 && echo yes || echo no)"
  print_kv "dracut" "$(command -v dracut >/dev/null 2>&1 && echo yes || echo no)"
  if readable_file /etc/initramfs-tools/modules; then
    print_kv "/etc/initramfs-tools/modules" "present"
    print_kv "vfio in initramfs-tools/modules" "$(grep -nE '^(vfio|vfio_pci|vfio-iommu-type1|vfio_virqfd)' /etc/initramfs-tools/modules 2>/dev/null | tr '\n' ' ' || true)"
  fi
  if [[ -d /etc/dracut.conf.d ]]; then
    print_kv "/etc/dracut.conf.d" "present"
    print_kv "vfio in dracut conf" "$(grep -RIn --no-messages -E 'vfio|vfio-pci|add_drivers|force_drivers' /etc/dracut.conf.d 2>/dev/null | head -n 20 | tr '\n' ' ' || true)"
  fi

  # vendor-reset module (useful for AMD reset bugs)
  if [[ -d /sys/module/vendor_reset ]]; then
    print_kv "vendor-reset" "Loaded (good for AMD reset bugs)"
  else
    if command -v lspci >/dev/null 2>&1 && lspci -n | grep -q "1002:"; then
      print_kv "vendor-reset" "MISSING (Recommended for AMD GPUs with reset issues)"
    else
      print_kv "vendor-reset" "Not loaded"
    fi
  fi

  # GRUB defaults
  if readable_file /etc/default/grub; then
    say
    say "-- /etc/default/grub cmdline --"
    local key
    key="$(grub_get_key 2>/dev/null || true)"
    if [[ -n "$key" ]]; then
      print_kv "$key" "$(grub_read_cmdline "$key" 2>/dev/null || true)"
    else
      say "  Could not locate GRUB_CMDLINE_LINUX(_DEFAULT)"
    fi
  fi

  # Current device bindings
  say
  say "-- Current GPU/Audio bindings (lspci -nnk) --"
  if command -v lspci >/dev/null 2>&1; then
    lspci -Dnn | awk '/(VGA compatible controller|3D controller|Display controller|Audio device)/ {print $1}' | while read -r bdf; do
      [[ -n "$bdf" ]] || continue
      # Only show AMD/NVIDIA/Intel GPUs + audio
      if lspci -Dnn -s "$bdf" | grep -Eq 'Advanced Micro Devices|AMD/ATI|NVIDIA|Intel|Audio device'; then
        printf '%s\n' "$(lspci -Dnnk -s "$bdf" 2>/dev/null | sed 's/^/  /')"
      fi
    done
  fi

  # Libvirt hook detection (common VFIO stage)
  say
  say "-- libvirt hook detection --"
  if [[ -d /etc/libvirt/hooks ]]; then
    print_kv "/etc/libvirt/hooks" "present"
    print_kv "hook files" "$(ls -1 /etc/libvirt/hooks 2>/dev/null | tr '\n' ' ' || true)"
  else
    print_kv "/etc/libvirt/hooks" "missing"
  fi

  say "==== End report ===="
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      exec sudo -E "$0" "$@"
    fi
    die "Run as root (or install sudo)."
  fi
}

require_systemd() {
  if [[ ! -d /run/systemd/system ]]; then
    say "This helper only supports systems running systemd as PID 1."
    say "Other init systems (for example OpenRC, runit, sysvinit, s6, etc.) are NOT supported."
    die "systemd not detected (/run/systemd/system missing)."
  fi
  need_cmd systemctl
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0

  # Only back up a given file once per run.
  if [[ -n "${BACKUP_MAP[$f]:-}" ]]; then
    return 0
  fi

  local bak
  bak="${f}.bak.${RUN_TS}"

  BACKUP_MAP[$f]="$bak"
  BACKUP_ENTRIES+=("$f::$bak")

  if (( DRY_RUN )); then
    return 0
  fi

  cp -a "$f" "$bak"
}

trim() {
  local s="$1"
  # shellcheck disable=SC2001
  s="$(echo "$s" | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
  printf '%s' "$s"
}

vendor_name() {
  case "${1,,}" in
    1002) echo "AMD";;
    10de) echo "NVIDIA";;
    8086) echo "Intel";;
    *) echo "vendor:$1";;
  esac
}

vendor_label() {
  # Prints vendor name, optionally colorized.
  local vid="${1,,}"
  local name
  name="$(vendor_name "$vid")"

  if (( ! ENABLE_COLOR )); then
    echo "$name"
    return 0
  fi

  case "$vid" in
    1002) echo "${C_BOLD}${C_RED}${name}${C_RESET}";;   # AMD = red
    10de) echo "${C_BOLD}${C_GREEN}${name}${C_RESET}";; # NVIDIA = green
    8086) echo "${C_BOLD}${C_BLUE}${name}${C_RESET}";;  # Intel = blue
    *) echo "${C_BOLD}${name}${C_RESET}";;
  esac
}

hdr() {
  # Header line for steps.
  local title="$1"
  if (( ENABLE_COLOR )); then
    say "${C_BOLD}${C_CYAN}==== ${title} ====${C_RESET}"
  else
    say "==== ${title} ===="
  fi
}

note() {
  local msg="$1"
  if (( ENABLE_COLOR )); then
    say "${C_DIM}${msg}${C_RESET}"
  else
    say "$msg"
  fi
}

short_gpu_desc() {
  # Make lspci GPU description shorter for menus.
  # Keep model info, drop trailing [vvvv:dddd] and (rev ..) when present.
  local d="$1"
  d="$(echo "$d" | sed -E 's/^Advanced Micro Devices, Inc\. \[[^]]+\] //; s/^NVIDIA Corporation //; s/^Intel Corporation //')"
  d="$(echo "$d" | sed -E 's/ \[[0-9a-f]{4}:[0-9a-f]{4}\].*$//; s/ \(rev [^)]+\)$//')"
  printf '%s' "$(trim "$d")"
}

short_audio_desc() {
  local d="$1"
  if grep -Eqi 'HDMI|DP' <<<"$d"; then
    echo "HDMI/DP Audio"
  elif grep -qi 'HD Audio' <<<"$d"; then
    echo "HD Audio"
  else
    echo "Audio"
  fi
}

select_from_list() {
  local prompt="$1"; shift
  local -a options=("$@")
  local idx

  # IMPORTANT: stdout is reserved for the return value (index). Print UI to tty/stderr.
  local in="/dev/stdin"
  local out="/dev/stderr"
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    in="/dev/tty"
    out="/dev/tty"
  fi

  while true; do
    printf '\n%s\n' "$prompt" >"$out"
    for i in "${!options[@]}"; do
      printf '  [%d] ' "$((i+1))" >"$out"
      # %b expands backslash escapes in the argument (useful if an option contains \n).
      printf '%b\n' "${options[$i]}" >"$out"
    done
    printf '\nEnter number: ' >"$out"

    read -r idx <"$in"

    [[ "$idx" =~ ^[0-9]+$ ]] || { printf 'Invalid number\n' >"$out"; continue; }
    (( idx >= 1 && idx <= ${#options[@]} )) || { printf 'Out of range\n' >"$out"; continue; }
    echo "$((idx-1))"
    return 0
  done
}

# ---------------- Discovery ----------------

# Helper to read sysfs values (strips leading 0x if present)
sysfs_read() {
  local bdf="$1" file="$2" val
  if [[ -r "/sys/bus/pci/devices/$bdf/$file" ]]; then
    read -r val <"/sys/bus/pci/devices/$bdf/$file"
    val="${val#0x}"
    echo "$val"
  else
    echo ""
  fi
}

# Sysfs-based GPU discovery (more robust than parsing lspci output)
gpu_discover_all_sysfs() {
  # Emits TSV per GPU:
  # GPU_BDF \t GPU_DESC \t VENDOR_ID \t DEVICE_ID \t AUDIO_BDFS(comma) \t AUDIO_DESCS(pipe)
  local dev_path bdf class vendor device desc slot
  local audio_bdfs audio_descs

  # CACHE: Run lspci once to speed up the loop
  local lspci_cache=""
  if have_cmd lspci; then
    lspci_cache="$(lspci -Dnn 2>/dev/null || true)"
  fi

  for dev_path in /sys/bus/pci/devices/*; do
    [[ -e "$dev_path" ]] || continue
    bdf="$(basename "$dev_path")"

    class="$(sysfs_read "$bdf" class)"
    [[ -n "$class" ]] || continue
    # High byte 0x03 = Display controller (VGA/3D/etc).
    local class_base="${class:0:2}"
    [[ "$class_base" == "03" ]] || continue

    vendor="$(sysfs_read "$bdf" vendor)"
    device="$(sysfs_read "$bdf" device)"

    desc=""
    if [[ -n "$lspci_cache" ]]; then
      # Grep from cache instead of running lspci again.
      desc="$(grep -F "$bdf" <<<"$lspci_cache" | head -n1 | sed 's/^[^]]*] *//')"
      desc="$(trim "$desc")"
    fi

    slot="${bdf%.*}"
    audio_bdfs=""
    audio_descs=""

    # Scan functions 1-7 in the same slot for High Definition Audio (class 0x0403xx).
    local func abdf aclass aclass_prefix adesc
    for func in 1 2 3 4 5 6 7; do
      abdf="${slot}.${func}"
      if [[ -d "/sys/bus/pci/devices/$abdf" ]]; then
        aclass="$(sysfs_read "$abdf" class)"
        [[ -n "$aclass" ]] || continue
        aclass_prefix="${aclass:0:4}"
        if [[ "$aclass_prefix" == "0403" ]]; then
          audio_bdfs+="${audio_bdfs:+,}$abdf"
          if [[ -n "$lspci_cache" ]]; then
            adesc="$(grep -F "$abdf" <<<"$lspci_cache" | head -n1 | sed 's/^[^]]*] *//')"
            adesc="$(trim "$adesc")"
          else
            adesc="Audio"
          fi
          audio_descs+="${audio_descs:+|}$adesc"
        fi
      fi
    done

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$bdf" "${desc:-Unknown}" "$vendor" "$device" "$audio_bdfs" "$audio_descs"
  done
}

audio_devices_discover_all() {
  # Emits TSV per audio device:
  # AUDIO_BDF \t AUDIO_DESC \t VENDOR_ID \t DEVICE_ID
  local line bdf desc ids vendor dev
  while IFS= read -r line; do
    bdf="$(awk '{print $1}' <<<"$line")"
    desc="$(cut -d']' -f2- <<<"$line" | sed 's/^: *//')"
    ids="$(grep -oE '\[[0-9a-f]{4}:[0-9a-f]{4}\]' <<<"$line" | head -n1 | tr -d '[]')"
    vendor="${ids%%:*}"
    dev="${ids##*:}"
    printf '%s\t%s\t%s\t%s\n' "$bdf" "$(trim "$desc")" "$vendor" "$dev"
  done < <(lspci -Dnn | awk '/Audio device/ {print}')
}

pipewire_sinks_discover() {
  # Emits TSV: SINK_ID \t NODE_NAME \t LABEL
  # Uses wpctl status + wpctl inspect.
  have_cmd wpctl || return 1

  # Silence PipeWire connection noise and handle "wpctl can't connect" gracefully.
  # Use a small timeout if available so we don't hang when PipeWire is unhappy.
  local status
  if have_cmd timeout; then
    status="$(timeout 2s wpctl_cmd status 2>/dev/null || true)"
  else
    status="$(wpctl_cmd status 2>/dev/null || true)"
  fi
  [[ -n "$status" ]] || return 1

  local -a ids=()
  mapfile -t ids < <(
    printf '%s\n' "$status" | awk '
      /Sinks:/{ins=1;next}
      /Sources:/{ins=0}
      ins{
        for(i=1;i<=NF;i++){
          if($i ~ /^[0-9]+\.$/){ gsub("\\.","",$i); print $i; break }
        }
      }
    '
  )

  local id
  for id in "${ids[@]}"; do
    local node_name label
    node_name="$(wpctl_cmd inspect "$id" 2>/dev/null | awk -F' = ' '/node\.name/{gsub(/"/,"",$2); print $2; exit}')"
    label="$(wpctl_cmd inspect "$id" 2>/dev/null | awk -F' = ' '
      /node\.description/{gsub(/"/,"",$2); print $2; exit}
      /device\.description/{gsub(/"/,"",$2); print $2; exit}
    ' | head -n1)"

    [[ -n "$node_name" ]] || continue
    label="${label:-$node_name}"
    printf '%s\t%s\t%s\n' "$id" "$node_name" "$label"
  done
}

# ---------------- Writes ----------------

# Discover which VFIO modules actually exist for the running kernel.
# This avoids asking Dracut or modules-load for modules that are not built
# (for example vfio_virqfd on some Fedora kernels).
discover_vfio_modules() {
  local -a want=(vfio vfio_pci vfio_iommu_type1 vfio_virqfd)
  local -a have=()
  local m

  if command -v modinfo >/dev/null 2>&1; then
    for m in "${want[@]}"; do
      if modinfo "$m" >/dev/null 2>&1; then
        have+=("$m")
      fi
    done
  else
    # Fallback: only the core three, which exist on all modern kernels using VFIO.
    have=(vfio vfio_pci vfio_iommu_type1)
  fi

  printf '%s\n' "${have[@]}"
}

write_conf() {
  local host_gpu="$1"
  local host_audio_bdfs_csv="$2"
  local host_audio_node_name="$3"
  local guest_gpu="$4"
  local guest_audio_bdfs_csv="$5"
  local guest_vendor="$6"

  backup_file "$CONF_FILE"

  write_file_atomic "$CONF_FILE" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
#
# IMPORTANT:
# - Use PCI addresses (BDF) to avoid accidentally binding the wrong device when IDs repeat.
#   Example: both AMD HDMI audio controllers can share the same PCI ID (1002:ab28).
#
# Debug tips:
# - Verify bind status:
#     lspci -nnk -s <BDF>
# - Verify IOMMU groups:
#     find /sys/kernel/iommu_groups -type l | grep <BDF>

HOST_GPU_BDF="$host_gpu"
HOST_AUDIO_BDFS_CSV="$host_audio_bdfs_csv"
HOST_AUDIO_NODE_NAME="$host_audio_node_name"

GUEST_GPU_BDF="$guest_gpu"
GUEST_AUDIO_BDFS_CSV="$guest_audio_bdfs_csv"
GUEST_GPU_VENDOR_ID="$guest_vendor"
EOF
}

install_vfio_modules_load() {
  backup_file "$MODULES_LOAD"

  # Build the list of VFIO modules that are actually present for this kernel.
  local -a mods=()
  mapfile -t mods < <(discover_vfio_modules)

  write_file_atomic "$MODULES_LOAD" 0644 "root:root" <<EOF
# Load VFIO modules at boot
$(printf '%s
' "${mods[@]}")
EOF
}

install_dracut_config() {
  # Only applies on dracut-based systems.
  [[ -d /etc/dracut.conf.d ]] || return 0

  local file="$DRACUT_VFIO_CONF"
  backup_file "$file"

  # Reuse the same VFIO module list and turn it into a single space-separated string.
  # Be extremely strict about using spaces (not commas) between module names, because
  # a comma-separated list would make dracut look for a single bogus module named
  # "vfio,vfio_pci,..." and fail with:
  #   dracut-install: Failed to find module 'vfio,vfio_pci,vfio_iommu_type1'
  local -a mods=()
  mapfile -t mods < <(discover_vfio_modules)

  # Join with spaces explicitly and sanitize any accidental commas just in case.
  local IFS=' '
  local joined="${mods[*]}"
  joined="${joined//,/ }"

  write_file_atomic "$file" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
# Ensure VFIO modules are included and loaded early in the initramfs.
force_drivers+=" ${joined} "
EOF

  say "Installed Dracut configuration to ensure early VFIO loading."
}

write_optional_blacklist() {
  local vendor_id="$1"; shift
  local -a mods=("$@")

  backup_file "$BLACKLIST_FILE"

  write_file_atomic "$BLACKLIST_FILE" 0644 "root:root" <<EOF
# Optional driver blacklisting for VFIO (generated by $SCRIPT_NAME on $(date -Is))
# Vendor: $(vendor_name "$vendor_id") ($vendor_id)
#
# Safety:
# - This is OPTIONAL and can break host graphics if you blacklist the wrong module.
# - Prefer BDF-based vfio-pci binding (this script's default) over blacklisting.
#
# To undo: remove this file and rebuild initramfs.

$(for m in "${mods[@]}"; do echo "blacklist $m"; done)
EOF
}

install_softdep_config() {
  local guest_vendor="$1"
  local target_driver=""
  
  case "${guest_vendor,,}" in
    10de) target_driver="nvidia" ;;
    1002) target_driver="amdgpu" ;;
    8086) target_driver="i915" ;;
    *) return 0 ;; # Unknown vendor, skip
  esac

  local file="/etc/modprobe.d/vfio-softdep.conf"
  backup_file "$file"

  write_file_atomic "$file" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
# Ensures vfio-pci loads before the graphics driver to prevent race conditions.

softdep $target_driver pre: vfio-pci
softdep ${target_driver}* pre: vfio-pci
EOF

  say "Installed soft dependency to ensure vfio-pci loads before $target_driver."
}

# ---------------- GRUB / kernel params ----------------

cpu_iommu_param() {
  if command -v lscpu >/dev/null 2>&1; then
    if lscpu | grep -qi 'GenuineIntel'; then
      echo "intel_iommu=on"
      return 0
    fi
    if lscpu | grep -qi 'AuthenticAMD'; then
      echo "amd_iommu=on"
      return 0
    fi
  fi
  # fallback
  if grep -qi 'GenuineIntel' /proc/cpuinfo 2>/dev/null; then
    echo "intel_iommu=on"
  else
    echo "amd_iommu=on"
  fi
}

grub_get_key() {
  if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub; then
    echo 'GRUB_CMDLINE_LINUX_DEFAULT'
    return 0
  fi
  if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
    echo 'GRUB_CMDLINE_LINUX'
    return 0
  fi
  return 1
}

grub_read_cmdline() {
  # Reads existing cmdline string without adding new lines.
  local key="$1"
  local line
  line="$(grep -E "^${key}=" /etc/default/grub)" || true

  # Must be exactly one matching line.
  local count
  count="$(grep -Ec "^${key}=" /etc/default/grub || true)"
  [[ "$count" == "1" ]] || die "Expected exactly 1 ${key}= line in /etc/default/grub, found: $count"

  line="${line#${key}=}"
  line="$(trim "$line")"

  # Strip matching quotes if present.
  if [[ "$line" == \"*\" ]]; then
    echo "${line:1:${#line}-2}"
  elif [[ "$line" == \'.*\' ]]; then
    echo "${line:1:${#line}-2}"
  else
    echo "$line"
  fi
}

grub_write_cmdline_in_place() {
  # Modify ONLY the existing cmdline line. Do not add new lines.
  local key="$1" new_cmdline="$2"

  local ln
  ln="$(grep -nE "^${key}=" /etc/default/grub | cut -d: -f1)"
  [[ -n "$ln" ]] || die "Missing ${key}= line in /etc/default/grub (refusing to add new line)"

  # Ensure it's a single line number.
  if grep -nE "^${key}=" /etc/default/grub | cut -d: -f1 | wc -l | grep -qv '^1$'; then
    die "Multiple ${key}= lines found; refusing to edit ambiguously."
  fi

  if (( DRY_RUN )); then
    return 0
  fi

  # SAFETY 1: Verify backup exists and has content.
  local bak="/etc/default/grub.bak.${RUN_TS}"
  if [[ ! -s "$bak" ]]; then
    die "Backup failed or empty ($bak). Aborting GRUB edit."
  fi

  # Apply edit: replace EXACTLY that line number.
  sed -i "${ln}s|^${key}=.*|${key}=\"${new_cmdline//|/\\|}\"|" /etc/default/grub

  # SAFETY 2: Syntax check.
  if ! bash -n /etc/default/grub 2>/dev/null; then
    cp -a "$bak" /etc/default/grub
    die "Syntax error in /etc/default/grub after edit. Reverted to backup."
  fi

  # SAFETY 3: Logic check – ensure the key still exists after edit.
  if ! grep -q "^${key}=" /etc/default/grub; then
    cp -a "$bak" /etc/default/grub
    die "GRUB edit removed ${key} line unexpectedly. Reverted to backup."
  fi
}

add_param_once() {
  local cmdline="$1" param="$2"
  # token match (space or start/end). cmdline is treated as space-separated.
  if grep -Eq "(^|[[:space:]])${param//./\\.}([[:space:]]|$)" <<<"$cmdline"; then
    echo "$cmdline"
  else
    echo "$(trim "$cmdline $param")"
  fi
}

remove_param_all() {
  # Remove a cmdline token (exact token) if present.
  local cmdline="$1" param="$2"
  # Split on spaces to be safe.
  local out="" tok
  for tok in $cmdline; do
    if [[ "$tok" == "$param" ]]; then
      continue
    fi
    out+="${out:+ }$tok"
  done
  echo "$(trim "$out")"
}

detect_bootloader() {
  # 1) Classic GRUB with /etc/default/grub present (most distros)
  if [[ -f /etc/default/grub ]]; then
    echo "grub"
    return 0
  fi

  # 2) GRUB installed but /etc/default/grub missing or managed differently
  #    (for example some openSUSE setups). Presence of /boot/grub* is a
  #    strong indicator that GRUB is the bootloader, even if we cannot
  #    safely auto-edit its configuration.
  if [[ -d /boot/grub || -d /boot/grub2 ]]; then
    echo "grub"
    return 0
  fi

  # 3) systemd-boot style layout
  if [[ -d /boot/loader/entries || -d /efi/loader/entries || -d /boot/efi/loader/entries ]]; then
    echo "systemd-boot"
    return 0
  fi

  # 4) rEFInd
  if [[ -f /boot/refind_linux.conf || -f /efi/EFI/refind/refind.conf || -f /boot/efi/EFI/refind/refind.conf ]]; then
    echo "refind"
    return 0
  fi

  echo "unknown"
}

print_manual_iommu_instructions() {
  local param bl
  param="$(cpu_iommu_param)"
  bl="$(detect_bootloader)"
  if [[ "$bl" != "grub" ]]; then
    say "Detected boot loader: $bl"
  fi
  say "Automatic kernel parameter editing is ONLY implemented for GRUB on systemd-based systems."
  say "Other boot loaders (for example rEFInd, systemd-boot, custom UEFI stubs, etc.) are NOT supported by this script."
  say "If you use one of those, you must edit your kernel parameters manually. Add these parameters and then reboot:"
  say "  $param iommu=pt"
  say "Advanced (usually NOT recommended): pcie_acs_override=downstream,multifunction"
  say "  - Only consider this if your IOMMU groups are not isolated."
  say "  - It can reduce PCIe isolation and may cause instability on some systems."
}

grub_add_kernel_params() {
  # Merge standard params with any discovered extras (for example video=efifb:off).
  local -a params_to_add=("$(cpu_iommu_param)" "iommu=pt" ${GRUB_EXTRA_PARAMS:-})

  if [[ ! -f /etc/default/grub ]]; then
    print_manual_iommu_instructions
    return 0
  fi

  backup_file /etc/default/grub

  local key
  key="$(grub_get_key)" || die "Could not find GRUB_CMDLINE_LINUX_DEFAULT or GRUB_CMDLINE_LINUX in /etc/default/grub"

  local current new
  current="$(grub_read_cmdline "$key")"
  new="$current"

  local p
  for p in "${params_to_add[@]}"; do
    new="$(add_param_once "$new" "$p")"
  done

  say
  hdr "Advanced (optional): ACS override"
  note "ACS override can sometimes split up IOMMU groups on motherboards that don't expose proper isolation."
  note "This may help GPU passthrough if your guest GPU shares an IOMMU group with other devices."
  note "Downsides: weaker PCIe isolation/security and possible instability."
  note "Recommended: NO unless you know you need it."

  if prompt_yn "Enable ACS override in GRUB (pcie_acs_override=downstream,multifunction)?" N; then
    new="$(add_param_once "$new" "pcie_acs_override=downstream,multifunction")"
  fi

  # Safety: do not silently rewrite if nothing changed.
  if [[ "$(trim "$new")" == "$(trim "$current")" ]]; then
    say "GRUB cmdline unchanged (params already present)."
  else
    grub_write_cmdline_in_place "$key" "$(trim "$new")"
  fi

  if command -v update-grub >/dev/null 2>&1; then
    say "Updating GRUB config via update-grub..."
    run update-grub
  elif command -v grub-mkconfig >/dev/null 2>&1; then
    local out
    if [[ -d /boot/grub ]]; then
      out=/boot/grub/grub.cfg
    elif [[ -d /boot/grub2 ]]; then
      out=/boot/grub2/grub.cfg
    else
      die "Could not determine grub.cfg output path (no /boot/grub or /boot/grub2)"
    fi
    say "Updating GRUB config via grub-mkconfig -o $out ..."
    run grub-mkconfig -o "$out"
  elif command -v grub2-mkconfig >/dev/null 2>&1; then
    local out
    if [[ -d /boot/grub2 ]]; then
      out=/boot/grub2/grub.cfg
    elif [[ -d /boot/grub ]]; then
      out=/boot/grub/grub.cfg
    else
      die "Could not determine grub.cfg output path (no /boot/grub2 or /boot/grub)"
    fi
    say "Updating GRUB config via grub2-mkconfig -o $out ..."
    run grub2-mkconfig -o "$out"
  else
    die "No supported GRUB update command found (tried update-grub, grub-mkconfig, grub2-mkconfig)"
  fi
}

maybe_update_initramfs() {
  if command -v update-initramfs >/dev/null 2>&1 && [[ -d /etc/initramfs-tools ]]; then
    say "Updating initramfs via update-initramfs -u ..."
    run update-initramfs -u
    return 0
  fi

  if command -v mkinitcpio >/dev/null 2>&1; then
    say "Updating initramfs via mkinitcpio -P ..."
    run mkinitcpio -P
    return 0
  fi

  if command -v dracut >/dev/null 2>&1; then
    say "Updating initramfs via dracut (no --force; will refuse to overwrite on error) ..."
    if ! run dracut; then
      note "dracut failed or refused to overwrite an existing initramfs."
      note "Your previous initramfs is still on disk. Review the dracut error above and rerun dracut manually (for example: dracut --force) once you are satisfied."
    fi
    return 0
  fi

  say "NOTE: No initramfs update tool detected (update-initramfs, mkinitcpio, dracut). Skipping."
}

# ---------------- VFIO binding service ----------------

install_bind_script() {
  backup_file "$BIND_SCRIPT"

  write_file_atomic "$BIND_SCRIPT" 0755 "root:root" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/vfio-gpu-passthrough.conf"

say() { printf '%s\n' "$*"; }

die() {
  say "ERROR: $*" >&2
  exit 1
}

[[ -f "$CONF_FILE" ]] || die "Missing $CONF_FILE"
# shellcheck disable=SC1090
. "$CONF_FILE"

: "${GUEST_GPU_BDF:?}"

# Basic sanity: ensure sysfs entries exist.
[[ -d "/sys/bus/pci/devices/$GUEST_GPU_BDF" ]] || die "Guest GPU not present in sysfs: $GUEST_GPU_BDF"

modprobe vfio
modprobe vfio-pci
modprobe vfio_iommu_type1

csv_to_array() {
  local csv="${1:-}"; shift || true
  local -a out=()
  local IFS=','
  read -r -a out <<<"$csv"
  printf '%s\n' "${out[@]}"
}

bind_one() {
  local dev="$1"
  [[ -n "$dev" ]] || return 0

  local sys="/sys/bus/pci/devices/$dev"
  [[ -d "$sys" ]] || die "PCI device not present in sysfs: $dev"

  # Unbind from current driver if any.
  if [[ -L "$sys/driver" ]]; then
    local drv
    drv="$(basename "$(readlink "$sys/driver")")"
    if [[ -w "/sys/bus/pci/drivers/$drv/unbind" ]]; then
      echo "$dev" >"/sys/bus/pci/drivers/$drv/unbind" || true
    fi
  fi

  echo vfio-pci >"$sys/driver_override"
  echo "$dev" >"/sys/bus/pci/drivers/vfio-pci/bind" || true
}

clear_override() {
  local dev="$1"
  [[ -n "$dev" ]] || return 0
  local sys="/sys/bus/pci/devices/$dev"
  [[ -d "$sys" ]] || return 0
  echo "" >"$sys/driver_override" || true
}

# Safety: never bind host audio list.
for dev in $(csv_to_array "${HOST_AUDIO_BDFS_CSV:-}"); do
  [[ "$dev" != "$GUEST_GPU_BDF" ]] || die "Refusing: guest GPU is also listed as host audio ($dev)"
  [[ "$dev" != "${GUEST_AUDIO_BDFS_CSV:-}" ]] || true
done

# Bind guest GPU first.
bind_one "$GUEST_GPU_BDF"

# Bind selected guest audio functions.
while IFS= read -r dev; do
  [[ -n "$dev" ]] || continue
  # Do not bind if user accidentally selected same BDF for host audio.
  if grep -Eq "(^|,)${dev}($|,)" <<<"${HOST_AUDIO_BDFS_CSV:-}"; then
    die "Refusing to bind $dev: it is configured as host audio"
  fi
  bind_one "$dev"
done < <(csv_to_array "${GUEST_AUDIO_BDFS_CSV:-}")

# Ensure host audio functions are NOT overridden.
while IFS= read -r dev; do
  clear_override "$dev"
done < <(csv_to_array "${HOST_AUDIO_BDFS_CSV:-}")

# Post-check: verify guest GPU is bound to vfio-pci.
if [[ -L "/sys/bus/pci/devices/$GUEST_GPU_BDF/driver" ]]; then
  drv="$(basename "$(readlink "/sys/bus/pci/devices/$GUEST_GPU_BDF/driver")")"
  [[ "$drv" == "vfio-pci" ]] || die "Guest GPU driver is '$drv' (expected vfio-pci)."
fi

say "vfio-pci binding complete: $GUEST_GPU_BDF ${GUEST_AUDIO_BDFS_CSV:-}"
EOF
}

install_systemd_unit() {
  backup_file "$SYSTEMD_UNIT"

  write_file_atomic "$SYSTEMD_UNIT" 0644 "root:root" <<EOF
[Unit]
Description=Bind selected GPU (and selected PCI functions) to vfio-pci for passthrough
DefaultDependencies=yes
After=systemd-modules-load.service
Before=display-manager.service
Before=libvirtd.service
Before=virtqemud.service
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=$BIND_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  run systemctl daemon-reload
  run systemctl enable vfio-bind-selected-gpu.service
}

# ---------------- Host audio default (PipeWire/PulseAudio) ----------------

install_audio_script() {
  backup_file "$AUDIO_SCRIPT"

  write_file_atomic "$AUDIO_SCRIPT" 0755 "root:root" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/vfio-gpu-passthrough.conf"

[[ -f "$CONF_FILE" ]] || exit 0
# shellcheck disable=SC1090
. "$CONF_FILE"

# Prefer stable PipeWire node.name if configured.
if command -v wpctl >/dev/null 2>&1 && [[ -n "${HOST_AUDIO_NODE_NAME:-}" ]]; then
  mapfile -t sink_ids < <(
    wpctl status | awk '
      /Sinks:/{ins=1;next}
      /Sources:/{ins=0}
      ins{
        for(i=1;i<=NF;i++){
          if($i ~ /^[0-9]+\.$/){ gsub("\\.","",$i); print $i; break }
        }
      }
    '
  )

  for id in "${sink_ids[@]}"; do
    node_name="$(wpctl inspect "$id" 2>/dev/null | awk -F' = ' '/node\.name/{gsub(/"/,"",$2); print $2; exit}')"
    if [[ "$node_name" == "$HOST_AUDIO_NODE_NAME" ]]; then
      wpctl set-default "$id" || true
      exit 0
    fi
  done
  exit 0
fi

# Fallback: if configured with PCI BDFs, try to match on pci tag.
if command -v wpctl >/dev/null 2>&1 && [[ -n "${HOST_AUDIO_BDFS_CSV:-}" ]]; then
  host_bdf="${HOST_AUDIO_BDFS_CSV%%,*}"
  if [[ -n "$host_bdf" ]]; then
    pci_tag="$(echo "$host_bdf" | sed -E 's/^0000:/pci-0000_/; s/:/_/g')"

    mapfile -t sink_ids < <(
      wpctl status | awk '
        /Sinks:/{ins=1;next}
        /Sources:/{ins=0}
        ins{
          for(i=1;i<=NF;i++){
            if($i ~ /^[0-9]+\.$/){ gsub("\\.","",$i); print $i; break }
          }
        }
      '
    )

    for id in "${sink_ids[@]}"; do
      if wpctl inspect "$id" 2>/dev/null | grep -Fq "$pci_tag"; then
        wpctl set-default "$id" || true
        exit 0
      fi
    done
  fi
  exit 0
fi

# PulseAudio fallback: set default sink by matching the node name.
if command -v pactl >/dev/null 2>&1 && [[ -n "${HOST_AUDIO_NODE_NAME:-}" ]]; then
  pactl set-default-sink "$HOST_AUDIO_NODE_NAME" || true
  exit 0
fi
EOF
}

install_user_audio_unit() {
  local user="${SUDO_USER:-}"
  if [[ -z "$user" ]]; then
    printf 'Which username should get the user systemd audio unit? (blank to skip) '
    read -r user
  fi
  [[ -n "$user" ]] || { say "Skipping user audio unit."; return 0; }

  local home
  home="$(getent passwd "$user" | cut -d: -f6)"
  [[ -n "$home" && -d "$home" ]] || { say "Skipping user audio unit (no home for $user)"; return 0; }

  local unit_dir="$home/.config/systemd/user"
  local unit_path="$unit_dir/vfio-set-host-audio.service"

  mkdir -p "$unit_dir"

  cat >"$unit_path" <<EOF
[Unit]
Description=Set default audio sink (helps keep host audio stable with VFIO)
After=pipewire.service wireplumber.service

[Service]
Type=oneshot
ExecStart=$AUDIO_SCRIPT

[Install]
WantedBy=default.target
EOF

  chown -R "$user:$user" "$home/.config/systemd"
  # Enabling a user unit requires a running user systemd + DBus. If not available, don't spam errors.
  local uid
  uid="$(id -u "$user")"

  if command -v runuser >/dev/null 2>&1; then
    # Try best-effort with XDG_RUNTIME_DIR. If it still fails, we silently skip.
    runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user daemon-reload >/dev/null 2>&1 || true
    runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user enable vfio-set-host-audio.service >/dev/null 2>&1 || true
  fi

  note "User audio unit installed at: $unit_path"
  note "If it isn't enabled automatically, run after login: systemctl --user enable --now vfio-set-host-audio.service"
}

# ---------------- Main ----------------

verify_setup() {
  hdr "VERIFY VFIO SETUP"
  detect_existing_vfio_report

  [[ -f "$CONF_FILE" ]] || die "Missing $CONF_FILE (nothing to verify)."
  # shellcheck disable=SC1090
  . "$CONF_FILE"

  local ok=1

  say
  say "Configured devices from $CONF_FILE:"
  say "  Guest GPU:   ${GUEST_GPU_BDF:-<missing>}"
  say "  Guest audio: ${GUEST_AUDIO_BDFS_CSV:-<none>}"
  say "  Host audio:  ${HOST_AUDIO_BDFS_CSV:-<none>}"

  # Basic sanity
  if [[ -z "${GUEST_GPU_BDF:-}" ]]; then
    say "FAIL: GUEST_GPU_BDF is missing in $CONF_FILE"
    ok=0
  else
    if [[ "$(bdf_driver_name "$GUEST_GPU_BDF")" != "vfio-pci" ]]; then
      say "FAIL: Guest GPU $GUEST_GPU_BDF is not bound to vfio-pci (driver: $(bdf_driver_name "$GUEST_GPU_BDF"))"
      note "This is expected BEFORE reboot (or if the vfio bind service isn't enabled)."
      ok=0
    else
      say "OK: Guest GPU $GUEST_GPU_BDF bound to vfio-pci"
    fi
  fi

  if [[ -n "${GUEST_AUDIO_BDFS_CSV:-}" ]]; then
    local IFS=','
    for dev in $GUEST_AUDIO_BDFS_CSV; do
      [[ -n "$dev" ]] || continue
      if [[ "$(bdf_driver_name "$dev")" != "vfio-pci" ]]; then
        say "FAIL: Guest audio $dev is not bound to vfio-pci (driver: $(bdf_driver_name "$dev"))"
        ok=0
      else
        say "OK: Guest audio $dev bound to vfio-pci"
      fi
    done
  fi

  if [[ -n "${HOST_AUDIO_BDFS_CSV:-}" ]]; then
    local host_audio="${HOST_AUDIO_BDFS_CSV%%,*}"
    if [[ "$(bdf_driver_name "$host_audio")" == "vfio-pci" ]]; then
      say "FAIL: Host audio $host_audio is bound to vfio-pci (should remain on host driver)"
      ok=0
    else
      say "OK: Host audio $host_audio driver: $(bdf_driver_name "$host_audio")"
    fi
  fi

  # Check that our files/services exist (best-effort)
  say
  if [[ -f "$BIND_SCRIPT" ]]; then
    say "OK: Bind script present: $BIND_SCRIPT"
  else
    say "WARN: Bind script missing: $BIND_SCRIPT"
  fi

  if [[ -f "$SYSTEMD_UNIT" ]]; then
    say "OK: Systemd unit present: $SYSTEMD_UNIT"
    if command -v systemctl >/dev/null 2>&1; then
      local enabled active
      enabled="$(systemctl is-enabled vfio-bind-selected-gpu.service 2>/dev/null || true)"
      active="$(systemctl is-active vfio-bind-selected-gpu.service 2>/dev/null || true)"
      say "INFO: vfio-bind-selected-gpu.service is-enabled: ${enabled:-<unknown>}"
      say "INFO: vfio-bind-selected-gpu.service is-active:  ${active:-<unknown>}"
    fi
  else
    say "WARN: Systemd unit missing: $SYSTEMD_UNIT"
  fi

  # IOMMU sanity (best-effort)
  say
  if [[ -d /sys/kernel/iommu_groups ]]; then
    if [[ -n "${GUEST_GPU_BDF:-}" ]]; then
      local g
      g="$(iommu_group_of_bdf "$GUEST_GPU_BDF" 2>/dev/null || true)"
      if [[ -n "$g" ]]; then
        say "OK: IOMMU group exists for guest GPU ($GUEST_GPU_BDF): group $g"
      else
        say "WARN: No IOMMU group found for guest GPU ($GUEST_GPU_BDF). IOMMU may be disabled."
      fi
    fi
  else
    say "WARN: /sys/kernel/iommu_groups not present. IOMMU may be disabled in BIOS/kernel."
  fi

  # Kernel cmdline + GRUB sanity (if available)
  say
  if [[ -r /proc/cmdline ]]; then
    local cmd
    cmd="$(cat /proc/cmdline 2>/dev/null || true)"
    if grep -qw "iommu=pt" <<<"$cmd"; then
      say "OK: Running kernel cmdline contains iommu=pt"
    else
      say "WARN: Running kernel cmdline does NOT contain iommu=pt"
    fi
  fi

  if [[ -f /etc/default/grub ]]; then
    local key current
    key="$(grub_get_key 2>/dev/null || true)"
    if [[ -n "$key" ]]; then
      current="$(grub_read_cmdline "$key" 2>/dev/null || true)"
      if grep -qw "iommu=pt" <<<"$current"; then
        say "OK: /etc/default/grub contains iommu=pt"
      else
        say "WARN: /etc/default/grub missing iommu=pt (did you skip GRUB edit?)"
      fi
    fi
  fi

  say
  if (( ok )); then
    say "RESULT: PASS (guest devices are on vfio-pci; host audio is not)"
    return 0
  fi
  say "RESULT: FAIL (see messages above)"
  return 1
}

generate_rollback_script() {
  local path="/root/vfio-rollback-${RUN_TS}.sh"

  if (( DRY_RUN )); then
    say "DRY RUN: would write rollback script to: $path"
    return 0
  fi

  # Build restore/remove commands:
  # - If backup for a path exists, restore it.
  # - Otherwise, remove the file (only for files we expect this installer to create/manage).
  # IMPORTANT: never delete /etc/default/grub; only restore if we backed it up.
  local rr=""
  rr+="if [ -f '/etc/default/grub.bak.${RUN_TS}' ]; then cp -a '/etc/default/grub.bak.${RUN_TS}' '/etc/default/grub'; fi\n"

  local managed_paths=(
    "$MODULES_LOAD"
    "$BLACKLIST_FILE"
    "$BIND_SCRIPT"
    "$AUDIO_SCRIPT"
    "$SYSTEMD_UNIT"
    "$CONF_FILE"
    "$DRACUT_VFIO_CONF"
  )

  local p bak
  for p in "${managed_paths[@]}"; do
    bak="${p}.bak.${RUN_TS}"
    rr+="if [ -f '$bak' ]; then cp -a '$bak' '$p'; else rm -f '$p'; fi\n"
  done

  write_file_atomic "$path" 0700 "root:root" <<EOF
#!/usr/bin/env bash
set -euo pipefail

echo "Rolling back VFIO setup from ${RUN_TS}..."

# Disable/stop VFIO bind service (best-effort)
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now vfio-bind-selected-gpu.service 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
fi

# Restore or remove managed files
${rr}

# Rebuild boot config (best-effort)
if command -v update-grub >/dev/null 2>&1; then
  update-grub || true
elif command -v grub-mkconfig >/dev/null 2>&1; then
  if [ -d /boot/grub ]; then
    grub-mkconfig -o /boot/grub/grub.cfg || true
  elif [ -d /boot/grub2 ]; then
    grub-mkconfig -o /boot/grub2/grub.cfg || true
  fi
elif command -v grub2-mkconfig >/dev/null 2>&1; then
  if [ -d /boot/grub2 ]; then
    grub2-mkconfig -o /boot/grub2/grub.cfg || true
  elif [ -d /boot/grub ]; then
    grub2-mkconfig -o /boot/grub/grub.cfg || true
  fi
fi

# Rebuild initramfs (best-effort)
if command -v update-initramfs >/dev/null 2>&1 && [ -d /etc/initramfs-tools ]; then
  update-initramfs -u || true
elif command -v mkinitcpio >/dev/null 2>&1; then
  mkinitcpio -P || true
elif command -v dracut >/dev/null 2>&1; then
  dracut || true
fi

echo "Rollback finished. Reboot recommended."
EOF

  say "Rollback script written: $path"
}

iommu_group_preflight() {
  # Hard-gate unsafe IOMMU groups.
  local guest_gpu="$1" guest_audio_csv="$2"

  local group
  group="$(iommu_group_of_bdf "$guest_gpu" 2>/dev/null || true)"
  if [[ -z "$group" ]]; then
    die "No IOMMU group found for $guest_gpu. Is IOMMU enabled in BIOS and kernel params?"
  fi

  say
  say "IOMMU group for guest GPU ($guest_gpu) is: $group"
  say "Devices in group $group:"

  local -a allowed=("$guest_gpu")
  if [[ -n "$guest_audio_csv" ]]; then
    local IFS=','
    for dev in $guest_audio_csv; do
      [[ -n "$dev" ]] || continue
      allowed+=("$dev")
    done
  fi

  local unsafe=0 d
  for d in $(list_iommu_group_devices "$group"); do
    say "  - $d"
    local ok=0 a
    for a in "${allowed[@]}"; do
      if [[ "$d" == "$a" ]]; then ok=1; break; fi
    done
    if (( ! ok )); then
      unsafe=1
    fi
  done

  if (( unsafe )); then
    if ! confirm_phrase "This IOMMU group contains extra devices. Passthrough may be unsafe unless you passthrough *all* of them or have ACS separation." "I UNDERSTAND"; then
      die "Aborted due to unsafe IOMMU group"
    fi
  fi
}

audio_slot_sanity() {
  local host_gpu="$1" host_audio="$2"
  [[ -n "$host_audio" ]] || return 0

  local gpu_slot audio_slot
  gpu_slot="$(pci_slot_of_bdf "$host_gpu")"
  audio_slot="$(pci_slot_of_bdf "$host_audio")"

  if [[ "$gpu_slot" != "$audio_slot" ]]; then
    say "WARN: Selected host audio ($host_audio) is not in the same PCI slot as host GPU ($host_gpu)."
    if ! confirm_phrase "This is often a misconfiguration. Continue anyway?" "I UNDERSTAND"; then
      die "Aborted: host audio does not match host GPU slot"
    fi
  fi
}

remove_user_audio_unit() {
  local user="$1"
  [[ -n "$user" ]] || return 0

  # getent exits non-zero if user does not exist; do not abort reset.
  local home
  home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6 || true)"
  [[ -n "$home" && -d "$home" ]] || return 0

  local unit_path="$home/.config/systemd/user/vfio-set-host-audio.service"
  if [[ -f "$unit_path" ]]; then
    run rm -f "$unit_path"
  fi
}

reset_vfio_all() {
  hdr "RESET / CLEANUP"
  note "This will remove VFIO passthrough settings installed by this script."
  note "It will NOT uninstall libvirt/QEMU, and it will NOT change your VM XMLs."

  if ! confirm_phrase "To continue, confirm reset." "RESET VFIO"; then
    die "Reset cancelled"
  fi

  # Disable system service (best-effort)
  if command -v systemctl >/dev/null 2>&1; then
    run systemctl disable --now vfio-bind-selected-gpu.service 2>/dev/null || true
    run systemctl daemon-reload 2>/dev/null || true
  fi

  # Remove managed files
  run rm -f "$SYSTEMD_UNIT" "$BIND_SCRIPT" "$AUDIO_SCRIPT" "$CONF_FILE" "$MODULES_LOAD" "$BLACKLIST_FILE" "$DRACUT_VFIO_CONF" 2>/dev/null || true

  # Remove user unit for SUDO_USER (and optionally all /home users)
  if [[ -n "${SUDO_USER:-}" ]]; then
    remove_user_audio_unit "$SUDO_USER"
  fi

  if prompt_yn "Also remove vfio-set-host-audio.service for ALL users under /home/* ?" N; then
    local d u
    for d in /home/*; do
      [[ -d "$d" ]] || continue
      u="$(basename "$d")"
      # Some /home entries may not correspond to real user accounts; that's OK.
      remove_user_audio_unit "$u"
    done
  fi

  local grub_changed=0

  # Remove GRUB kernel parameters added by this script
  if [[ -f /etc/default/grub ]]; then
    if prompt_yn "Also remove IOMMU/VFIO kernel params from /etc/default/grub (amd_iommu/intel_iommu, iommu=pt, pcie_acs_override)?" Y; then
      backup_file /etc/default/grub

      local key current new
      key="$(grub_get_key)" || die "Could not find GRUB_CMDLINE_LINUX(_DEFAULT) in /etc/default/grub"
      current="$(grub_read_cmdline "$key")"
      new="$current"

      new="$(remove_param_all "$new" "amd_iommu=on")"
      new="$(remove_param_all "$new" "intel_iommu=on")"
      new="$(remove_param_all "$new" "iommu=pt")"
      new="$(remove_param_all "$new" "pcie_acs_override=downstream,multifunction")"

      if [[ "$(trim "$new")" != "$(trim "$current")" ]]; then
        grub_write_cmdline_in_place "$key" "$new"
        grub_changed=1
      else
        note "No matching VFIO/IOMMU params found in GRUB cmdline; leaving it unchanged."
      fi
    fi
  fi

  # Always regenerate GRUB config if we changed /etc/default/grub.
  if (( grub_changed )); then
    if command -v update-grub >/dev/null 2>&1; then
      say "Updating GRUB config via update-grub..."
      run update-grub
    elif command -v grub-mkconfig >/dev/null 2>&1; then
      local out
      if [[ -d /boot/grub ]]; then
        out=/boot/grub/grub.cfg
      elif [[ -d /boot/grub2 ]]; then
        out=/boot/grub2/grub.cfg
      else
        out=""
      fi
      [[ -n "$out" ]] && run grub-mkconfig -o "$out" || true
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
      local out
      if [[ -d /boot/grub2 ]]; then
        out=/boot/grub2/grub.cfg
      elif [[ -d /boot/grub ]]; then
        out=/boot/grub/grub.cfg
      else
        out=""
      fi
      [[ -n "$out" ]] && run grub2-mkconfig -o "$out" || true
    fi
  fi

  # Always rebuild initramfs at end of reset (so removed blacklists/modules are fully gone on next boot).
  say
  say "Rebuilding initramfs (recommended after reset)..."
  maybe_update_initramfs

  say
  say "Reset complete. Reboot recommended."
  note "If any devices are currently bound to vfio-pci, a reboot is the cleanest way to restore host drivers."
}

preflight_existing_config_gate() {
  # If we detect existing VFIO configuration, leftover kernel params, or active vfio bindings, offer reset.
  local detected=0

  if readable_file "$CONF_FILE" || readable_file "$SYSTEMD_UNIT" || readable_file "$MODULES_LOAD" || readable_file "$BLACKLIST_FILE"; then
    detected=1
  fi

  # Leftover kernel parameters are also "existing config".
  if grub_has_vfio_params; then
    detected=1
  fi

  if command -v lspci >/dev/null 2>&1; then
    if lspci -Dnnk | grep -q "Kernel driver in use: vfio-pci"; then
      detected=1
    fi
  fi

  if (( detected )); then
    detect_existing_vfio_report

    local hc status
    hc="$(vfio_config_health)"
    status="$(printf '%s\n' "$hc" | awk -F= '/^STATUS=/{print $2; exit}')"

    # UX goal: offer RESET first, but default should be "No" so user can keep going.
    say
    if [[ "$status" == "BAD" ]]; then
      hdr "WARNING"
      note "A BAD VFIO configuration was detected. Reset is recommended."
      if prompt_yn "Reset / cleanup VFIO settings now?" N; then
        reset_vfio_all
        exit 0
      fi

      # If user refuses reset, require explicit acknowledgement.
      if ! confirm_phrase "Continuing with a BAD config can break boot, graphics, or audio." "I UNDERSTAND"; then
        die "Aborted"
      fi
    else
      # OK/WARN: offer reset, default no, then proceed.
      if prompt_yn "Existing VFIO config detected. Do you want to RESET it before continuing?" N; then
        reset_vfio_all
        exit 0
      fi
      # Default is to continue to next step with no extra prompts.
      note "Continuing with existing config. (You can run: sudo bash vfio.sh --reset)"
    fi
  fi
}

main() {
  parse_args "$@"

  need_cmd lspci
  need_cmd modprobe
  need_cmd sed
  need_cmd awk
  need_cmd grep
  need_cmd install
  need_cmd mktemp
  # Optional but improves UX for PipeWire enumeration under sudo
  have_cmd runuser || true

  if [[ "$MODE" == "verify" ]]; then
    verify_setup
    exit $?
  fi

  if [[ "$MODE" == "detect" ]]; then
    detect_existing_vfio_report
    exit 0
  fi

  if [[ "$MODE" == "self-test" ]]; then
    self_test
    exit $?
  fi

  if [[ "$MODE" == "reset" ]]; then
    require_root
    require_systemd
    reset_vfio_all
    exit 0
  fi

  require_root
  require_systemd

  # For install mode, require IOMMU to be active before continuing.
  iommu_enabled_or_die

  # Clearly describe supported environment up front.
  local bl
  bl="$(detect_bootloader)"
  say
  hdr "Environment support"
  note "Init system: systemd (required; other init systems are NOT supported by this helper)."
  note "Boot loader detected: ${bl}"
  if [[ "$bl" == "grub" ]]; then
    note "Automatic kernel parameter editing is available for GRUB."
  else
    note "Automatic kernel parameter editing is ONLY implemented for GRUB. For ${bl}, you must apply kernel parameters manually when prompted."
  fi

  # Early detection of existing passthrough config (before user makes changes).
  preflight_existing_config_gate

  say
  hdr "VFIO GPU Passthrough Setup (multi-vendor)"
  note "This wizard will ask you to choose: (1) Guest GPU to passthrough, (2) Host audio device to KEEP on the host."
  note "Anything you choose for the GUEST will be bound to vfio-pci (passthrough). Anything you choose for the HOST stays on host drivers."
  if (( DRY_RUN )); then
    say "- DRY RUN: no files/commands will be applied"
  fi
  if (( DEBUG )); then
    say "- DEBUG enabled"
  fi
  say

  # Discover GPUs (via sysfs; lspci is only used for human-readable descriptions)
  local -a gpu_bdfs=() gpu_descs=() gpu_vendor_ids=() gpu_audio_bdfs_csv=() gpu_audio_descs=()
  local gpu_bdf gpu_desc vendor_id device_id audio_csv audio_descs
  while IFS=$'\t' read -r gpu_bdf gpu_desc vendor_id device_id audio_csv audio_descs; do
    [[ -n "${gpu_bdf:-}" ]] || continue
    gpu_bdfs+=("$gpu_bdf")
    gpu_descs+=("$gpu_desc")
    gpu_vendor_ids+=("$vendor_id")
    gpu_audio_bdfs_csv+=("$audio_csv")
    gpu_audio_descs+=("$audio_descs")
  done < <(gpu_discover_all_sysfs)

  if (( ${#gpu_bdfs[@]} < 2 )); then
    die "Found fewer than 2 GPUs. This script assumes a host GPU + guest GPU."
  fi

  # Sanity: all discovered BDFs must exist.
  for gpu_bdf in "${gpu_bdfs[@]}"; do
    assert_pci_bdf_exists "$gpu_bdf"
  done

  local -a options=()
  local i
  for i in "${!gpu_bdfs[@]}"; do
    local bdf slot audio_csv vend short
    bdf="${gpu_bdfs[$i]}"
    slot="$(pci_slot_of_bdf "$bdf")"
    audio_csv="${gpu_audio_bdfs_csv[$i]}"
    vend="$(vendor_label "${gpu_vendor_ids[$i]}")"
    short="$(short_gpu_desc "${gpu_descs[$i]}")"

    options+=("GPU: $bdf  |  Vendor: ${vend}"$'\n'"      Model: ${short}"$'\n'"      PCI slot: ${slot}  |  Slot audio: ${audio_csv:-<none>}")
  done

  local guest_idx host_idx
  hdr "Step 1/4: Select GUEST GPU (will be passed through)"
  guest_idx="$(select_from_list "Which GPU should be the GUEST (vfio-pci / passthrough)?" "${options[@]}")"

  if (( ${#gpu_bdfs[@]} == 2 )); then
    if (( guest_idx == 0 )); then host_idx=1; else host_idx=0; fi
  else
    host_idx="$(select_from_list "Select the GPU to use for HOST display:" "${options[@]}")"
    (( host_idx != guest_idx )) || die "Host GPU and guest GPU cannot be the same."
  fi

  local guest_gpu host_gpu guest_vendor guest_desc host_desc
  guest_gpu="${gpu_bdfs[$guest_idx]}"
  host_gpu="${gpu_bdfs[$host_idx]}"
  guest_vendor="${gpu_vendor_ids[$guest_idx]}"
  guest_desc="${gpu_descs[$guest_idx]}"
  host_desc="${gpu_descs[$host_idx]}"

  say
  hdr "Selection summary so far"
  say "Host GPU (stays on host):"
  say "  $host_gpu"
  note "  $(short_gpu_desc "$host_desc")"
  say "Guest GPU (passthrough / vfio-pci):"
  say "  $guest_gpu"
  note "  $(short_gpu_desc "$guest_desc")"

  assert_not_equal "$guest_gpu" "$host_gpu" "Host GPU and guest GPU are the same (refusing)."
  assert_pci_bdf_exists "$guest_gpu"
  assert_pci_bdf_exists "$host_gpu"

  # Guest audio selection (default: audio functions in the same PCI slot)
  local guest_audio_csv="${gpu_audio_bdfs_csv[$guest_idx]}"
  if [[ -n "$guest_audio_csv" ]]; then
    say
    hdr "Step 2/4: Guest GPU HDMI/DP Audio (optional)"
    say "Guest GPU: $guest_gpu"
    note "$(short_gpu_desc "$guest_desc")"
    say "Detected HDMI/DP audio PCI function(s) for this GPU: $guest_audio_csv"
    note "Choose YES if you want HDMI/DP audio output from the VM using the guest GPU."
    note "Choose NO if you plan to use a different audio device (USB headset, emulated audio, etc.)."

    prompt_yn "Also passthrough HDMI/DP AUDIO for the guest GPU?" Y || guest_audio_csv=""
  else
    say
    hdr "Step 2/4: Guest GPU HDMI/DP Audio"
    note "No HDMI/DP audio device found in the same PCI slot as the selected guest GPU ($guest_gpu)."
  fi

  # Preflight: detect if the selected guest GPU looks in-use by the host.
  gpu_in_use_preflight "$guest_gpu"

  # Preflight: IOMMU group gate.
  iommu_group_preflight "$guest_gpu" "$guest_audio_csv"

  # Check for AMD Reset Bug mitigation (vendor-reset)
  if [[ "${guest_vendor,,}" == "1002" ]]; then
    say
    hdr "AMD Reset Bug Check"
    if [[ -d /sys/module/vendor_reset ]]; then
      say "OK: 'vendor-reset' module is loaded."
      if ! grep -q "vendor-reset" "$MODULES_LOAD" 2>/dev/null; then
        say "Adding vendor-reset to $MODULES_LOAD so it loads at boot..."
        if (( ! DRY_RUN )); then
          printf '%s\n' "vendor-reset" >>"$MODULES_LOAD"
        fi
      fi
    else
      say "${C_YELLOW}WARN: AMD GPU selected but 'vendor-reset' module not found.${C_RESET}"
      note "Many AMD cards (Polaris/Vega/Navi) cannot be reliably reused after VM shutdown without this module."
      note "Recommended: install the 'vendor-reset' kernel module (see vendor-reset project docs) after this script finishes."
    fi
  fi

  # Host audio selection (important when AMD HDMI audio IDs repeat, e.g. 1002:ab28)
  local host_audio_bdfs_csv="${gpu_audio_bdfs_csv[$host_idx]}"

  say
  hdr "Step 3/4: Select HOST audio device (must stay on host)"
  say "Host GPU is: $host_gpu"
  note "$(short_gpu_desc "$host_desc")"
  note "Pick the AUDIO device that should KEEP working on the host (for your desktop sound)."
  note "Tip: for HDMI sound from the host GPU, pick the audio device in the SAME PCI slot as the host GPU."
  note "This avoids the common AMD issue where both HDMI audio devices share the same ID (1002:ab28)."

  local host_slot
  host_slot="$(pci_slot_of_bdf "$host_gpu")"

  local -a aud_opts=() aud_bdfs=()
  local abdf adesc avendor adev
  while IFS=$'\t' read -r abdf adesc avendor adev; do
    local aslot atype vend rec_tag
    aslot="$(pci_slot_of_bdf "$abdf")"
    atype="$(short_audio_desc "$adesc")"
    vend="$(vendor_label "$avendor")"

    rec_tag=""
    if [[ "$aslot" == "$host_slot" ]]; then
      rec_tag="${C_BOLD}${C_GREEN}[RECOMMENDED for host GPU]${C_RESET} "
      (( ! ENABLE_COLOR )) && rec_tag="[RECOMMENDED for host GPU] "
    fi

    aud_bdfs+=("$abdf")
    aud_opts+=("${rec_tag}Audio: $abdf  |  Type: ${atype}  |  Vendor: ${vend}"$'\n'"      PCI slot: ${aslot}  |  IDs: ${avendor}:${adev}"$'\n'"      lspci: $(short_gpu_desc "$adesc")")
  done < <(audio_devices_discover_all)

  if (( ${#aud_bdfs[@]} > 0 )); then
    local host_audio_idx
    host_audio_idx="$(select_from_list "Which AUDIO device should stay on the HOST?" "${aud_opts[@]}")"
    host_audio_bdfs_csv="${aud_bdfs[$host_audio_idx]}"
    [[ -n "$host_audio_bdfs_csv" ]] && assert_pci_bdf_exists "$host_audio_bdfs_csv"
  else
    say "WARN: No PCI audio devices found via lspci."
    host_audio_bdfs_csv=""
  fi

  # Hard safety: host audio must never equal guest GPU.
  if [[ -n "$host_audio_bdfs_csv" ]]; then
    assert_not_equal "$host_audio_bdfs_csv" "$guest_gpu" "Selected host audio equals guest GPU BDF (refusing)."
  fi

  # Slot sanity: host audio should match host GPU slot unless explicitly overridden.
  audio_slot_sanity "$host_gpu" "$host_audio_bdfs_csv"

  # PipeWire default sink selection (user-session)
  local host_audio_node_name=""
  if command -v wpctl >/dev/null 2>&1; then
    if prompt_yn "Do you want to select the DEFAULT AUDIO SINK for the host user session (PipeWire/WirePlumber)?" Y; then
      note "(Tip: this sets the default sink name for the user session; it does NOT affect VFIO binding.)"
      local -a sink_opts=() sink_node_names=()

      # Prefer sinks that match the selected host audio PCI device.
      if [[ -n "$host_audio_bdfs_csv" ]]; then
        note "Recommended: pick the sink that uses the HOST audio PCI device ($host_audio_bdfs_csv)."
        while IFS=$'\t' read -r sname slabel; do
          sink_node_names+=("$sname")
          if (( ENABLE_COLOR )); then
            sink_opts+=("${C_BOLD}${C_GREEN}[RECOMMENDED: host audio]${C_RESET} $sname  ::  $slabel")
          else
            sink_opts+=("[RECOMMENDED: host audio] $sname  ::  $slabel")
          fi
        done < <(pipewire_sinks_for_pci_bdf "$host_audio_bdfs_csv" 2>/dev/null || true)
      fi

      # Add the rest.
      local sid sname slabel
      while IFS=$'\t' read -r sid sname slabel; do
        # Avoid duplicates.
        local seen=0
        local existing
        for existing in "${sink_node_names[@]}"; do
          [[ "$existing" == "$sname" ]] && { seen=1; break; }
        done
        (( seen )) && continue

        sink_node_names+=("$sname")
        sink_opts+=("$sname  ::  $slabel")
      done < <(pipewire_sinks_discover || true)

    if (( ${#sink_node_names[@]} > 0 )); then
        local sink_idx
        hdr "Step 4/4: Choose default HOST audio output (PipeWire)"
        note "This only sets your desktop's default sound output after login."
        note "It does NOT change what gets passed through to the VM."
        sink_idx="$(select_from_list "Which host audio OUTPUT should be default?" "${sink_opts[@]}")"
        host_audio_node_name="${sink_node_names[$sink_idx]}"
      else
        note "Could not enumerate PipeWire sinks (common if PipeWire isn't running for that user yet). Skipping."
      fi
    fi
  fi

  say
  say "Summary:"
  say "  Host GPU:   $host_gpu"
  say "  Guest GPU:  $guest_gpu (vendor: $(vendor_name "$guest_vendor"))"
  say "  Host audio PCI:  ${host_audio_bdfs_csv:-<none>}"
  say "  Guest audio PCI: ${guest_audio_csv:-<none>}"
  say "  Host default sink node.name: ${host_audio_node_name:-<not set>}"
  say

  hdr "Apply changes"
  note "If you continue, this script will install the core VFIO binding setup:" 
  note "  - Write $CONF_FILE (your selected PCI BDFs)"
  note "  - Write $MODULES_LOAD (load vfio modules at boot)"
  note "  - Write $BIND_SCRIPT (bind ONLY the selected guest BDF(s) to vfio-pci)"
  note "  - Write + enable $SYSTEMD_UNIT (runs the bind script early at boot)"
  note "It will then ASK about optional steps (GRUB/IOMMU, ACS override, blacklisting, initramfs, host audio unit)."
  note "Important: The VFIO binding will fully take effect AFTER a reboot."

  prompt_yn "Apply these changes now?" N || die "Aborted by user"

  # Preflight sanity checks before writing anything.
  assert_pci_bdf_exists "$host_gpu"
  assert_pci_bdf_exists "$guest_gpu"
  if [[ -n "$host_audio_bdfs_csv" ]]; then
    assert_pci_bdf_exists "$host_audio_bdfs_csv"
  fi
  if [[ -n "$guest_audio_csv" ]]; then
    # validate each guest audio bdf
    local IFS=','
    for dev in $guest_audio_csv; do
      [[ -n "$dev" ]] || continue
      assert_pci_bdf_exists "$dev"
      assert_not_equal "$dev" "$host_audio_bdfs_csv" "Guest audio BDF equals host audio BDF (refusing)."
    done
  fi

  write_conf "$host_gpu" "$host_audio_bdfs_csv" "$host_audio_node_name" "$guest_gpu" "$guest_audio_csv" "$guest_vendor"
  install_vfio_modules_load

  say
  hdr "Initramfs integration (optional)"
  note "By default, VFIO modules will load from the root filesystem via $MODULES_LOAD after it is mounted."
  note "You can also pre-load them in the initramfs via dracut config; this is more invasive and can affect very early boot."
  if prompt_yn "Install dracut config to include VFIO modules in the initramfs now? (advanced)" N; then
    install_dracut_config
  else
    note "Skipping dracut VFIO initramfs config. You can add it later by re-running this helper."
  fi

  say
  hdr "Module load ordering (optional soft dependency)"
  note "To reduce race conditions where the GPU driver (amdgpu/nvidia/i915) grabs the card before vfio-pci,"
  note "you can install a softdep rule so vfio-pci is always loaded first for the guest GPU vendor."
  note "This is usually safe, but if you have unusual driver setups you may prefer to skip it."
  if prompt_yn "Install vfio-pci softdep for $(vendor_name "$guest_vendor") now?" Y; then
    install_softdep_config "$guest_vendor"
  else
    note "Skipping vfio softdep installation. You can add it later in /etc/modprobe.d/vfio-softdep.conf if needed."
  fi

  install_bind_script
  install_systemd_unit

  say
  hdr "Boot configuration (IOMMU / boot loader)"
  local bl2
  bl2="$(detect_bootloader)"
  note "IOMMU must be enabled for PCI passthrough to work."
  note "Boot loader detected: ${bl2}"
  if [[ "$bl2" == "grub" ]]; then
    note "Recommended: YES (adds amd_iommu=on or intel_iommu=on + iommu=pt to GRUB)."
    note "If you answer NO, passthrough may fail unless you already configured IOMMU another way."
  else
    note "Automatic kernel parameter editing is ONLY supported for GRUB. For ${bl2}, you must add the parameters manually."
    note "If you skip the manual instructions, passthrough may fail."
  fi
  note "If you enable IOMMU, you will also be offered an optional 'ACS override' (advanced; usually NO)."

  local q
  if [[ "$bl2" == "grub" ]]; then
    q="Enable IOMMU kernel parameters in GRUB now? (recommended)"
  else
    q="Show recommended IOMMU kernel parameters and MANUAL instructions now? (recommended)"
  fi

  if prompt_yn "$q" Y; then
    if [[ "$bl2" == "grub" ]]; then
      grub_add_kernel_params
    else
      print_manual_iommu_instructions
    fi
  else
    note "Skipping automatic/manual IOMMU helper. Ensure your kernel parameters enable IOMMU, or passthrough may fail."
  fi

  # Optional driver blacklisting
  say
  hdr "Optional: driver blacklisting (advanced)"
  note "Blacklisting prevents the host from loading a GPU vendor's kernel modules at boot."
  note "This can help passthrough on some systems, but it can also break host graphics if you blacklist the wrong thing."
  note "This script does NOT require blacklisting (it binds by PCI BDF to vfio-pci instead)."

  local -a suggested_mods=()
  local suggested_note=""
  case "${guest_vendor,,}" in
    10de)
      suggested_mods=(nouveau nvidia nvidia_drm nvidia_modeset nvidia_uvm)
      ;;
    1002)
      # Many people prefer NOT to blacklist amdgpu on dual-GPU systems.
      suggested_mods=(radeon)
      suggested_note="AMD note: 'amdgpu' is the modern driver and is often used by the host GPU on dual-AMD systems. Blacklisting amdgpu is usually NOT recommended unless you're sure the host does not need it."
      ;;
    8086)
      suggested_mods=(i915)
      ;;
    *)
      suggested_mods=()
      ;;
  esac

  if (( ${#suggested_mods[@]} > 0 )); then
    note "If you choose YES, this script will offer to write: $BLACKLIST_FILE"
    note "Suggested modules to blacklist for vendor $(vendor_name "$guest_vendor") ($guest_vendor):"
    local m
    for m in "${suggested_mods[@]}"; do
      note "  - blacklist $m"
    done
    [[ -n "$suggested_note" ]] && note "$suggested_note"
  else
    note "No suggested modules for vendor $(vendor_name "$guest_vendor") ($guest_vendor)."
  fi

  # Extra safety: require an explicit BLACKLIST confirmation before entering the submenu.
  if prompt_yn "Open advanced driver blacklist submenu for $(vendor_name "$guest_vendor") drivers?" N; then
    if ! confirm_phrase "WARNING: Driver blacklisting is OPTIONAL and can break host graphics if misused. To continue and create $BLACKLIST_FILE, type BLACKLIST." "BLACKLIST"; then
      note "Skipping driver blacklist (confirmation failed)."
    else
      # User typed BLACKLIST; give them one last chance to cancel and proceed without any blacklist.
      if ! prompt_yn "You typed BLACKLIST. Do you still want to create a driver blacklist file now?" N; then
        note "Skipping driver blacklist (user cancelled after confirmation)."
      else
        local -a mods=() candidates=() recommended=()

        case "${guest_vendor,,}" in
          10de)
            candidates=(nouveau nvidia nvidia_drm nvidia_modeset nvidia_uvm)
            # No safe universal default for NVIDIA -> recommended empty.
            recommended=()
            ;;
          1002)
            # AMD: amdgpu is often needed for the host GPU on dual-AMD systems.
            candidates=(amdgpu radeon)
            # Conservative default: blacklist only the legacy radeon module.
            recommended=(2)
            ;;
          8086)
            candidates=(i915)
            # No safe universal default -> recommended empty.
            recommended=()
            ;;
          *)
            candidates=()
            recommended=()
            note "Unknown vendor; no suggested modules."
            ;;
        esac

        if (( ${#candidates[@]} == 0 )); then
          note "No blacklist candidates for this vendor; skipping."
        else
          say
          note "Choose which kernel modules to blacklist by number (example: 1 2)."
          note "Enter 0 for none."
          if (( ${#recommended[@]} > 0 )); then
            note "Press ENTER for recommended: ${recommended[*]}"
          else
            note "Press ENTER for recommended: (none)"
          fi

          local in="/dev/stdin"
          local out="/dev/stderr"
          if [[ -r /dev/tty && -w /dev/tty ]]; then
            in="/dev/tty"
            out="/dev/tty"
          fi

          while true; do
            local i
            for i in "${!candidates[@]}"; do
              local n=$((i+1))
              printf '  [%d] blacklist %s\n' "$n" "${candidates[$i]}" >"$out"
            done

            printf 'Select modules to blacklist (numbers): ' >"$out"
            local raw
            read -r raw <"$in" || raw=""
            raw="$(trim "$raw")"

            local -a picks=()

            if [[ -z "$raw" ]]; then
              picks=("${recommended[@]}")
            elif [[ "$raw" == "0" ]]; then
              picks=()
            else
              # allow commas and spaces
              raw="${raw//,/ }"
              local tok
              for tok in $raw; do
                [[ "$tok" =~ ^[0-9]+$ ]] || { printf '%s\n' "Invalid selection: '$tok'" >"$out"; picks=(); break; }
                (( tok >= 1 && tok <= ${#candidates[@]} )) || { printf '%s\n' "Out of range: $tok" >"$out"; picks=(); break; }
                # de-dupe
                local seen=0 x
                for x in "${picks[@]}"; do
                  [[ "$x" == "$tok" ]] && { seen=1; break; }
                done
                (( seen )) || picks+=("$tok")
              done
              # if we broke due to invalid input, re-prompt
              if [[ "$raw" != "0" && -n "$raw" && ${#picks[@]} -eq 0 ]]; then
                continue
              fi
            fi

            mods=()
            local p
            for p in "${picks[@]}"; do
              mods+=("${candidates[$((p-1))]}")
            done
            break
          done

          if (( ${#mods[@]} > 0 )); then
            write_optional_blacklist "$guest_vendor" "${mods[@]}"
            say "Wrote $BLACKLIST_FILE"
            say "NOTE: If you blacklist modules, updating initramfs is strongly recommended."
          else
            say "No modules selected; skipping blacklist file."
          fi
        fi
      fi
    fi
  fi

  if prompt_yn "Update initramfs now? (recommended after VFIO and/or blacklisting changes)" Y; then
    maybe_update_initramfs
  fi

  # Generate a rollback script after changes are applied.
  generate_rollback_script

  if prompt_yn "Install a user systemd unit to set the host default audio sink after login?" Y; then
    install_audio_script
    install_user_audio_unit
  fi

  say
  say "Done. Next steps:"
  say "  1) Reboot."
  say "  2) Verify guest devices are bound to vfio-pci:"
  say "       lspci -nnk -s $guest_gpu"
  if [[ -n "$guest_audio_csv" ]]; then
    local IFS=','
    for dev in $guest_audio_csv; do
      say "       lspci -nnk -s $dev"
    done
  fi
  say "  3) Verify host audio device is NOT on vfio-pci:"
  if [[ -n "$host_audio_bdfs_csv" ]]; then
    say "       lspci -nnk -s ${host_audio_bdfs_csv%%,*}"
  fi
  say "  4) In your VM manager, passthrough the guest GPU and any selected guest audio PCI functions."
}

main "$@"
