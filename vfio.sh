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

# Global context structure used to separate detection, user selection and
# application logic. Keys are documented near detect_system/user_selection.
# Example keys:
#   CTX[bootloader]           - detected bootloader (grub/systemd-boot/...) 
#   CTX[guest_gpu]            - selected guest GPU BDF
#   CTX[host_gpu]             - selected host GPU BDF
#   CTX[guest_audio_csv]      - CSV of guest audio BDFs
#   CTX[host_audio_bdfs_csv]  - CSV of host audio BDFs
#   CTX[host_audio_node_name] - PipeWire node name for host default sink
#   CTX[guest_vendor]         - guest GPU vendor ID (e.g. 1002)
#
# This keeps the wizard's state explicit and makes it easier to extend.
declare -Ag CTX=()

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

# Optional TUI support (whiptail/dialog-style). If not available, we fall back
# to the existing plain-text prompts. This keeps the script usable everywhere
# while offering a nicer UI when possible.
HAS_TUI=0
if command -v whiptail >/dev/null 2>&1; then
  HAS_TUI=1
fi

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
  # prompt_yn "Question" default(Y/N) [title]
  local q="$1"; local def="${2:-Y}"; local title="${3:-Confirmation}"; local ans

  # TUI path: use whiptail if available.
  if (( HAS_TUI )); then
    local exit_status
    if [[ "$def" =~ ^[Nn]$ ]]; then
      whiptail --title "$title" --defaultno --yesno "$q" 10 60
      exit_status=$?
    else
      whiptail --title "$title" --yesno "$q" 10 60
      exit_status=$?
    fi
    # whiptail exit status: 0 = Yes, 1/255 = No/ESC
    return $exit_status
  fi

  # Fallback: original plain-text logic on /dev/tty.
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
Usage: $SCRIPT_NAME [--debug] [--dry-run] [--no-tui] [--verify] [--detect] [--self-test] [--reset]

  --debug      Enable verbose debug logging (and bash xtrace).
  --dry-run    Show actions but do not write files / run system-changing commands.
  --no-tui     Force plain-text prompts even if whiptail is installed.
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
      --no-tui)
        HAS_TUI=0
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
        note "      This can lock the GPU memory, causing VFIO binding to fail (\"Header type 127\" / hangs)."
        
        local fb_param=""
        if grep -qi "simple-framebuffer" /proc/iomem 2>/dev/null; then
          fb_param="video=simplefb:off"
        elif grep -qi "efifb" /proc/iomem 2>/dev/null; then
          fb_param="video=efifb:off"
        else
          fb_param="video=vesafb:off"
        fi

        # IMPORTANT for stability on some systems ("Christmas tree" crash):
        # this prompt now matches the recommended wording exactly.
        if prompt_yn "Add '$fb_param' to GRUB?" Y "Boot framebuffer options"; then
          export GRUB_EXTRA_PARAMS="${GRUB_EXTRA_PARAMS:-} ${fb_param}"
          say "Queued '$fb_param' for GRUB update. It will be applied if you enable IOMMU/GRUB editing."
        else
          if ! prompt_yn "Continue without fixing (higher risk of passthrough failure)?" N "Boot framebuffer options"; then
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
    local euid
    euid="${EUID:-$(id -u)}"

    # Best-effort: if running under sudo with a real SUDO_USER and runuser,
    # try to talk to that user's PipeWire instance via /run/user/$uid. If
    # the runtime dir does not exist, fall back to plain wpctl.
    if [[ "$euid" -eq 0 ]]; then
      if [[ -n "${SUDO_USER:-}" ]] && have_cmd runuser; then
        local uid runtime
        uid="$(id -u "$SUDO_USER")"
        runtime="/run/user/$uid"
        if [[ -d "$runtime" ]]; then
          runuser -u "$SUDO_USER" -- env XDG_RUNTIME_DIR="$runtime" wpctl "$@"
          return $?
        fi
      else
        # If running as root without SUDO_USER, warn once that audio
        # auto-detection may be incomplete because there is no obvious
        # desktop user session to talk to.
        if [[ -z "${_VFIO_WPCTL_ROOT_WARNED:-}" ]]; then
          _VFIO_WPCTL_ROOT_WARNED=1
          note "wpctl is running as root without SUDO_USER; PipeWire device detection may be limited. Run this helper via sudo from your desktop user for best results."
        fi
      fi
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
  if (( ENABLE_COLOR )); then
    say "${C_CYAN}${C_BOLD}==== Existing VFIO / Passthrough Detection Report ==== ${C_RESET}"
  else
    say "==== Existing VFIO / Passthrough Detection Report ===="
  fi

  # Basic host state
  if (( ENABLE_COLOR )); then
    print_kv "Kernel" "${C_GREEN}$(uname -r)${C_RESET}"
    print_kv "Current cmdline" "${C_DIM}$(cat /proc/cmdline 2>/dev/null || true)${C_RESET}"
    print_kv "Bootloader" "${C_GREEN}$(detect_bootloader)${C_RESET}"
  else
    print_kv "Kernel" "$(uname -r)"
    print_kv "Current cmdline" "$(cat /proc/cmdline 2>/dev/null || true)"
    print_kv "Bootloader" "$(detect_bootloader)"
  fi

  # Health check
  say
  if (( ENABLE_COLOR )); then
    say "${C_CYAN}-- Health check --${C_RESET}"
  else
    say "-- Health check --"
  fi
  local hc
  hc="$(vfio_config_health)"
  local status
  status="$(printf '%s\n' "$hc" | awk -F= '/^STATUS=/{print $2; exit}')"
  if (( ENABLE_COLOR )); then
    case "${status:-UNKNOWN}" in
      OK)
        print_kv "Health" "${C_GREEN}${status}${C_RESET}"
        ;;
      WARN)
        print_kv "Health" "${C_YELLOW}${status}${C_RESET}"
        ;;
      BAD)
        print_kv "Health" "${C_RED}${status}${C_RESET}"
        ;;
      *)
        print_kv "Health" "${status:-UNKNOWN}"
        ;;
    esac
  else
    print_kv "Health" "${status:-UNKNOWN}"
  fi
  printf '%s\n' "$hc" | awk -F= '/^REASON=/{print "  - " $2}'

  # Our config
  if readable_file "$CONF_FILE"; then
    if (( ENABLE_COLOR )); then
      print_kv "Config" "${C_GREEN}$CONF_FILE (present)${C_RESET}"
    else
      print_kv "Config" "$CONF_FILE (present)"
    fi
    # shellcheck disable=SC1090
    . "$CONF_FILE"
    print_kv "Configured host GPU" "${HOST_GPU_BDF:-<unset>}"
    print_kv "Configured guest GPU" "${GUEST_GPU_BDF:-<unset>}"
    print_kv "Configured host audio" "${HOST_AUDIO_BDFS_CSV:-<unset>}"
    print_kv "Configured guest audio" "${GUEST_AUDIO_BDFS_CSV:-<unset>}"
  else
    if (( ENABLE_COLOR )); then
      print_kv "Config" "${C_RED}$CONF_FILE (missing)${C_RESET}"
    else
      print_kv "Config" "$CONF_FILE (missing)"
    fi
  fi

  # systemd unit
  if readable_file "$SYSTEMD_UNIT"; then
    if (( ENABLE_COLOR )); then
      print_kv "Systemd unit" "${C_GREEN}$SYSTEMD_UNIT (present)${C_RESET}"
    else
      print_kv "Systemd unit" "$SYSTEMD_UNIT (present)"
    fi
    if command -v systemctl >/dev/null 2>&1; then
      print_kv "Unit enabled" "$(systemctl is-enabled vfio-bind-selected-gpu.service 2>/dev/null || true)"
      print_kv "Unit active" "$(systemctl is-active vfio-bind-selected-gpu.service 2>/dev/null || true)"
      print_kv "Unit status" "$(systemctl show -p ExecStart vfio-bind-selected-gpu.service 2>/dev/null | sed 's/^ExecStart=//' || true)"
    fi
  else
    if (( ENABLE_COLOR )); then
      print_kv "Systemd unit" "${C_RED}$SYSTEMD_UNIT (missing)${C_RESET}"
    else
      print_kv "Systemd unit" "$SYSTEMD_UNIT (missing)"
    fi
  fi

  # modules-load
  if readable_file "$MODULES_LOAD"; then
    if (( ENABLE_COLOR )); then
      print_kv "Modules-load" "${C_GREEN}$MODULES_LOAD (present)${C_RESET}"
    else
      print_kv "Modules-load" "$MODULES_LOAD (present)"
    fi
    print_kv "Modules-load content" "$(tr '\n' ' ' <"$MODULES_LOAD" 2>/dev/null || true)"
  else
    if (( ENABLE_COLOR )); then
      print_kv "Modules-load" "${C_RED}$MODULES_LOAD (missing)${C_RESET}"
    else
      print_kv "Modules-load" "$MODULES_LOAD (missing)"
    fi
  fi

  # modprobe configs
  local hits=""
  if [[ -d /etc/modprobe.d ]]; then
    hits="$(grep -RIn --no-messages -E 'vfio-pci|vfio_pci|driver_override|blacklist (amdgpu|nouveau|nvidia|i915|radeon)' /etc/modprobe.d 2>/dev/null | head -n 50 || true)"
  fi
  if [[ -n "$hits" ]]; then
    say
    if (( ENABLE_COLOR )); then
      say "${C_CYAN}-- /etc/modprobe.d matches (first 50) --${C_RESET}"
    else
      say "-- /etc/modprobe.d matches (first 50) --"
    fi
    printf '%s\n' "$hits"
  else
    say
    if (( ENABLE_COLOR )); then
      say "${C_CYAN}-- /etc/modprobe.d matches --${C_RESET}"
    else
      say "-- /etc/modprobe.d matches --"
    fi
    say "  (none found)"
  fi

  # initramfs hints
  say
  if (( ENABLE_COLOR )); then
    say "${C_CYAN}-- initramfs tooling detected --${C_RESET}"
  else
    say "-- initramfs tooling detected --"
  fi
  if (( ENABLE_COLOR )); then
    local u_i m_i d_i
    u_i="$(command -v update-initramfs >/dev/null 2>&1 && echo yes || echo no)"
    m_i="$(command -v mkinitcpio >/dev/null 2>&1 && echo yes || echo no)"
    d_i="$(command -v dracut >/dev/null 2>&1 && echo yes || echo no)"

    [[ "$u_i" == yes ]] && u_i="${C_GREEN}yes${C_RESET}" || u_i="${C_RED}no${C_RESET}"
    [[ "$m_i" == yes ]] && m_i="${C_GREEN}yes${C_RESET}" || m_i="${C_RED}no${C_RESET}"
    [[ "$d_i" == yes ]] && d_i="${C_GREEN}yes${C_RESET}" || d_i="${C_RED}no${C_RESET}"

    print_kv "update-initramfs" "$u_i"
    print_kv "mkinitcpio" "$m_i"
    print_kv "dracut" "$d_i"
  else
    print_kv "update-initramfs" "$(command -v update-initramfs >/dev/null 2>&1 && echo yes || echo no)"
    print_kv "mkinitcpio" "$(command -v mkinitcpio >/dev/null 2>&1 && echo yes || echo no)"
    print_kv "dracut" "$(command -v dracut >/dev/null 2>&1 && echo yes || echo no)"
  fi
  if readable_file /etc/initramfs-tools/modules; then
    print_kv "/etc/initramfs-tools/modules" "present"
    print_kv "vfio in initramfs-tools/modules" "$(grep -nE '^(vfio|vfio_pci|vfio-iommu-type1|vfio_virqfd)' /etc/initramfs-tools/modules 2>/dev/null | tr '\n' ' ' || true)"
  fi
  if [[ -d /etc/dracut.conf.d ]]; then
    if (( ENABLE_COLOR )); then
      print_kv "/etc/dracut.conf.d" "${C_GREEN}present${C_RESET}"
    else
      print_kv "/etc.dracut.conf.d" "present"
    fi
    print_kv "vfio in dracut conf" "$(grep -RIn --no-messages -E 'vfio|vfio-pci|add_drivers|force_drivers' /etc/dracut.conf.d 2>/dev/null | head -n 20 | tr '\n' ' ' || true)"
  fi

  # vendor-reset module (useful for AMD reset bugs)
  if [[ -d /sys/module/vendor_reset ]]; then
    if (( ENABLE_COLOR )); then
      print_kv "vendor-reset" "${C_GREEN}Loaded (good for AMD reset bugs)${C_RESET}"
    else
      print_kv "vendor-reset" "Loaded (good for AMD reset bugs)"
    fi
  else
    if command -v lspci >/dev/null 2>&1 && lspci -n | grep -q "1002:"; then
      if (( ENABLE_COLOR )); then
        print_kv "vendor-reset" "${C_YELLOW}MISSING (Recommended for AMD GPUs with reset issues)${C_RESET}"
      else
        print_kv "vendor-reset" "MISSING (Recommended for AMD GPUs with reset issues)"
      fi
    else
      print_kv "vendor-reset" "Not loaded"
    fi
  fi

  # GRUB defaults
  if readable_file /etc/default/grub; then
    say
    if (( ENABLE_COLOR )); then
      say "${C_CYAN}-- /etc/default/grub cmdline --${C_RESET}"
    else
      say "-- /etc/default/grub cmdline --"
    fi
    local key
    key="$(grub_get_key 2>/dev/null || true)"
    if [[ -n "$key" ]]; then
      print_kv "$key" "$(grub_read_cmdline "$key" 2>/dev/null || true)"
    else
      say "  Could not locate GRUB_CMDLINE_LINUX(_DEFAULT)"
    fi
  fi

  # BLS / systemd-boot entries (for openSUSE and other BLS users).
  # In full reports (e.g. --detect) we show ALL entries; in brief
  # reports (e.g. --verify) we skip this verbose listing and rely on
  # the dedicated current-entry check instead.
  if [[ -z "${VFIO_BRIEF_REPORT:-}" ]]; then
    local bls_dir
    bls_dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
    if [[ -n "$bls_dir" ]]; then
      say
      if (( ENABLE_COLOR )); then
        say "${C_CYAN}-- Boot Loader Spec entries (IOMMU/VFIO params) --${C_RESET}"
      else
        say "-- Boot Loader Spec entries (IOMMU/VFIO params) --"
      fi
      local f opts
      shopt -s nullglob
      for f in "$bls_dir"/*.conf; do
        opts="$(grep -m1 -E '^options[[:space:]]+' "$f" 2>/dev/null | sed -E 's/^options[[:space:]]+//')"
        opts="$(trim "${opts:-}")"
        if [[ -z "$opts" ]]; then
          print_kv "$(basename "$f")" "<no options line>"
          continue
        fi

        local -a missing=()
        if ! grep -qwE 'amd_iommu=on|intel_iommu=on' <<<"$opts"; then
          missing+=("iommu_on")
        fi
        if ! grep -qw "iommu=pt" <<<"$opts"; then
          missing+=("iommu_pt")
        fi
        # On openSUSE dracut systems, rd.driver.pre=vfio-pci is highly
        # recommended, so we flag its absence separately.
        if is_opensuse_like && command -v dracut >/dev/null 2>&1; then
          if ! grep -qw "rd.driver.pre=vfio-pci" <<<"$opts"; then
            missing+=("rd.driver.pre=vfio-pci")
          fi
        fi

        if (( ${#missing[@]} == 0 )); then
          print_kv "$(basename "$f")" "OK (IOMMU + VFIO params present)"
        else
          print_kv "$(basename "$f")" "WARN missing: ${missing[*]}"
        fi
      done
      shopt -u nullglob
    fi
  fi

  # Current device bindings
  say
  if (( ENABLE_COLOR )); then
    say "${C_CYAN}-- Current GPU/Audio bindings (lspci -nnk) --${C_RESET}"
  else
    say "-- Current GPU/Audio bindings (lspci -nnk) --"
  fi
  if command -v lspci >/dev/null 2>&1; then
    lspci -Dnn | awk '/(VGA compatible controller|3D controller|Display controller|Audio device)/ {print $1}' | while read -r bdf; do
      [[ -n "$bdf" ]] || continue
      # Only show AMD/NVIDIA/Intel GPUs + audio
      if lspci -Dnn -s "$bdf" | grep -Eq 'Advanced Micro Devices|AMD/ATI|NVIDIA|Intel|Audio device'; then
        if (( ENABLE_COLOR )); then
          printf '%s\n' "${C_GREEN}  $bdf${C_RESET}"
          lspci -Dnnk -s "$bdf" 2>/dev/null | sed '1d;s/^/  /'
        else
          printf '%s\n' "$(lspci -Dnnk -s "$bdf" 2>/dev/null | sed 's/^/  /')"
        fi
      fi
    done
  fi

  # Libvirt hook detection (common VFIO stage)
  say
  if (( ENABLE_COLOR )); then
    say "${C_CYAN}-- libvirt hook detection --${C_RESET}"
  else
    say "-- libvirt hook detection --"
  fi
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
  # select_from_list "Prompt" "Title" options...
  local prompt="$1"; local title="$2"; shift 2
  local -a options=("$@")
  local idx

  # TUI path: use whiptail if available. We keep zero-based indices by using
  # the index as the whiptail TAG and returning it directly.
  if (( HAS_TUI )); then
    local -a menu_args=()
    local i opt first_line
    for i in "${!options[@]}"; do
      opt="${options[$i]}"
      # Use the first line of the option as the menu label.
      first_line="${opt%%$'\n'*}"
      menu_args+=("$i" "$first_line")
    done

    local choice
    choice=$(whiptail --title "$title" --menu "$prompt" 20 75 10 "${menu_args[@]}" 3>&1 1>&2 2>&3) || die "Selection cancelled."
    # choice is already the zero-based index as a string.
    echo "$choice"
    return 0
  fi

  # Fallback: original plain-text menu on /dev/tty.
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

# Return 0 if the core vfio-pci module is available for this kernel.
# This is used to avoid adding rd.driver.pre=vfio-pci on systems where
# the module is not built at all (which would otherwise cause dracut
# to emit "FATAL: Module vfio-pci not found" during early boot).
vfio_pci_available() {
  if command -v modinfo >/dev/null 2>&1; then
    modinfo vfio-pci >/dev/null 2>&1
    return $?
  fi
  # If modinfo is missing, be conservative and assume not available.
  return 1
}

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

# On some openSUSE Tumbleweed systems with recent default kernels, AMD Navi
# GPUs (such as 73bf) may still be claimed by amdgpu even when vfio-pci.ids=
# and rd.driver.pre=vfio-pci are present. In testing, the distribution's
# longterm kernel (package: kernel-longterm) behaved more predictably and
# allowed vfio-pci to bind the GPU at boot. This helper does NOT force a
# kernel switch automatically, but offers to install kernel-longterm so the
# user can choose that entry at boot.
maybe_offer_kernel_longterm() {
  local guest_vendor_b10="$1" guest_gpu_bdf="$2"

  # Only relevant on openSUSE-like systems using zypper.
  if ! is_opensuse_like; then
    return 0
  fi
  if ! have_cmd zypper; then
    return 0
  fi

  # Only makes sense for AMD guest GPUs.
  if [[ "${guest_vendor_b10,,}" != "1002" ]]; then
    return 0
  fi

  # If the guest GPU is already bound to vfio-pci on this boot, there is no
  # need to suggest an alternative kernel.
  if [[ "$(bdf_driver_name "$guest_gpu_bdf")" == "vfio-pci" ]]; then
    return 0
  fi

  # If kernel-longterm is already installed, nothing to do.
  if rpm -q kernel-longterm >/dev/null 2>&1; then
    return 0
  fi

  say
  hdr "Optional: install long-term kernel for more reliable VFIO binding"
  note "On some openSUSE Tumbleweed systems with AMD GPUs, the very newest default kernel can let amdgpu claim the guest GPU even when vfio-pci.ids= is set."
  note "The distribution's long-term support kernel (package: kernel-longterm) often has a more conservative driver stack and has been observed to let vfio-pci bind cleanly."
  note "Installing kernel-longterm keeps your current kernel installed; at boot you can pick either the default or the long-term kernel from the menu."

  # If we detect that the guest GPU is still owned by amdgpu right now,
  # strongly suggest installing the long-term kernel by making YES the
  # default answer. Otherwise keep it as an opt-in.
  local def="N"
  if [[ "$(bdf_driver_name "$guest_gpu_bdf")" == "amdgpu" ]]; then
    def="Y"
    note "Right now the guest GPU ($guest_gpu_bdf) is driven by amdgpu; installing kernel-longterm is RECOMMENDED so vfio-pci can reliably bind it."
  else
    note "If you later find that amdgpu still owns the guest GPU after enabling VFIO, consider installing kernel-longterm manually: zypper in kernel-longterm."
  fi

  if prompt_yn "Install the kernel-longterm package now via zypper (optional, safe alongside the current kernel)?" "$def" "Kernel (optional)"; then
    run zypper --non-interactive in kernel-longterm || \
      note "kernel-longterm install via zypper failed; you can install it manually later with: zypper in kernel-longterm"
  fi
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

  # Older RHEL/CentOS-style dracut setups tend to be more conservative
  # when using force_drivers; a missing or renamed module can in theory
  # cause early-boot surprises. For those, we prefer add_drivers. On
  # openSUSE we pair rd.driver.pre=vfio-pci with force_drivers so VFIO
  # is definitely present as an early driver.
  local dracut_directive="add_drivers"
  if is_opensuse_like; then
    dracut_directive="force_drivers"
  fi

  write_file_atomic "$file" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
# Ensure VFIO modules are included in the initramfs image.
# NOTE: this uses ${dracut_directive} so VFIO modules are available early
#       in the initramfs. On openSUSE this combines with rd.driver.pre=vfio-pci
#       so VFIO wins the race against the GPU driver; on other dracut-based
#       systems we keep a slightly more conservative add_drivers default.
${dracut_directive}+=" ${joined} "
EOF

  say "Installed Dracut configuration to ensure early VFIO loading (dracut: ${dracut_directive})."
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

# Run a best-effort GRUB syntax check on the generated grub.cfg, if tooling
# is available. This helps catch situations where an edited cmdline or script
# causes lexer errors at boot ("lexer.c:352: syntax error").
#
# We return non-zero when GRUB reports a syntax error so callers can
# automatically roll back to a known-good /etc/default/grub if a backup
# from this run exists.
maybe_check_grub_cfg() {
  local cfg=""

  # Locate grub.cfg in common locations.
  if [[ -f /boot/grub2/grub.cfg ]]; then
    cfg="/boot/grub2/grub.cfg"
  elif [[ -f /boot/grub/grub.cfg ]]; then
    cfg="/boot/grub/grub.cfg"
  fi

  [[ -n "$cfg" ]] || return 0

  # Prefer grub2-script-check if present.
  if command -v grub2-script-check >/dev/null 2>&1; then
    if grub2-script-check "$cfg" >/dev/null 2>&1; then
      return 0
    fi
    note "GRUB syntax check reported issues in $cfg (boot menu may show lexer errors)."
    return 1
  fi

  # Some distros ship grub-script-check instead.
  if command -v grub-script-check >/dev/null 2>&1; then
    if grub-script-check "$cfg" >/dev/null 2>&1; then
      return 0
    fi
    note "GRUB syntax check reported issues in $cfg (boot menu may show lexer errors)."
    return 1
  fi

  return 0
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

# Return 0 if the running kernel looks like an openSUSE default kernel
# ("*-default") with a version at or above a given threshold. This is used
# to warn users about known/expected VFIO binding issues on very new
# default kernels, and to suggest booting the long-term kernel instead.
opensuse_default_kernel_is_at_least() {
  local min_major="$1" min_minor="$2"
  local kver rel base major minor

  kver="$(uname -r 2>/dev/null || echo '')"
  [[ -n "$kver" ]] || return 1

  # Only care about -default flavour; -longterm and others are fine.
  case "$kver" in
    *-default*) : ;;
    *) return 1 ;;
  esac

  base="${kver%%-*}"
  major="${base%%.*}"
  minor="${base#*.}"
  minor="${minor%%.*}"

  [[ "$major" =~ ^[0-9]+$ ]] || return 1
  [[ "$minor" =~ ^[0-9]+$ ]] || return 1

  if (( major > min_major )); then
    return 0
  fi
  if (( major == min_major && minor >= min_minor )); then
    return 0
  fi
  return 1
}

detect_bootloader() {
  # 1) Check if systemd-boot is the ACTIVE bootloader (via bootctl)
  # This fixes setups (like openSUSE) where /etc/default/grub exists but isn't used.
  if command -v bootctl >/dev/null 2>&1; then
    # bootctl status prints "Product: systemd-boot" if active
    if bootctl status 2>/dev/null | grep -qi "systemd-boot"; then
      echo "systemd-boot"
      return 0
    fi
  fi

  # 2) openSUSE GRUB2-BLS: uses Boot Loader Spec entries + /etc/kernel/cmdline
  # even though /etc/default/grub may still exist. We detect this explicitly so
  # we DO NOT treat it as classic GRUB (which would incorrectly edit
  # /etc/default/grub and be ignored at boot).
  if is_opensuse_like && [[ -r /etc/sysconfig/bootloader ]]; then
    if grep -qi 'LOADER_TYPE=.*grub2-bls' /etc/sysconfig/bootloader 2>/dev/null; then
      echo "grub2-bls"
      return 0
    fi
  fi
  # Many openSUSE Tumbleweed systems use BLS while still declaring
  # LOADER_TYPE="grub2-efi" in /etc/sysconfig/bootloader, with BLS
  # actually enabled via GRUB_ENABLE_BLSCFG="true" in /etc/default/grub.
  # Detect that configuration as grub2-bls as well so we follow the
  # /etc/kernel/cmdline + sdbootutil path instead of legacy GRUB.
  if is_opensuse_like && [[ -f /etc/default/grub ]]; then
    # Many setups enable BLS via GRUB_ENABLE_BLSCFG="true" (or similar).
    if grep -qi 'GRUB_ENABLE_BLSCFG=.*true' /etc/default/grub 2>/dev/null; then
      echo "grub2-bls"
      return 0
    fi
  fi

  # 3) Fallback: Check for systemd-boot-style config directories directly
  if [[ -d /boot/loader/entries || -d /efi/loader/entries || -d /boot/efi/loader/entries ]]; then
    # If standard grub dirs are missing, it's definitely systemd-boot
    if [[ ! -d /boot/grub && ! -d /boot/grub2 ]]; then
      echo "systemd-boot"
      return 0
    fi
  fi
  
  # 4) Classic GRUB with /etc/default/grub present (most distros)
  if [[ -f /etc/default/grub ]]; then
    echo "grub"
    return 0
  fi

  # 5) GRUB installed but config missing
  if [[ -d /boot/grub || -d /boot/grub2 ]]; then
    echo "grub"
    return 0
  fi

  # 6) rEFInd
  if [[ -f /boot/refind_linux.conf || -f /efi/EFI/refind/refind.conf || -f /boot/efi/EFI/refind/refind.conf ]]; then
    echo "refind"
    return 0
  fi

  echo "unknown"
}

# Return 0 if this looks like an openSUSE-like system (used to gate /etc/kernel/cmdline edits).
is_opensuse_like() {
  if [[ -r /etc/os-release ]]; then
    # Match ID=opensuse* or ID_LIKE containing opensuse
    if grep -qiE '^ID=.?opensuse' /etc/os-release || \
       grep -qiE '^ID_LIKE=.*opensuse' /etc/os-release; then
      return 0
    fi
  fi
  return 1
}

# Locate the systemd-boot / BLS entries directory (if any).
systemd_boot_entries_dir() {
  local d
  for d in /boot/efi/loader/entries /boot/loader/entries /efi/loader/entries; do
    if [[ -d "$d" ]]; then
      echo "$d"
      return 0
    fi
  done
  return 1
}

# On openSUSE systems that use Boot Loader Spec (systemd-boot or grub2-bls),
# kernel parameters are persisted via /etc/kernel/cmdline and propagated to
# loader entries using sdbootutil. This helper wraps that propagation so we
# don't rely on editing individual *.conf files by hand.
opensuse_sdbootutil_update_all_entries() {
  if ! is_opensuse_like; then
    return 0
  fi
  if ! have_cmd sdbootutil; then
    return 0
  fi
  say "Updating Boot Loader Spec entries via: sdbootutil add-all-kernels && sdbootutil update-all-entries (errors will be ignored by this helper)"
  # Call sdbootutil directly and silence its stdout/stderr to avoid leaking
  # internal sed errors or similar implementation details to the user.
  # We try add-all-kernels first (to ensure all installed kernels have
  # BLS entries) and then update-all-entries to sync options/initrds.
  # If either fails, we only emit a soft note instead of aborting.
  if sdbootutil add-all-kernels >/dev/null 2>&1 && \
     sdbootutil update-all-entries >/dev/null 2>&1; then
    return 0
  fi
  note "sdbootutil add-all-kernels/update-all-entries reported an error; BLS entries may still reference older parameters or initrds."
  return 0
}

# Safely rewrite the options line for a single systemd-boot entry.
systemd_boot_write_options() {
  local entry="$1" new_opts="$2"
  [[ -f "$entry" ]] || die "systemd-boot entry not found: $entry"

  backup_file "$entry"

  # Preserve original mode/owner/group.
  local mode owner group
  mode="$(stat -c '%a' "$entry")"
  owner="$(stat -c '%u' "$entry")"
  group="$(stat -c '%g' "$entry")"

  local tmp
  tmp="$(mktemp)"
  local done=0 line
  while IFS= read -r line || [[ -n "$line" ]]; do
    if (( ! done )) && [[ "$line" =~ ^options[[:space:]]+ ]]; then
      printf 'options %s\n' "$(trim "$new_opts")" >>"$tmp"
      done=1
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$entry"

  if (( ! done )); then
    printf 'options %s\n' "$(trim "$new_opts")" >>"$tmp"
  fi

  if (( DRY_RUN )); then
    rm -f "$tmp" || true
    return 0
  fi

  install -o "$owner" -g "$group" -m "$mode" "$tmp" "$entry"
  rm -f "$tmp" || true
}

systemd_boot_add_kernel_params() {
  local dir
  # Track whether the user chose verbose boot so we can apply it both to
  # /etc/kernel/cmdline (persistence) and the current boot entry options.
  local verbose_persist=0
  dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
  if [[ -z "$dir" ]]; then
    note "systemd-boot detected but no loader entries directory could be found."
    print_manual_iommu_instructions
    return 0
  fi

  # --- openSUSE / sdbootutil persistence layer ---
  # openSUSE (Tumbleweed / MicroOS / Leap with BLS) uses /etc/kernel/cmdline
  # to generate Boot Loader Spec entries. We must edit this file AND rely on
  # sdbootutil to regenerate the per-kernel entry .conf files.
  if is_opensuse_like && [[ -f /etc/kernel/cmdline ]]; then
    hdr "openSUSE Persistence Check"
    note "Detected /etc/kernel/cmdline on an openSUSE-like system. This is used to generate boot entries (GRUB2-BLS / systemd-boot)."
    
    local cmdline_content
    cmdline_content="$(cat /etc/kernel/cmdline)"
    local -a params_to_add=("$(cpu_iommu_param)" "iommu=pt" "video=efifb:off" "video=vesafb:off" "initcall_blacklist=sysfb_init" ${GRUB_EXTRA_PARAMS:-})
    # If we know the exact vfio-pci.ids value for the selected guest GPU,
    # persist it into /etc/kernel/cmdline as well.
    if [[ -n "${CTX[guest_vfio_ids]:-}" ]]; then
      params_to_add+=("vfio-pci.ids=${CTX[guest_vfio_ids]}")
    fi
    local new_cmdline="$cmdline_content"
    
    local p
    for p in "${params_to_add[@]}"; do
      new_cmdline="$(add_param_once "$new_cmdline" "$p")"
    done

    # Optional: disable SELinux/AppArmor at the kernel level.
    # On openSUSE Tumbleweed with Btrfs rollbacks, enabling SELinux
    # or AppArmor on a rolled-back root can easily cause confusing
    # boot failures (desktop spin+reboot, services denied writes on
    # read-only or mislabelled subvolumes, etc.). This helper is
    # not LSM-policy aware, so the safest default for passthrough
    # debugging is to turn those off via selinux=0 apparmor=0.
    say
    hdr "Kernel security modules (SELinux/AppArmor)"
    note "On openSUSE Tumbleweed with snapshot rollbacks, SELinux or AppArmor on the rolled-back root can cause subtle boot issues."
    note "Examples: desktop spinning then rebooting, services failing because /etc or /var look read-only or mislabelled after rollback."
    note "This helper does not manage SELinux/AppArmor policy. For predictable VFIO testing it is safest to disable them via kernel params."
    if prompt_yn "Disable SELinux and AppArmor in kernel parameters (add selinux=0 apparmor=0 and remove security=selinux/apparmor)?" Y "Kernel security modules"; then
      new_cmdline="$(remove_param_all "$new_cmdline" "security=selinux")"
      new_cmdline="$(remove_param_all "$new_cmdline" "security=apparmor")"
      new_cmdline="$(remove_param_all "$new_cmdline" "selinux=1")"
      new_cmdline="$(remove_param_all "$new_cmdline" "apparmor=1")"
      new_cmdline="$(add_param_once "$new_cmdline" "selinux=0")"
      new_cmdline="$(add_param_once "$new_cmdline" "apparmor=0")"
    else
      note "Keeping existing SELinux/AppArmor kernel parameters as-is. If you see spin+reboot or permission errors after rollback, consider rerunning with this option."
    fi
    
    # On openSUSE with dracut, rd.driver.pre=vfio-pci is effectively
    # required for reliable GPU binding because the graphics driver is
    # pulled in very early from the initramfs. Treat it as strongly
    # recommended here (default YES) instead of a hidden "advanced" knob.
    # However, if the vfio-pci module is not present for this kernel,
    # forcing rd.driver.pre=vfio-pci would just cause dracut to fail a
    # modprobe very early in boot, so we skip it in that case.
    if command -v dracut >/dev/null 2>&1 && vfio_pci_available; then
      say
      hdr "Initramfs early VFIO driver (recommended on openSUSE)"
      note "On openSUSE (dracut-based), rd.driver.pre=vfio-pci helps vfio-pci claim the guest GPU before amdgpu/nvidia/i915 inside the initramfs."
      note "Skipping this can lead to boot loops or the GPU being grabbed by the host before VFIO." 
      if prompt_yn "Add rd.driver.pre=vfio-pci to /etc/kernel/cmdline? (recommended)" Y "Initramfs (openSUSE)"; then
        new_cmdline="$(add_param_once "$new_cmdline" "rd.driver.pre=vfio-pci")"
        CTX[rd_driver_pre]=1
      else
        note "You chose to skip rd.driver.pre=vfio-pci; passthrough may fail if the initramfs grabs the GPU first."
      fi
    elif command -v dracut >/dev/null 2>&1; then
      note "Skipping rd.driver.pre=vfio-pci because vfio-pci module is not available for this kernel."
    fi
    
    # Optional: disable quiet/splash and show verbose boot logs while
    # testing VFIO, just like we do for GRUB. This affects all future
    # entries generated from /etc/kernel/cmdline.
    say
    hdr "Boot verbosity (persistence)"
    note "While you are testing VFIO passthrough it is often useful to see full boot logs instead of a silent splash screen."
    note "This option will remove 'quiet' and 'splash=silent' from the kernel cmdline and add 'systemd.show_status=1 loglevel=7'."
    note "This automatically removes quiet and splash=silent and adds loglevel=7 for you when installing."
    if prompt_yn "Disable boot splash / quiet and enable detailed text logs on boot?" Y "Boot verbosity (persistence)"; then
      new_cmdline="$(remove_param_all "$new_cmdline" "quiet")"
      new_cmdline="$(remove_param_all "$new_cmdline" "splash=silent")"
      new_cmdline="$(add_param_once "$new_cmdline" "systemd.show_status=1")"
      new_cmdline="$(add_param_once "$new_cmdline" "loglevel=7")"
      verbose_persist=1
    fi

    # Optional: boot into multi-user.target (text mode) for VFIO debugging.
    # This replaces the default graphical target with a console-only
    # environment so that failures in the desktop stack cannot immediately
    # trigger a reboot loop. You can later remove this by running the
    # script with --reset or manually deleting systemd.unit=multi-user.target
    # from /etc/kernel/cmdline.
  say
  hdr "Boot target (persistence, optional)"
  note "By default your system boots to the graphical desktop (graphical.target)."
  note "If your VFIO setup causes the desktop or display manager to crash/reboot, you can instead boot to text mode (multi-user.target)."
  note "In text mode, the system stops at a console login so you can inspect logs and fix things before starting the desktop manually."
  if prompt_yn "Change the DEFAULT boot to multi-user.target (text mode) until you switch it back?" N "Boot target (persistence)"; then
    new_cmdline="$(add_param_once "$new_cmdline" "systemd.unit=multi-user.target")"
  fi
    
    # ACS Override check for cmdline file
    if prompt_yn "Enable ACS override in /etc/kernel/cmdline (persistence)?" N "Boot options (persistence)"; then
      new_cmdline="$(add_param_once "$new_cmdline" "pcie_acs_override=downstream,multifunction")"
    fi

    if [[ "$(trim "$new_cmdline")" != "$(trim "$cmdline_content")" ]]; then
      backup_file "/etc/kernel/cmdline"
      if (( DRY_RUN )); then
        : # do nothing in dry-run
      else
        printf '%s
' "$new_cmdline" > /etc/kernel/cmdline
      fi
      say "Updated /etc/kernel/cmdline for persistence."
      # NOTE: We defer sdbootutil add-all-kernels/update-all-entries
      # until AFTER a successful initramfs rebuild at the end of
      # apply_configuration() to avoid a window where the bootloader
      # demands rd.driver.pre= without the driver being present in the
      # initramfs.
    else
      say "/etc/kernel/cmdline already contains VFIO/IOMMU params."
    fi

    # On openSUSE we intentionally STOP here and do not run the
    # generic systemd-boot .conf editing logic below. sdbootutil
    # owns /boot/loader/entries/*.conf; we only manipulate
    # /etc/kernel/cmdline and let sdbootutil regenerate entries.
    return 0
  fi
  # -----------------------------------------------

  # Continue with standard logic to update the CURRENT entry immediately
  local -a entries=()
  local f
  shopt -s nullglob
  for f in "$dir"/*.conf; do
    entries+=("$f")
  done
  shopt -u nullglob

  if (( ${#entries[@]} == 0 )); then
    note "No systemd-boot entry files (*.conf) found under $dir."
    print_manual_iommu_instructions
    return 0
  fi

  local -a opts_list=()
  local i title current_opts

  # Try to auto-detect the currently booted entry by matching root= and
  # rootflags= from /proc/cmdline against each entry's options line.
  local running_cmdline running_root running_rootflags
  local entry_root entry_rootflags
  local auto_idx=""

  running_cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
  if [[ -n "$running_cmdline" ]]; then
    running_root="$(sed -n 's/.*\<root=\([^ ]*\).*/\1/p' <<<"$running_cmdline")"
    # Use extended regex to handle optional quotes around rootflags value
    running_rootflags="$(sed -nE 's/.*rootflags="?([^ "]+)"?.*/\1/p' <<<"$running_cmdline")"
  fi

  for i in "${!entries[@]}"; do
    f="${entries[$i]}"
    title="$(grep -m1 -E '^title[[:space:]]+' "$f" 2>/dev/null | sed -E 's/^title[[:space:]]+//')"
    title="${title:-$(basename "$f")}"
    current_opts="$(grep -m1 -E '^options[[:space:]]+' "$f" 2>/dev/null | sed -E 's/^options[[:space:]]+//')"
    current_opts="$(trim "${current_opts:-<none>}")"
    opts_list+=("$title"$'\n'"  file: $(basename "$f")"$'\n'"  options: $current_opts")

    if [[ -n "$running_root" && -n "$running_rootflags" && "$current_opts" != "<none>" ]]; then
      entry_root="$(sed -n 's/.*\<root=\([^ ]*\).*/\1/p' <<<"$current_opts")"
      # Use extended regex to handle optional quotes around rootflags value
      entry_rootflags="$(sed -nE 's/.*rootflags="?([^ "]+)"?.*/\1/p' <<<"$current_opts")"
      # CHECK: Does this entry actually match the running kernel version?
      # We grep the file for the current kernel version (e.g. "6.18.7-1-default").
      local running_kernel
      running_kernel="$(uname -r)"

      if [[ -n "$entry_root" && -n "$entry_rootflags" && \
            "$entry_root" == "$running_root" && "$entry_rootflags" == "$running_rootflags" ]]; then
        # logical_match: 1 if the file contains the kernel version string, 0 otherwise
        local logical_match=0
        if grep -Fq "$running_kernel" "$f"; then
          logical_match=1
        fi

        # If we match root flags AND kernel version, this is definitely our guy.
        if (( logical_match )); then
          auto_idx="$i"
        fi
      fi
    fi
  done

  hdr "Current Boot Entry Update"
  note "This will edit the selected systemd-boot entry in-place for the CURRENT kernel."

  local idx entry_path
  if [[ -n "$auto_idx" ]]; then
    entry_path="${entries[$auto_idx]}"
    note "Auto-detected current boot entry: $(basename "$entry_path")"
  else
    idx="$(select_from_list "Select the systemd-boot entry to modify:" "Boot entry selection" "${opts_list[@]}")"
    entry_path="${entries[$idx]}"
  fi

  current_opts="$(grep -m1 -E '^options[[:space:]]+' "$entry_path" 2>/dev/null | sed -E 's/^options[[:space:]]+//')"
  current_opts="$(trim "${current_opts:-}")"

  local -a params_to_add=("$(cpu_iommu_param)" "iommu=pt" ${GRUB_EXTRA_PARAMS:-})
  # Mirror vfio-pci.ids for the selected guest GPU into the live entry as
  # well so the current kernel uses the same binding.
  if [[ -n "${CTX[guest_vfio_ids]:-}" ]]; then
    params_to_add+=("vfio-pci.ids=${CTX[guest_vfio_ids]}")
  fi
  local new_opts="$current_opts"
  for p in "${params_to_add[@]}"; do
    new_opts="$(add_param_once "$new_opts" "$p")"
  done
  
  # If the user chose verbose boot in the persistence step, mirror that
  # here so the CURRENT entry immediately shows logs instead of splash.
  if (( verbose_persist )); then
    new_opts="$(remove_param_all "$new_opts" "quiet")"
    new_opts="$(remove_param_all "$new_opts" "splash=silent")"
    new_opts="$(add_param_once "$new_opts" "systemd.show_status=1")"
    new_opts="$(add_param_once "$new_opts" "loglevel=7")"
  fi
  
  say
  hdr "Advanced (optional): ACS override (systemd-boot)"
  if prompt_yn "Enable ACS override (pcie_acs_override=downstream,multifunction) in this entry?" N "Boot options (systemd-boot)"; then
    new_opts="$(add_param_once "$new_opts" "pcie_acs_override=downstream,multifunction")"
  fi

  if [[ "$(trim "$new_opts")" == "$(trim "$current_opts")" ]]; then
    say "systemd-boot entry options unchanged (params already present)."
    return 0
  fi

  systemd_boot_write_options "$entry_path" "$new_opts"
  say "Updated systemd-boot entry: $entry_path"
}

print_manual_iommu_instructions() {
  local param bl
  param="$(cpu_iommu_param)"
  bl="$(detect_bootloader)"
  if [[ "$bl" != "grub" && "$bl" != "systemd-boot" && "$bl" != "grub2-bls" ]]; then
    say "Detected boot loader: $bl"
  fi
  say "Automatic kernel parameter editing is implemented for GRUB, GRUB2-BLS and systemd-boot on systemd-based systems."
  say "Other boot loaders (for example rEFInd or custom UEFI stubs) are NOT auto-edited by this script."
  say "If you use one of those, you must edit your kernel parameters manually. Add these parameters and then reboot:"
  say "  $param iommu=pt"
  say "Advanced (usually NOT recommended): pcie_acs_override=downstream,multifunction"
  say "  - Only consider this if your IOMMU groups are not isolated."
  say "  - It can reduce PCIe isolation and may cause instability on some systems."
}

grub_add_kernel_params() {
  # Merge standard params with any discovered extras (for example video=efifb:off).
  local -a params_to_add=("$(cpu_iommu_param)" "iommu=pt" "video=efifb:off" "video=vesafb:off" "initcall_blacklist=sysfb_init" ${GRUB_EXTRA_PARAMS:-})
  # If we know vfio-pci.ids for the selected guest GPU, also place it on
  # the GRUB cmdline so vfio-pci can bind in the initramfs.
  if [[ -n "${CTX[guest_vfio_ids]:-}" ]]; then
    params_to_add+=("vfio-pci.ids=${CTX[guest_vfio_ids]}")
  fi

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

  # Optional: disable SELinux/AppArmor on GRUB-based systems as
  # well to match the openSUSE BLS path.
  say
  hdr "Kernel security modules (SELinux/AppArmor)"
  note "On systems that use Btrfs rollbacks (like openSUSE), SELinux/AppArmor combined with an older root snapshot can cause boot issues."
  note "This helper focuses on VFIO and does not manage LSM policy, so for stable passthrough testing it is often safest to turn them off."
  if prompt_yn "Disable SELinux and AppArmor in GRUB kernel parameters (selinux=0 apparmor=0)?" Y "Kernel security modules"; then
    new="$(remove_param_all "$new" "security=selinux")"
    new="$(remove_param_all "$new" "security=apparmor")"
    new="$(remove_param_all "$new" "selinux=1")"
    new="$(remove_param_all "$new" "apparmor=1")"
    new="$(add_param_once "$new" "selinux=0")"
    new="$(add_param_once "$new" "apparmor=0")"
  else
    note "Keeping existing SELinux/AppArmor kernel parameters in GRUB. If rollbacks cause boot loops or denials, rerun and enable this option."
  fi
 
  say
  hdr "Advanced (optional): ACS override"
  note "ACS override can sometimes split up IOMMU groups on motherboards that don't expose proper isolation."
  note "This may help GPU passthrough if your guest GPU shares an IOMMU group with other devices."
  note "Downsides: weaker PCIe isolation/security and possible instability."
  note "Recommended: NO unless you know you need it."

  if prompt_yn "Enable ACS override in GRUB (pcie_acs_override=downstream,multifunction)?" N "Boot options (GRUB)"; then
    new="$(add_param_once "$new" "pcie_acs_override=downstream,multifunction")"
  fi

  # Optional: disable quiet/splash and show verbose boot logs while testing VFIO.
  say
  hdr "Boot verbosity (optional)"
  note "While you are testing VFIO passthrough it is often useful to see full boot logs instead of a silent splash screen."
  note "This option will remove 'quiet' and 'splash=silent' from the kernel cmdline and add 'systemd.show_status=1 loglevel=7'."
  note "This automatically removes quiet and splash=silent and adds loglevel=7 for you when installing."
  note "You can later revert this by running the script with --reset or manually editing /etc/default/grub."
  if prompt_yn "Disable boot splash / quiet and enable detailed text logs on boot?" Y "Boot verbosity"; then
    new="$(remove_param_all "$new" "quiet")"
    new="$(remove_param_all "$new" "splash=silent")"
    new="$(add_param_once "$new" "systemd.show_status=1")"
    new="$(add_param_once "$new" "loglevel=7")"
  fi

  # Optional: boot into multi-user.target (text mode) for VFIO debugging.
  # This replaces the default graphical target with a console-only
  # environment so that failures in the desktop stack cannot immediately
  # trigger a reboot loop. You can later remove this by running the
  # script with --reset or manually deleting systemd.unit=multi-user.target
  # from your GRUB kernel cmdline.
  say
  hdr "Boot target (optional)"
  note "Normally your system boots straight into the graphical desktop (graphical.target)."
  note "If VFIO makes the desktop or display manager unstable, you can boot to text mode instead (multi-user.target)."
  note "In text mode, you'll land at a console login first and can start the desktop manually after checking logs (for example with journalctl -b)."
  if prompt_yn "Change the DEFAULT boot to multi-user.target (text mode) until you switch it back?" N "Boot target"; then
    new="$(add_param_once "$new" "systemd.unit=multi-user.target")"
  fi

  # Dracut-specific early driver ordering (advanced)
  # On dracut-based systems, you can ask dracut to preload vfio-pci before
  # other drivers via rd.driver.pre=vfio-pci. This can help vfio-pci "win"
  # the race against amdgpu/nvidia/i915 when those are pulled into the
  # initramfs. It is still optional because misconfiguration can affect
  # boot if your host depends on those drivers very early.
  if command -v dracut >/dev/null 2>&1 && vfio_pci_available; then
    say
    # On openSUSE (dracut-based), rd.driver.pre=vfio-pci is strongly
    # recommended; elsewhere we keep it as an advanced optional setting.
    if is_opensuse_like; then
      say
      hdr "Initramfs early VFIO driver (recommended on openSUSE)"
      note "On openSUSE with dracut, rd.driver.pre=vfio-pci helps vfio-pci claim the guest GPU before amdgpu/nvidia/i915 in the initramfs."
      note "Skipping this can cause the host driver to grab the GPU first and break passthrough."
      if prompt_yn "Add rd.driver.pre=vfio-pci to the kernel cmdline? (recommended)" Y "Boot options (dracut/openSUSE)"; then
        new="$(add_param_once "$new" "rd.driver.pre=vfio-pci")"
        CTX[rd_driver_pre]=1
      else
        note "You chose to skip rd.driver.pre=vfio-pci; passthrough may fail if the initramfs grabs the GPU first."
      fi
    else
      hdr "Advanced (optional): rd.driver.pre=vfio-pci (dracut)"
      note "On dracut-based systems this can help vfio-pci bind the guest GPU before display drivers inside the initramfs."
      note "Only enable this if you understand the implications and have a rollback/snapshot available."
      if prompt_yn "Add rd.driver.pre=vfio-pci to the kernel cmdline?" N "Boot options (dracut)"; then
        new="$(add_param_once "$new" "rd.driver.pre=vfio-pci")"
        CTX[rd_driver_pre]=1
      fi
    fi
  elif command -v dracut >/dev/null 2>&1; then
    note "Skipping rd.driver.pre=vfio-pci because vfio-pci module is not available for this kernel."
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
  # Prefer a transparent, verbose path on openSUSE/dracut systems so you
  # can clearly see when dracut is being invoked, while still keeping
  # Boot Loader Spec / ESP in sync via sdbootutil where applicable.

  # 1. openSUSE with dracut: run dracut explicitly, then sync via sdbootutil
  #    if it is available. This guarantees visible dracut output.
  if is_opensuse_like && command -v dracut >/dev/null 2>&1; then
    say "Updating initramfs via dracut (--force) ..."
    if run dracut --force; then
      note "dracut completed; initramfs on the root filesystem is updated."
    else
      note "dracut failed even with --force. Your previous initramfs is still on disk."
      # Even if this fails, we still attempt sdbootutil below so that
      # any partially-updated images are synced as best-effort.
    fi

    if command -v sdbootutil >/dev/null 2>&1; then
      say "Syncing initramfs and boot entries via sdbootutil add-all-kernels ..."
      if run sdbootutil add-all-kernels; then
        return 0
      fi
      note "sdbootutil add-all-kernels failed. Boot entries on the ESP may still point at older initrds."
      # Fall through so we can still try generic tools if present.
    fi
    # If we got here on openSUSE with dracut, we've already made our best
    # effort and printed clear logs, so we don't re-run generic tools.
    return 0
  fi

  # 2. Standard update-initramfs (Debian/Ubuntu)
  if command -v update-initramfs >/dev/null 2>&1 && [[ -d /etc/initramfs-tools ]]; then
    say "Updating initramfs via update-initramfs -u ..."
    if run update-initramfs -u; then
      return 0
    fi
    note "update-initramfs reported an error; initramfs may not have been updated."
    return 1
  fi

  # 3. Standard mkinitcpio (Arch)
  if command -v mkinitcpio >/dev/null 2>&1; then
    say "Updating initramfs via mkinitcpio -P ..."
    if run mkinitcpio -P; then
      return 0
    fi
    note "mkinitcpio reported an error; initramfs may not have been updated."
    return 1
  fi

  # 4. Standard dracut (Fedora/RHEL/legacy systems)
  if command -v dracut >/dev/null 2>&1; then
    say "Updating initramfs via dracut (--force) ..."
    # On many dracut-based systems, overwriting an existing initramfs
    # requires --force; without it, dracut will often refuse to update
    # and silently leave the old image in place.
    if run dracut --force; then
      return 0
    fi
    note "dracut failed even with --force. Your previous initramfs is still on disk."
    return 1
  fi

  say "NOTE: No initramfs update tool detected (sdbootutil, update-initramfs, mkinitcpio, dracut). Skipping."
  return 1
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

install_udev_isolation() {
  local gpu_bdf="$1"
  local audio_csv="$2"

  local rule_file="/etc/udev/rules.d/99-vfio-isolation.rules"
  backup_file "$rule_file"

  # Base rule for the guest GPU itself.
  write_file_atomic "$rule_file" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
# Remove Guest GPU from the master seat to prevent the host desktop from grabbing it.

# GPU
ACTION=="add", SUBSYSTEM=="pci", KERNELS=="$gpu_bdf", TAG-="seat", TAG-="master-of-seat"
EOF

  # Append rules for any associated guest audio PCI functions (if provided).
  if [[ -n "$audio_csv" ]]; then
    local IFS=',' aud
    for aud in $audio_csv; do
      [[ -n "$aud" ]] || continue
      if (( DRY_RUN )); then
        continue
      fi
      printf '%s\n' "ACTION==\"add\", SUBSYSTEM==\"pci\", KERNELS==\"$aud\", TAG-=\"seat\", TAG-=\"master-of-seat\"" >>"$rule_file" || true
    done
  fi

  if have_cmd udevadm; then
    run udevadm control --reload-rules
    run udevadm trigger
  fi

  say "Installed udev isolation rules to prevent the host UI from grabbing the guest GPU (and HDMI audio, if selected)."
}

# Install a small helper that dumps the current boot's VFIO-related logs to the
# desktop of the primary user. This makes it easy to inspect what happened
# during early boot without having to remember journalctl incantations.
install_bootlog_dumper() {
  local user="${SUDO_USER:-}"
  [[ -n "$user" ]] || return 0

  local home
  home="$(getent passwd "$user" | cut -d: -f6)"
  [[ -n "$home" && -d "$home" ]] || return 0

  # Place the helper script under the user's home (on /home), so it
  # survives Btrfs root snapshot rollbacks. Only the small systemd
  # unit lives on the root filesystem.
  local bin_dir="$home/.local/bin"
  local bin="$bin_dir/vfio-dump-boot-log.sh"
  local unit="/etc/systemd/system/vfio-dump-boot-log.service"

  mkdir -p "$bin_dir"

  backup_file "$bin"
  backup_file "$unit"

  write_file_atomic "$bin" 0755 "root:root" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

USER_HOME="__VFIO_BOOT_USER_HOME__"
DESKTOP_DIR="${USER_HOME}/Desktop"

# Try to detect the current Btrfs root subvolume/snapshot from the
# kernel cmdline so logs are snapshot-aware.
CMDLINE="$(cat /proc/cmdline 2>/dev/null || true)"
SNAP_SUBVOL=""
SNAP_ID=""
if [ -n "$CMDLINE" ]; then
  SNAP_SUBVOL="$(printf '%s\n' "$CMDLINE" | sed -n 's/.*rootflags=[^ ]*subvol=\([^ ,]*\).*/\1/p')"
  if [ -n "$SNAP_SUBVOL" ]; then
    SNAP_ID="$(printf '%s\n' "$SNAP_SUBVOL" | sed -n 's#^.*/@/.snapshots/\([0-9]\+\)/snapshot.*#\1#p')"
  fi
fi

# Organize logs under a dedicated tree by date to avoid clutter and
# make it easy to browse: Desktop/vfio-boot-logs/YYYY/MM/DD/
LOG_ROOT="${DESKTOP_DIR}/vfio-boot-logs"
DATE_PATH="$(date +%Y/%m/%d)"
LOG_DIR="${LOG_ROOT}/${DATE_PATH}"
mkdir -p "${LOG_DIR}" || true

# Dump as much information as possible for the current boot, including
# early failures, kernel messages, and systemd unit errors.
TS="$(date +%H%M%S)"
OUT_CUR="${LOG_DIR}/vfio-boot-${TS}-current.log"
OUT_PREV="${LOG_DIR}/vfio-boot-${TS}-previous.log"

# Current boot log
{
  echo "# VFIO boot log dump for $(date -Is) (current boot)"
  echo "# Host: $(hostname)  Kernel: $(uname -r)"
  echo "# Root subvolume: ${SNAP_SUBVOL:-<unknown>}"
  [ -n "$SNAP_ID" ] && echo "# Snapshot ID: ${SNAP_ID}"
  echo
  echo "# Log directory: ${LOG_DIR}"
  echo
  # Full journal for this boot, no pager, with explanatory text.
  journalctl -b -x -a --no-pager || true
} >"$OUT_CUR" 2>&1 || true

# Previous boot log (if available). This is particularly useful when
# the previous boot crashed or rebooted unexpectedly; we can inspect
# it after the next successful boot.
if journalctl -b -1 >/dev/null 2>&1; then
  {
    echo "# VFIO boot log dump for $(date -Is) (previous boot)"
    echo "# Host: $(hostname)  Kernel: $(uname -r)"
    echo "# Root subvolume: ${SNAP_SUBVOL:-<unknown>}"
    [ -n "$SNAP_ID" ] && echo "# Snapshot ID (current): ${SNAP_ID}"
    echo
    echo "# Log directory: ${LOG_DIR}"
    echo
    journalctl -b -1 -x -a --no-pager || true
  } >"$OUT_PREV" 2>&1 || true
fi
EOF

  # Service: run as early as is reasonably safe, after local filesystems
  # and journald are up, but before basic.target and any display manager.
  # This follows the constraints you outlined: no default dependencies,
  # ordered right after disk mount, and ahead of graphics.
  write_file_atomic "$unit" 0644 "root:root" <<EOF
[Unit]
Description=VFIO Early Boot Log Dumper (current and previous boot)
# Disable standard dependencies so we don't wait for network, timers, etc.
DefaultDependencies=no

# START CONDITION: need local filesystems and journald so we can read the
# journal and write logs to the Desktop on /home.
After=local-fs.target systemd-journald.service

# STOP CONDITION: ensure this runs before basic system + display manager.
Before=sysinit.target basic.target display-manager.service plymouth-start.service
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=$bin

[Install]
WantedBy=multi-user.target
EOF

  # Replace placeholder with the actual user home path in the helper script.
  if [[ -n "$home" ]]; then
    if (( ! DRY_RUN )); then
      sed -i "s#__VFIO_BOOT_USER_HOME__#$home#g" "$bin" || true
    fi
  fi

  if have_cmd systemctl; then
    run systemctl daemon-reload
    run systemctl enable vfio-dump-boot-log.service || true
  fi

  note "Boot log dumper installed. It will run once each boot (after multi-user.target) and drop vfio-boot-*.log files under ${home}/Desktop/vfio-boot-logs/."
}

# Small helper to set KDE Plasma Wayland as the default SDDM session when desired.
# This is optional and only affects display-manager login, not VFIO itself.
set_plasma_wayland_default_session() {
  # Only attempt this on systems that appear to use SDDM.
  if ! command -v sddm >/dev/null 2>&1 && [[ ! -d /etc/sddm.conf.d && ! -f /etc/sddm.conf ]]; then
    return 0
  fi

  # UPDATED: Search for Plasma 6 specific session files first.
  # plasma6.desktop / plasma.desktop = Plasma 6 defaults
  # plasmawayland.desktop = Plasma 5 legacy
  local session
  for session in plasma6.desktop plasma.desktop plasmawayland.desktop org.kde.plasma.wayland.desktop; do
    if [[ -f "/usr/share/wayland-sessions/$session" ]]; then
      local sddm_dir="/etc/sddm.conf.d"
      local sddm_file="$sddm_dir/10-vfio-plasma-wayland.conf"
      mkdir -p "$sddm_dir"
      backup_file "$sddm_file"
      write_file_atomic "$sddm_file" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
# Prefer KDE Plasma (Wayland) as the default session. This improves
# compatibility with modern PipeWire-based desktops when using VFIO.
[General]
Session=$session
EOF
      say "Configured SDDM to prefer KDE Plasma Wayland session by default ($session)."
      return 0
    fi
  done

  # If we get here, no known Plasma Wayland session file was found; do nothing.
}

# ---------------- Main ----------------

verify_setup() {
  hdr "VERIFY VFIO SETUP"
  VFIO_BRIEF_REPORT=1 detect_existing_vfio_report

  [[ -f "$CONF_FILE" ]] || die "Missing $CONF_FILE (nothing to verify)."
  # shellcheck disable=SC1090
  . "$CONF_FILE"

  local ok=1

  say
  if (( ENABLE_COLOR )); then
    say "${C_CYAN}Configured devices from $CONF_FILE:${C_RESET}"
  else
    say "Configured devices from $CONF_FILE:"
  fi
  say "  Guest GPU:   ${GUEST_GPU_BDF:-<missing>}"
  say "  Guest audio: ${GUEST_AUDIO_BDFS_CSV:-<none>}"
  say "  Host audio:  ${HOST_AUDIO_BDFS_CSV:-<none>}"

  # Basic sanity
  if [[ -z "${GUEST_GPU_BDF:-}" ]]; then
    if (( ENABLE_COLOR )); then
      say "${C_RED}✖ FAIL${C_RESET}: GUEST_GPU_BDF is missing in $CONF_FILE"
    else
      say "FAIL: GUEST_GPU_BDF is missing in $CONF_FILE"
    fi
    ok=0
  else
    if [[ "$(bdf_driver_name "$GUEST_GPU_BDF")" != "vfio-pci" ]]; then
      if (( ENABLE_COLOR )); then
        say "${C_RED}✖ FAIL${C_RESET}: Guest GPU $GUEST_GPU_BDF is not bound to vfio-pci (driver: $(bdf_driver_name "$GUEST_GPU_BDF"))"
      else
        say "FAIL: Guest GPU $GUEST_GPU_BDF is not bound to vfio-pci (driver: $(bdf_driver_name "$GUEST_GPU_BDF"))"
      fi
      note "This is expected BEFORE reboot (or if the vfio bind service isn't enabled)."
      ok=0
    else
      if (( ENABLE_COLOR )); then
        say "${C_GREEN}✔ OK${C_RESET}: Guest GPU $GUEST_GPU_BDF bound to vfio-pci"
      else
        say "OK: Guest GPU $GUEST_GPU_BDF bound to vfio-pci"
      fi
    fi
  fi

  if [[ -n "${GUEST_AUDIO_BDFS_CSV:-}" ]]; then
    local IFS=','
    for dev in $GUEST_AUDIO_BDFS_CSV; do
      [[ -n "$dev" ]] || continue
      if [[ "$(bdf_driver_name "$dev")" != "vfio-pci" ]]; then
        if (( ENABLE_COLOR )); then
          say "${C_RED}✖ FAIL${C_RESET}: Guest audio $dev is not bound to vfio-pci (driver: $(bdf_driver_name "$dev"))"
        else
          say "FAIL: Guest audio $dev is not bound to vfio-pci (driver: $(bdf_driver_name "$dev"))"
        fi
        ok=0
      else
        if (( ENABLE_COLOR )); then
          say "${C_GREEN}✔ OK${C_RESET}: Guest audio $dev bound to vfio-pci"
        else
          say "OK: Guest audio $dev bound to vfio-pci"
        fi
      fi
    done
  fi

  if [[ -n "${HOST_AUDIO_BDFS_CSV:-}" ]]; then
    local host_audio="${HOST_AUDIO_BDFS_CSV%%,*}"
    if [[ "$(bdf_driver_name "$host_audio")" == "vfio-pci" ]]; then
      if (( ENABLE_COLOR )); then
        say "${C_RED}✖ FAIL${C_RESET}: Host audio $host_audio is bound to vfio-pci (should remain on host driver)"
      else
        say "FAIL: Host audio $host_audio is bound to vfio-pci (should remain on host driver)"
      fi
      ok=0
    else
      if (( ENABLE_COLOR )); then
        say "${C_GREEN}✔ OK${C_RESET}: Host audio $host_audio driver: $(bdf_driver_name "$host_audio")"
      else
        say "OK: Host audio $host_audio driver: $(bdf_driver_name "$host_audio")"
      fi
    fi
  fi

  # Check that our files/services exist (best-effort)
  say
  if [[ -f "$BIND_SCRIPT" ]]; then
    if (( ENABLE_COLOR )); then
      say "${C_GREEN}✔ OK${C_RESET}: Bind script present: $BIND_SCRIPT"
    else
      say "OK: Bind script present: $BIND_SCRIPT"
    fi
  else
    if (( ENABLE_COLOR )); then
      say "${C_YELLOW}WARN${C_RESET}: Bind script missing: $BIND_SCRIPT"
    else
      say "WARN: Bind script missing: $BIND_SCRIPT"
    fi
  fi

  if [[ -f "$SYSTEMD_UNIT" ]]; then
    if (( ENABLE_COLOR )); then
      say "${C_GREEN}✔ OK${C_RESET}: Systemd unit present: $SYSTEMD_UNIT"
    else
      say "OK: Systemd unit present: $SYSTEMD_UNIT"
    fi
    if command -v systemctl >/dev/null 2>&1; then
      local enabled active
      enabled="$(systemctl is-enabled vfio-bind-selected-gpu.service 2>/dev/null || true)"
      active="$(systemctl is-active vfio-bind-selected-gpu.service 2>/dev/null || true)"
      if (( ENABLE_COLOR )); then
        say "${C_BLUE}INFO${C_RESET}: vfio-bind-selected-gpu.service is-enabled: ${enabled:-<unknown>}"
        say "${C_BLUE}INFO${C_RESET}: vfio-bind-selected-gpu.service is-active:  ${active:-<unknown>}"
      else
        say "INFO: vfio-bind-selected-gpu.service is-enabled: ${enabled:-<unknown>}"
        say "INFO: vfio-bind-selected-gpu.service is-active:  ${active:-<unknown>}"
      fi
    fi
  else
    if (( ENABLE_COLOR )); then
      say "${C_YELLOW}WARN${C_RESET}: Systemd unit missing: $SYSTEMD_UNIT"
    else
      say "WARN: Systemd unit missing: $SYSTEMD_UNIT"
    fi
  fi

  # IOMMU sanity (best-effort)
  say
  if [[ -d /sys/kernel/iommu_groups ]]; then
    if [[ -n "${GUEST_GPU_BDF:-}" ]]; then
      local g
      g="$(iommu_group_of_bdf "$GUEST_GPU_BDF" 2>/dev/null || true)"
      if [[ -n "$g" ]]; then
        if (( ENABLE_COLOR )); then
          say "${C_GREEN}✔ OK${C_RESET}: IOMMU group exists for guest GPU ($GUEST_GPU_BDF): group $g"
        else
          say "OK: IOMMU group exists for guest GPU ($GUEST_GPU_BDF): group $g"
        fi
      else
        if (( ENABLE_COLOR )); then
          say "${C_YELLOW}WARN${C_RESET}: No IOMMU group found for guest GPU ($GUEST_GPU_BDF). IOMMU may be disabled."
        else
          say "WARN: No IOMMU group found for guest GPU ($GUEST_GPU_BDF). IOMMU may be disabled."
        fi
      fi
    fi
  else
    if (( ENABLE_COLOR )); then
      say "${C_YELLOW}WARN${C_RESET}: /sys/kernel/iommu_groups not present. IOMMU may be disabled in BIOS/kernel."
    else
      say "WARN: /sys/kernel/iommu_groups not present. IOMMU may be disabled in BIOS/kernel."
    fi
  fi

  # Kernel cmdline + bootloader sanity (if available)
  say
  if [[ -r /proc/cmdline ]]; then
    local cmd
    cmd="$(cat /proc/cmdline 2>/dev/null || true)"
    if grep -qw "iommu=pt" <<<"$cmd"; then
      if (( ENABLE_COLOR )); then
        say "${C_GREEN}✔ OK${C_RESET}: Running kernel cmdline contains iommu=pt"
      else
        say "OK: Running kernel cmdline contains iommu=pt"
      fi
    else
      if (( ENABLE_COLOR )); then
        say "${C_YELLOW}WARN${C_RESET}: Running kernel cmdline does NOT contain iommu=pt"
      else
        say "WARN: Running kernel cmdline does NOT contain iommu=pt"
      fi
    fi
  fi

  if [[ -f /etc/default/grub ]]; then
    local key current
    key="$(grub_get_key 2>/dev/null || true)"
    if [[ -n "$key" ]]; then
      current="$(grub_read_cmdline "$key" 2>/dev/null || true)"
      if grep -qw "iommu=pt" <<<"$current"; then
        if (( ENABLE_COLOR )); then
          say "${C_GREEN}✔ OK${C_RESET}: /etc/default/grub contains iommu=pt"
        else
          say "OK: /etc/default/grub contains iommu=pt"
        fi
      else
        if (( ENABLE_COLOR )); then
          say "${C_YELLOW}WARN${C_RESET}: /etc/default/grub missing iommu=pt (did you skip GRUB edit?)"
        else
          say "WARN: /etc/default/grub missing iommu=pt (did you skip GRUB edit?)"
        fi
      fi
    fi
  fi

  # On openSUSE/BLS, also check the CURRENT Boot Loader Spec entry that
  # was used to boot this kernel, so you know whether that exact entry
  # has the expected VFIO/IOMMU flags.
  if is_opensuse_like && command -v sdbootutil >/dev/null 2>&1; then
    say
    say "-- Current BLS entry (openSUSE) --"
    local running_cmdline bls_dir entry opts
    running_cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
    bls_dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
    if [[ -n "$bls_dir" && -n "$running_cmdline" ]]; then
      local running_root running_rootflags
      running_root="$(sed -n 's/.*\<root=\([^ ]*\).*/\1/p' <<<"$running_cmdline")"
      running_rootflags="$(sed -nE 's/.*rootflags="?([^ "]+)"?.*/\1/p' <<<"$running_cmdline")"
      if [[ -n "$running_root" && -n "$running_rootflags" ]]; then
        local f
        shopt -s nullglob
        for f in "$bls_dir"/*.conf; do
          opts="$(grep -m1 -E '^options[[:space:]]+' "$f" 2>/dev/null | sed -E 's/^options[[:space:]]+//')"
          opts="$(trim "${opts:-}")"
          [[ -n "$opts" ]] || continue
          local eroot eflags
          eroot="$(sed -n 's/.*\<root=\([^ ]*\).*/\1/p' <<<"$opts")"
          eflags="$(sed -nE 's/.*rootflags="?([^ "]+)"?.*/\1/p' <<<"$opts")"
          if [[ -n "$eroot" && -n "$eflags" && "$eroot" == "$running_root" && "$eflags" == "$running_rootflags" ]]; then
            say "BLS entry: $(basename "$f")"
            if grep -qwE 'amd_iommu=on|intel_iommu=on' <<<"$opts" && \
               grep -qw "iommu=pt" <<<"$opts" && \
               grep -qw "rd.driver.pre=vfio-pci" <<<"$opts"; then
              if (( ENABLE_COLOR )); then
                say "${C_GREEN}✔ OK${C_RESET}: current BLS options contain IOMMU + rd.driver.pre=vfio-pci"
              else
                say "OK: current BLS options contain IOMMU + rd.driver.pre=vfio-pci"
              fi
            else
              if (( ENABLE_COLOR )); then
                say "${C_YELLOW}WARN${C_RESET}: current BLS options are missing some of: amd_iommu/intel_iommu, iommu=pt, rd.driver.pre=vfio-pci"
              else
                say "WARN: current BLS options are missing some of: amd_iommu/intel_iommu, iommu=pt, rd.driver.pre=vfio-pci"
              fi
              say "      You may want to re-run the installer on this snapshot to update /etc/kernel/cmdline and BLS entries."
            fi
            break
          fi
        done
        shopt -u nullglob
      fi
    fi
  fi

  say
  if (( ok )); then
    if (( ENABLE_COLOR )); then
      say "${C_GREEN}✔ RESULT: PASS${C_RESET} (guest devices are on vfio-pci; host audio is not)"
    else
      say "RESULT: PASS (guest devices are on vfio-pci; host audio is not)"
    fi
    return 0
  fi
  if (( ENABLE_COLOR )); then
    say "${C_RED}✖ RESULT: FAIL${C_RESET} (see messages above)"
  else
    say "RESULT: FAIL (see messages above)"
  fi
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
    "/etc/systemd/system/vfio-dump-boot-log.service"
    "/home/${SUDO_USER:-root}/.local/bin/vfio-dump-boot-log.sh"
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

  # Disable system services (best-effort)
  if command -v systemctl >/dev/null 2>&1; then
    # Core VFIO bind unit
    run systemctl disable --now vfio-bind-selected-gpu.service 2>/dev/null || true
    # Optional boot log dumper unit
    run systemctl disable --now vfio-dump-boot-log.service 2>/dev/null || true
    run systemctl daemon-reload 2>/dev/null || true
  fi

  # Remove managed files, including the optional boot log dumper bits
  local bootlog_unit="/etc/systemd/system/vfio-dump-boot-log.service"
  local bootlog_bin="/home/${SUDO_USER:-root}/.local/bin/vfio-dump-boot-log.sh"

  run rm -f "$SYSTEMD_UNIT" "$BIND_SCRIPT" "$AUDIO_SCRIPT" \
           "$CONF_FILE" "$MODULES_LOAD" "$BLACKLIST_FILE" \
           "$bootlog_unit" "$bootlog_bin" 2>/dev/null || true

  # Remove user unit for SUDO_USER (and optionally all /home users)
  if [[ -n "${SUDO_USER:-}" ]]; then
    remove_user_audio_unit "$SUDO_USER"
  fi

  if prompt_yn "Also remove vfio-set-host-audio.service for ALL users under /home/* ?" N "Reset: user audio units"; then
    local d u
    for d in /home/*; do
      [[ -d "$d" ]] || continue
      u="$(basename "$d")"
      # Some /home entries may not correspond to real user accounts; that's OK.
      remove_user_audio_unit "$u"
    done
  fi

  local grub_changed=0

  # Detect active bootloader so we do not try to "classic GRUB"-reset on
  # systems that actually use systemd-boot/GRUB2-BLS with /etc/kernel/cmdline.
  local reset_bl
  reset_bl="$(detect_bootloader)"

  # Remove GRUB kernel parameters added by this script (classic GRUB only).
  # On GRUB2-BLS/systemd-boot setups, we instead operate on /etc/kernel/cmdline.
  if [[ "$reset_bl" == "grub" && -f /etc/default/grub ]]; then
    if prompt_yn "Also remove VFIO-related kernel params from /etc/default/grub (IOMMU, ACS override, rd.driver.pre, SELinux/AppArmor, verbosity, multi-user.target)?" Y "Reset: boot options"; then
      backup_file /etc/default/grub

      local key current new
      key="$(grub_get_key)" || die "Could not find GRUB_CMDLINE_LINUX(_DEFAULT) in /etc/default/grub"
      current="$(grub_read_cmdline "$key")"
      new="$current"

      # Core IOMMU / ACS params
      new="$(remove_param_all "$new" "amd_iommu=on")"
      new="$(remove_param_all "$new" "intel_iommu=on")"
      new="$(remove_param_all "$new" "iommu=pt")"
      new="$(remove_param_all "$new" "pcie_acs_override=downstream,multifunction")"
      # Initramfs / VFIO ordering
      new="$(remove_param_all "$new" "rd.driver.pre=vfio-pci")"
      # LSM knobs we may have added
      new="$(remove_param_all "$new" "selinux=0")"
      new="$(remove_param_all "$new" "apparmor=0")"
      # Boot verbosity and target overrides
      new="$(remove_param_all "$new" "systemd.show_status=1")"
      new="$(remove_param_all "$new" "loglevel=7")"
      new="$(remove_param_all "$new" "systemd.unit=multi-user.target")"
      # Framebuffer / sysfb related tweaks
      new="$(remove_param_all "$new" "video=efifb:off")"
      new="$(remove_param_all "$new" "video=vesafb:off")"
      new="$(remove_param_all "$new" "initcall_blacklist=sysfb_init")"

      if [[ "$(trim "$new")" != "$(trim "$current")" ]]; then
        grub_write_cmdline_in_place "$key" "$new"
        grub_changed=1
      else
        note "No matching VFIO/IOMMU-related params found in GRUB cmdline; leaving it unchanged."
      fi
    fi
  fi

  # On openSUSE-like systems using systemd-boot/sdbootutil, also offer to
  # remove VFIO/IOMMU params from /etc/kernel/cmdline so future kernel
  # entries stop inheriting them. This path is also used for GRUB2-BLS.
  if is_opensuse_like && [[ -f /etc/kernel/cmdline ]]; then
    if prompt_yn "Also remove VFIO-related kernel params from /etc/kernel/cmdline (IOMMU, ACS override, rd.driver.pre, SELinux/AppArmor, verbosity, multi-user.target)?" Y "Reset: boot options (persistence)"; then
      backup_file /etc/kernel/cmdline
      local kcur knew
      kcur="$(cat /etc/kernel/cmdline 2>/dev/null || true)"
      knew="$kcur"
      # Core IOMMU / ACS params
      knew="$(remove_param_all "$knew" "amd_iommu=on")"
      knew="$(remove_param_all "$knew" "intel_iommu=on")"
      knew="$(remove_param_all "$knew" "iommu=pt")"
      knew="$(remove_param_all "$knew" "pcie_acs_override=downstream,multifunction")"
      # Initramfs / VFIO ordering
      knew="$(remove_param_all "$knew" "rd.driver.pre=vfio-pci")"
      # LSM knobs we may have added
      knew="$(remove_param_all "$knew" "selinux=0")"
      knew="$(remove_param_all "$knew" "apparmor=0")"
      # Boot verbosity and target overrides
      knew="$(remove_param_all "$knew" "systemd.show_status=1")"
      knew="$(remove_param_all "$knew" "loglevel=7")"
      knew="$(remove_param_all "$knew" "systemd.unit=multi-user.target")"
      # Framebuffer / sysfb related tweaks
      knew="$(remove_param_all "$knew" "video=efifb:off")"
      knew="$(remove_param_all "$knew" "video=vesafb:off")"
      knew="$(remove_param_all "$knew" "initcall_blacklist=sysfb_init")"

      if [[ "$(trim "$knew")" != "$(trim "$kcur")" ]]; then
        if (( ! DRY_RUN )); then
          printf '%s
' "$knew" >/etc/kernel/cmdline
        fi
        # Ensure BLS/systemd-boot entries are regenerated without these
        # params on openSUSE.
        opensuse_sdbootutil_update_all_entries
      else
        note "No matching VFIO/IOMMU-related params found in /etc/kernel/cmdline; leaving it unchanged."
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

    # After regenerating grub.cfg, run a best-effort syntax check. If GRUB
    # reports a syntax error, we automatically roll back /etc/default/grub
    # to the backup from this run (if present) and regenerate grub.cfg a
    # second time so the user does not get stuck with a broken boot menu.
    if ! maybe_check_grub_cfg; then
      local bak="/etc/default/grub.bak.${RUN_TS}"
      if [[ -f "$bak" ]]; then
        note "GRUB syntax check failed; restoring previous /etc/default/grub from $bak and regenerating grub.cfg."
        cp -a "$bak" /etc/default/grub || true
        if command -v update-grub >/dev/null 2>&1; then
          say "Re-running update-grub after restoring backup..."
          run update-grub || true
        elif command -v grub-mkconfig >/dev/null 2>&1; then
          local out2=""
          if [[ -d /boot/grub ]]; then
            out2=/boot/grub/grub.cfg
          elif [[ -d /boot/grub2 ]]; then
            out2=/boot/grub2/grub.cfg
          fi
          [[ -n "$out2" ]] && { say "Re-running grub-mkconfig -o $out2 after restoring backup..."; run grub-mkconfig -o "$out2" || true; }
        elif command -v grub2-mkconfig >/dev/null 2>&1; then
          local out3=""
          if [[ -d /boot/grub2 ]]; then
            out3=/boot/grub2/grub.cfg
          elif [[ -d /boot/grub ]]; then
            out3=/boot/grub/grub.cfg
          fi
          [[ -n "$out3" ]] && { say "Re-running grub2-mkconfig -o $out3 after restoring backup..."; run grub2-mkconfig -o "$out3" || true; }
        fi
      else
        note "GRUB syntax check failed but no backup /etc/default/grub.bak.${RUN_TS} was found; please review /etc/default/grub manually."
      fi
    fi
  fi

  # Always rebuild initramfs at end of reset (so removed blacklists/modules are fully gone on next boot).
  say
  say "Rebuilding initramfs (recommended after reset)..."
  maybe_update_initramfs

  say
  say "Reset complete. Reboot recommended."
  note "If any devices are currently bound to vfio-pci, a reboot is the cleanest way to restore host drivers."

  # Snapshot-aware hint for openSUSE/Btrfs users: each snapshot has its own
  # /etc/kernel/cmdline. If you later roll back to an older snapshot that
  # still contains VFIO-related kernel params, you should run this reset
  # helper again from within that snapshot if you also want it cleaned.
  if is_opensuse_like && [[ -d /.snapshots ]]; then
    note "On Btrfs snapshots, each snapshot keeps its own /etc/kernel/cmdline."
    note "If you roll back to an older snapshot later, run 'sudo sh vfio.sh --reset' again inside that snapshot to clean its VFIO kernel params too."
  fi
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
      if prompt_yn "Reset / cleanup VFIO settings now?" N "Existing VFIO config"; then
        reset_vfio_all
        exit 0
      fi

      # If user refuses reset, require explicit acknowledgement.
      if ! confirm_phrase "Continuing with a BAD config can break boot, graphics, or audio." "I UNDERSTAND"; then
        die "Aborted"
      fi
    else
      # OK/WARN: offer reset, default no, then proceed.
      if prompt_yn "Existing VFIO config detected. Do you want to RESET it before continuing?" N "Existing VFIO config"; then
        reset_vfio_all
        exit 0
      fi
      # Default is to continue to next step with no extra prompts.
      note "Continuing with existing config. (You can run: sudo bash vfio.sh --reset)"
    fi
  fi
}

detect_system() {
  # Detect and record core environment capabilities into CTX.
  CTX[bootloader]="$(detect_bootloader)"

  # For install mode, require IOMMU to be active before continuing.
  iommu_enabled_or_die

  say
  hdr "Environment support"
  note "Init system: systemd (required; other init systems are NOT supported by this helper)."
  note "Boot loader detected: ${CTX[bootloader]}"
  if [[ "${CTX[bootloader]}" == "grub" || "${CTX[bootloader]}" == "systemd-boot" || "${CTX[bootloader]}" == "grub2-bls" ]]; then
    note "Automatic kernel parameter editing is available for ${CTX[bootloader]}."
  else
    note "Automatic kernel parameter editing is ONLY implemented for GRUB and systemd-boot. For ${CTX[bootloader]}, you must apply kernel parameters manually when prompted."
  fi

  # On openSUSE, warn if we are running a very new default kernel that is
  # known to cause VFIO binding problems for some AMD GPUs, and suggest
  # using kernel-longterm instead when available.
  if is_opensuse_like && opensuse_default_kernel_is_at_least 6 13; then
    say
    hdr "Kernel compatibility (openSUSE default kernel vs. VFIO)"
    note "The running kernel ($(uname -r)) is a very new *-default build (>= 6.13)."
    note "On some systems this default kernel lets amdgpu claim the guest GPU even when vfio-pci.ids and rd.driver.pre=vfio-pci are set."
    if rpm -q kernel-longterm >/dev/null 2>&1; then
      note "The 'kernel-longterm' package is installed. For VFIO you may get more reliable binding by booting the -longterm kernel instead of the default one."
    else
      note "If you see VFIO binding failures on this kernel, consider installing 'kernel-longterm' and testing VFIO there."
    fi
  fi

  # Early detection of existing passthrough config (before user makes changes).
  preflight_existing_config_gate
}

user_selection() {
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
    local bdf slot vend short
    bdf="${gpu_bdfs[$i]}"
    slot="$(pci_slot_of_bdf "$bdf")"
    vend="$(vendor_label "${gpu_vendor_ids[$i]}")"
    short="$(short_gpu_desc "${gpu_descs[$i]}")"
    options+=("GPU: $bdf  |  Vendor: ${vend}"$'\n'"      Model: ${short}"$'\n'"      PCI slot: ${slot}")
  done

  local guest_idx host_idx
  hdr "Step 1/4: Select GUEST GPU (will be passed through)"
  guest_idx="$(select_from_list "Which GPU should be the GUEST (vfio-pci / passthrough)?" "GPU selection" "${options[@]}")"

  if (( ${#gpu_bdfs[@]} == 2 )); then
    if (( guest_idx == 0 )); then host_idx=1; else host_idx=0; fi
  else
    host_idx="$(select_from_list "Select the GPU to use for HOST display:" "Host GPU selection" "${options[@]}")"
    (( host_idx != guest_idx )) || die "Host GPU and guest GPU cannot be the same."
  fi

  CTX[guest_gpu]="${gpu_bdfs[$guest_idx]}"
  CTX[host_gpu]="${gpu_bdfs[$host_idx]}"
  CTX[guest_vendor]="${gpu_vendor_ids[$guest_idx]}"

  # Track the exact vendor:device ID for the selected guest GPU so we can
  # expose a matching vfio-pci.ids= parameter in the kernel cmdline. This
  # makes sure vfio-pci claims the card as early as possible (initramfs),
  # which is required on some systems (including openSUSE+dracut) to avoid
  # races with amdgpu/nvidia/i915.
  local _guest_vid _guest_did
  _guest_vid="$(sysfs_read "${CTX[guest_gpu]}" vendor)"
  _guest_did="$(sysfs_read "${CTX[guest_gpu]}" device)"
  if [[ -n "$_guest_vid" && -n "$_guest_did" ]]; then
    CTX[guest_vfio_ids]="${_guest_vid}:${_guest_did}"
  fi

  local guest_desc host_desc
  guest_desc="${gpu_descs[$guest_idx]}"
  host_desc="${gpu_descs[$host_idx]}"

  say
  hdr "Selection summary so far"
  say "Host GPU (stays on host):"
  say "  ${CTX[host_gpu]}"
  note "  $(short_gpu_desc "$host_desc")"
  say "Guest GPU (passthrough / vfio-pci):"
  say "  ${CTX[guest_gpu]}"
  note "  $(short_gpu_desc "$guest_desc")"

  assert_not_equal "${CTX[guest_gpu]}" "${CTX[host_gpu]}" "Host GPU and guest GPU are the same (refusing)."
  assert_pci_bdf_exists "${CTX[guest_gpu]}"
  assert_pci_bdf_exists "${CTX[host_gpu]}"

  # Guest audio selection (default: audio functions in the same PCI slot)
  local guest_audio_csv="${gpu_audio_bdfs_csv[$guest_idx]}"
  if [[ -n "$guest_audio_csv" ]]; then
    say
    hdr "Step 2/4: Guest GPU HDMI/DP Audio (strongly recommended)"
    say "Guest GPU: ${CTX[guest_gpu]}"
    note "$(short_gpu_desc "$guest_desc")"
    say "Detected HDMI/DP audio PCI function(s) for this GPU: $guest_audio_csv"
    note "On many systems (including openSUSE Tumbleweed), it is safest to passthrough BOTH the GPU video (..0) and its HDMI/DP audio (..1)."
    note "Leaving the HDMI/DP audio on the host while the GPU is passed through can confuse PipeWire/PulseAudio and cause desktop hangs when the VM starts."
    note "Only skip this if you are sure you do NOT want the GPU's HDMI/DP audio in the guest and understand the risks."

    if ! prompt_yn "Also passthrough HDMI/DP AUDIO for the guest GPU? (recommended)" Y "Guest HDMI/DP audio"; then
      guest_audio_csv=""
    fi
  else
    say
    hdr "Step 2/4: Guest GPU HDMI/DP Audio"
    note "No HDMI/DP audio device found in the same PCI slot as the selected guest GPU (${CTX[guest_gpu]})."
  fi

  # Preflight: detect if the selected guest GPU looks in-use by the host.
  gpu_in_use_preflight "${CTX[guest_gpu]}"

  # Preflight: IOMMU group gate.
  iommu_group_preflight "${CTX[guest_gpu]}" "$guest_audio_csv"

  # Check for AMD Reset Bug mitigation (vendor-reset)
  if [[ "${CTX[guest_vendor],,}" == "1002" ]]; then
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

  # If the user chose NOT to passthrough any guest HDMI/DP audio, we skip the
  # host audio binding wizard entirely to avoid extra questions. In that
  # scenario the script will not try to manage host audio PCI devices at all.
  if [[ -n "$guest_audio_csv" ]]; then
    say
    hdr "Step 3/4: Select HOST audio device (must stay on host)"
    say "Host GPU is: ${CTX[host_gpu]}"
    note "$(short_gpu_desc "$host_desc")"
    note "Pick the AUDIO device that should KEEP working on the host (for your desktop sound)."
    note "Tip: for HDMI sound from the host GPU, pick the audio device in the SAME PCI slot as the host GPU."
    note "This avoids the common AMD issue where both HDMI audio devices share the same ID (1002:ab28)."

    local host_slot
    host_slot="$(pci_slot_of_bdf "${CTX[host_gpu]}")"

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
      host_audio_idx="$(select_from_list "Which AUDIO device should stay on the HOST?" "Host audio selection" "${aud_opts[@]}")"
      host_audio_bdfs_csv="${aud_bdfs[$host_audio_idx]}"
      [[ -n "$host_audio_bdfs_csv" ]] && assert_pci_bdf_exists "$host_audio_bdfs_csv"
    else
      say "WARN: No PCI audio devices found via lspci."
      host_audio_bdfs_csv=""
    fi

    # Hard safety: host audio must never equal guest GPU.
    if [[ -n "$host_audio_bdfs_csv" ]]; then
      assert_not_equal "$host_audio_bdfs_csv" "${CTX[guest_gpu]}" "Selected host audio equals guest GPU BDF (refusing)."
    fi

    # Slot sanity: host audio should match host GPU slot unless explicitly overridden.
    audio_slot_sanity "${CTX[host_gpu]}" "$host_audio_bdfs_csv"
  else
    say
    hdr "Step 3/4: Host audio binding"
    note "You chose not to passthrough any HDMI/DP audio for the guest. Skipping host audio PCI binding wizard."
    host_audio_bdfs_csv=""
  fi

  # PipeWire default sink selection (user-session)
  local host_audio_node_name=""
  if command -v wpctl >/dev/null 2>&1; then
    # KDE Plasma users usually manage outputs via the Plasma volume applet. For
    # them we default this to NO so it behaves like an advanced helper instead
    # of a mandatory extra question.
    local sink_prompt_def="Y"
    if [[ "${XDG_CURRENT_DESKTOP:-}" =~ KDE|Plasma|PLASMA ]]; then
      sink_prompt_def="N"
    fi

    if prompt_yn "Do you want to select the DEFAULT AUDIO SINK for the host user session (KDE Plasma / PipeWire / WirePlumber)?" "$sink_prompt_def" "Host audio output"; then
      note "(Tip: this only changes your desktop's default output device in PipeWire; it does NOT affect VFIO binding or the VM.)"
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
        sink_idx="$(select_from_list "Which host audio OUTPUT should be default?" "Host audio output selection" "${sink_opts[@]}")"
        host_audio_node_name="${sink_node_names[$sink_idx]}"
      else
        note "Could not enumerate PipeWire sinks (common if PipeWire isn't running for that user yet). Skipping."
      fi
    fi
  fi

  CTX[guest_audio_csv]="$guest_audio_csv"
  CTX[host_audio_bdfs_csv]="$host_audio_bdfs_csv"
  CTX[host_audio_node_name]="$host_audio_node_name"
}

apply_configuration() {
  local guest_gpu="${CTX[guest_gpu]}"
  local host_gpu="${CTX[host_gpu]}"
  local guest_vendor="${CTX[guest_vendor]}"
  local guest_audio_csv="${CTX[guest_audio_csv]}"
  local host_audio_bdfs_csv="${CTX[host_audio_bdfs_csv]}"
  local host_audio_node_name="${CTX[host_audio_node_name]}"

  # Track whether we actually installed a dracut config for vfio modules
  # and whether we added rd.driver.pre=vfio-pci to the kernel cmdline.
  CTX[dracut_vfio]=0
  CTX[rd_driver_pre]=0

  say
  say "Summary:"
  say "  Host GPU:   $host_gpu"
  say "  Guest GPU:  $guest_gpu (vendor: $(vendor_name "$guest_vendor"))"
  say "  Host audio PCI:  ${host_audio_bdfs_csv:-<none>}"
  say "  Guest audio PCI: ${guest_audio_csv:-<none>}"
  say "  Host default sink node.name: ${host_audio_node_name:-<not set>}"
  if [[ "${XDG_CURRENT_DESKTOP:-}" =~ KDE|Plasma|PLASMA ]]; then
    note "Desktop session: KDE Plasma detected; these settings are tuned for Plasma + Wayland + PipeWire."
  fi
  say

  hdr "Apply changes"
  note "If you continue, this script will install the core VFIO binding setup:" 
  note "  - Write $CONF_FILE (your selected PCI BDFs)"
  note "  - Write $MODULES_LOAD (load vfio modules at boot)"
  note "  - Write $BIND_SCRIPT (bind ONLY the selected guest BDF(s) to vfio-pci)"
  note "  - Write + enable $SYSTEMD_UNIT (runs the bind script early at boot)"
  note "On dracut-based systems (including openSUSE), it will also install a VFIO dracut config so rd.driver.pre=vfio-pci cannot cause a boot hang."
  note "It will then ASK about remaining optional steps (GRUB/IOMMU, ACS override, host audio unit, udev isolation, etc.)."
  note "On KDE Plasma systems, it can also (optionally) set Plasma Wayland as the default SDDM session to better match these settings."
  note "Important: The VFIO binding will fully take effect AFTER a reboot."

  prompt_yn "Apply these changes now?" N "Apply VFIO configuration" || die "Aborted by user"

  # Preflight sanity checks before writing anything.
  assert_pci_bdf_exists "$host_gpu"
  assert_pci_bdf_exists "$guest_gpu"
  if [[ -n "$host_audio_bdfs_csv" ]]; then
    assert_pci_bdf_exists "$host_audio_bdfs_csv"
  fi

  # Optional: if running under KDE Plasma, offer to set Plasma Wayland as the
  # default login session for SDDM so the desktop matches these VFIO-friendly
  # settings (PipeWire, Wayland, etc.).
  if [[ "${XDG_CURRENT_DESKTOP:-}" =~ KDE|Plasma|PLASMA ]]; then
    say
    hdr "KDE Plasma session integration"
    note "KDE Plasma detected. Using Plasma Wayland as the default login session usually works best with modern PipeWire + VFIO setups."
    if prompt_yn "Set KDE Plasma Wayland as the DEFAULT SDDM login session?" N "KDE Plasma session"; then
      set_plasma_wayland_default_session
    fi
  fi
  if [[ -n "$guest_audio_csv" ]]; then
    local IFS=',' dev
    for dev in $guest_audio_csv; do
      [[ -n "$dev" ]] || continue
      assert_pci_bdf_exists "$dev"
      assert_not_equal "$dev" "$host_audio_bdfs_csv" "Guest audio BDF equals host audio BDF (refusing)."
    done
  fi

  write_conf "$host_gpu" "$host_audio_bdfs_csv" "$host_audio_node_name" "$guest_gpu" "$guest_audio_csv" "$guest_vendor"
  install_vfio_modules_load

  # Optional: on openSUSE Tumbleweed offer to install the distribution's
  # long-term kernel. In real-world testing this kernel can make VFIO
  # binding more reliable for some AMD Navi GPUs by avoiding very recent
  # amdgpu changes that aggressively claim the device even when vfio-pci
  # is requested. We only suggest this for AMD guest GPUs and when the
  # current boot still shows amdgpu as the active driver for the guest
  # BDF, and in that case we default the prompt to YES.
  maybe_offer_kernel_longterm "$guest_vendor" "$guest_gpu"

  # EXTRA (advanced, openSUSE-only): if kernel-longterm is installed,
  # offer to UNINSTALL the default kernel package so only the long-term
  # kernel remains. This is dangerous if the long-term kernel ever
  # becomes unbootable, so the default answer is NO and the prompt is
  # explicit about the risks. To avoid accidental "yes" presses, this
  # requires typing a confirmation phrase instead of a single key.
  if is_opensuse_like && rpm -q kernel-longterm >/dev/null 2>&1; then
    say
    hdr "Advanced: openSUSE default kernel removal (optional)"
    note "You are running on an openSUSE-like system and the 'kernel-longterm' package is installed."
    note "For VFIO, some users prefer to keep ONLY the long-term kernel and uninstall the default kernel package."
    if (( ENABLE_COLOR )); then
      say "${C_BOLD}${C_RED}DANGER:${C_RESET} Removing the default kernel means you will NOT have a fallback kernel if kernel-longterm ever fails to boot."
    else
      say "DANGER: Removing the default kernel means you will NOT have a fallback kernel if kernel-longterm ever fails to boot."
    fi
    note "Recommended for most users: NO (keep both kernels so you always have a rescue/fallback entry)."
    note "If you really want to uninstall the default kernel, type: REMOVE DEFAULT KERNEL"
    note "Or press ENTER to skip and keep both kernels."

    local in="/dev/stdin" out="/dev/stderr" ans
    if [[ -r /dev/tty && -w /dev/tty ]]; then
      in="/dev/tty"; out="/dev/tty"
    fi

    printf '%s' "> " >"$out"
    read -r ans <"$in" || ans=""

    if [[ "$ans" == "REMOVE DEFAULT KERNEL" ]]; then
      if have_cmd zypper; then
        say "Attempting to uninstall default kernel packages via zypper..."
        # We target the common default-kernel patterns. If some are not
        # installed, zypper will simply ignore them.
        run zypper --non-interactive rm kernel-default kernel-default-base kernel-default-extra 2>/dev/null || \
          note "zypper could not remove one or more default kernel packages automatically. You may need to adjust packages manually."
        # After changing installed kernels, refresh BLS entries if applicable.
        opensuse_sdbootutil_update_all_entries
      else
        note "zypper is not available; cannot manage kernel packages automatically."
      fi
    else
      note "Keeping both default and long-term kernels installed (safer for recovery)."
    fi
  fi

  say
  hdr "Initramfs integration"

  if command -v dracut >/dev/null 2>&1; then
    # OPENSUSE FIX: On openSUSE (dracut-based), including VFIO modules in the
    # initramfs is **mandatory** if we are going to use rd.driver.pre=vfio-pci,
    # otherwise the kernel may hang waiting for a driver that is not present
    # in the early initramfs. We therefore install the dracut config
    # unconditionally on openSUSE instead of asking.
    if is_opensuse_like; then
      say "${C_YELLOW}openSUSE detected:${C_RESET} automatically installing Dracut VFIO config."
      note "This ensures 'rd.driver.pre=vfio-pci' does not hang your boot process by requesting a driver that is missing from the initramfs."
      install_dracut_config
      CTX[dracut_vfio]=1
    else
      note "By default, VFIO modules will load from the root filesystem via $MODULES_LOAD after it is mounted."
      note "You can also pre-load them in the initramfs via dracut config; this is more invasive and can affect very early boot."

      local prompt title
      title="Initramfs integration"
      prompt="Install dracut config to include VFIO modules in the initramfs now? (advanced)"
      if prompt_yn "$prompt" N "$title"; then
        install_dracut_config
        CTX[dracut_vfio]=1
      else
        note "Skipping dracut VFIO initramfs config. You can add it later by re-running this helper."
      fi
    fi
  else
    note "dracut not detected; skipping initramfs-specific VFIO config."
  fi

  say
  hdr "Module load ordering (optional soft dependency)"
  note "To reduce race conditions where the GPU driver (amdgpu/nvidia/i915) grabs the card before vfio-pci,"
  note "you can install a softdep rule so vfio-pci is always loaded first for the guest GPU vendor."
  note "This is usually safe, but if you have unusual driver setups you may prefer to skip it."
  if prompt_yn "Install vfio-pci softdep for $(vendor_name "$guest_vendor") now?" Y "Module load ordering"; then
    install_softdep_config "$guest_vendor"
  else
    note "Skipping vfio softdep installation. You can add it later in /etc/modprobe.d/vfio-softdep.conf if needed."
  fi

  install_bind_script
  install_systemd_unit

  say
  hdr "Boot log capture (optional)"
  note "You can automatically dump the current boot's journal to a vfio-boot-*.log file on your desktop after each boot."
  note "This is mainly useful when you are actively debugging passthrough problems and want to keep per-boot logs around."
  note "On a stable setup it is usually not necessary and can create a lot of log files over time."
  if prompt_yn "Install a small helper that saves a VFIO boot log to your Desktop on every boot?" N "Boot log capture"; then
    install_bootlog_dumper
  else
    note "Skipping boot log dumper; you can always inspect logs manually with journalctl -b when needed."
  fi

  say
  hdr "Display manager / seat isolation (optional)"
  note "A udev rule can remove the guest GPU (and its HDMI audio) from the host seat so the display manager does not grab it."
  note "This is usually helpful on multi-GPU systems where the host desktop should ignore the passthrough card."
  if prompt_yn "Install udev rule to isolate the guest GPU from the host seat? (recommended)" Y "Seat isolation"; then
    install_udev_isolation "$guest_gpu" "$guest_audio_csv"
  else
    note "Skipping udev isolation; the host display manager may still see the guest GPU."
  fi

  say
  hdr "Boot configuration (IOMMU / boot loader)"
  local bl2="${CTX[bootloader]}"
  note "IOMMU must be enabled for PCI passthrough to work."
  note "Boot loader detected: ${bl2}"
  if [[ "$bl2" == "grub" ]]; then
    note "Recommended: YES (adds amd_iommu=on or intel_iommu=on + iommu=pt to GRUB)."
    note "If you answer NO, passthrough may fail unless you already configured IOMMU another way."
  elif [[ "$bl2" == "systemd-boot" || "$bl2" == "grub2-bls" ]]; then
    note "Recommended: YES (adds amd_iommu=on or intel_iommu=on + iommu=pt to the Boot Loader Spec entry and /etc/kernel/cmdline)."
    note "If you answer NO, passthrough may fail unless you already configured IOMMU another way."
  else
    note "Automatic kernel parameter editing is ONLY supported for GRUB and systemd-boot. For ${bl2}, you must add the parameters manually."
    note "If you skip the manual instructions, passthrough may fail."
  fi
  note "If you enable IOMMU, you will also be offered an optional 'ACS override' (advanced; usually NO)."

  local q
  if [[ "$bl2" == "grub" ]]; then
    q="Enable IOMMU kernel parameters in GRUB now? (recommended)"
  elif [[ "$bl2" == "systemd-boot" || "$bl2" == "grub2-bls" ]]; then
    q="Enable IOMMU kernel parameters in a Boot Loader Spec entry now? (recommended)"
  else
    q="Show recommended IOMMU kernel parameters and MANUAL instructions now? (recommended)"
  fi

  if prompt_yn "$q" Y "Boot options"; then
    if [[ "$bl2" == "grub" ]]; then
      grub_add_kernel_params
    elif [[ "$bl2" == "systemd-boot" || "$bl2" == "grub2-bls" ]]; then
      systemd_boot_add_kernel_params
    else
      print_manual_iommu_instructions
    fi
  else
    note "Skipping automatic/manual IOMMU helper. Ensure your kernel parameters enable IOMMU, or passthrough may fail."
  fi

  # Even if systemd-boot is the active loader, many openSUSE systems keep
  # GRUB installed as a fallback. As a final step, if GRUB tooling and
  # config are present, regenerate grub.cfg so any previous cmdline edits
  # (whether made by this script or manually) are reflected.
  if [[ -f /etc/default/grub ]]; then
    if command -v update-grub >/dev/null 2>&1; then
      say "(Post-install) Updating GRUB config via update-grub..."
      run update-grub || true
    elif command -v grub-mkconfig >/dev/null 2>&1; then
      local out
      if [[ -d /boot/grub ]]; then
        out=/boot/grub/grub.cfg
      elif [[ -d /boot/grub2 ]]; then
        out=/boot/grub2/grub.cfg
      else
        out=""
      fi
      [[ -n "$out" ]] && { say "(Post-install) Updating GRUB config via grub-mkconfig -o $out ..."; run grub-mkconfig -o "$out" || true; }
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
      local out
      if [[ -d /boot/grub2 ]]; then
        out=/boot/grub2/grub.cfg
      elif [[ -d /boot/grub ]]; then
        out=/boot/grub/grub.cfg
      else
        out=""
      fi
      [[ -n "$out" ]] && { say "(Post-install) Updating GRUB config via grub2-mkconfig -o $out ..."; run grub2-mkconfig -o "$out" || true; }
    fi
  fi

  # Guard against the "dracut trap": rd.driver.pre=vfio-pci on the
  # kernel cmdline without including vfio modules in the initramfs.
  if command -v dracut >/dev/null 2>&1; then
    if [[ "${CTX[rd_driver_pre]:-0}" == "1" && "${CTX[dracut_vfio]:-0}" != "1" ]]; then
      say
      hdr "Dracut / rd.driver.pre sanity check"
      note "You enabled rd.driver.pre=vfio-pci in the kernel cmdline, but did not install a dracut config to include vfio modules in the initramfs."
      note "On dracut-based systems (such as openSUSE), this mismatch can cause boot failures if the requested driver is missing from the early initramfs."
      if prompt_yn "Write dracut config to include VFIO modules in the initramfs now? (recommended)" Y "Initramfs (dracut)"; then
        install_dracut_config
        CTX[dracut_vfio]=1
      else
        note "You chose to keep rd.driver.pre=vfio-pci without adding vfio modules to the initramfs; this may break boot. Make sure you know how to recover (snapshots, rescue media)."
      fi
    fi
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
  if prompt_yn "Open advanced driver blacklist submenu for $(vendor_name "$guest_vendor") drivers?" N "Driver blacklist"; then
    if ! confirm_phrase "WARNING: Driver blacklisting is OPTIONAL and can break host graphics if misused. To continue and create $BLACKLIST_FILE, type BLACKLIST." "BLACKLIST"; then
      note "Skipping driver blacklist (confirmation failed)."
    else
      # User typed BLACKLIST; give them one last chance to cancel and proceed without any blacklist.
      if ! prompt_yn "You typed BLACKLIST. Do you still want to create a driver blacklist file now?" N "Driver blacklist"; then
        note "Skipping driver blacklist (user cancelled after confirmation)."
      else
        write_optional_blacklist "$guest_vendor" "${suggested_mods[@]}"
        maybe_update_initramfs
      fi
    fi
  else
    note "Skipping driver blacklist submenu."
  fi

  say
  hdr "Initramfs update (recommended)"
  if prompt_yn "Update initramfs now? (recommended after VFIO and/or blacklisting changes)" Y "Initramfs update"; then
    if maybe_update_initramfs; then
      # Only refresh Boot Loader Spec entries AFTER a successful
      # initramfs rebuild to keep kernel cmdline and initramfs content
      # in sync when using rd.driver.pre=vfio-pci on openSUSE.
      if is_opensuse_like; then
        say "Refreshing Boot Loader Spec entries via sdbootutil update-all-entries ..."
        opensuse_sdbootutil_update_all_entries
      fi
    else
      say "WARNING: Initramfs update failed or no tool was found. Boot loader entries were NOT refreshed via sdbootutil to avoid a broken boot configuration."
    fi
  else
    note "Skipping initramfs rebuild; remember to update it yourself before relying on VFIO settings."
  fi

  say
  if prompt_yn "Install a user systemd unit to set the host default audio sink after login?" Y "Host audio output"; then
    install_audio_script
    install_user_audio_unit
  else
    note "Skipping user systemd audio helper. You can install it later by re-running this helper."
  fi

  say
  say "Done. Next steps:"
  say "  1) Reboot."
  say "  2) Verify guest devices are bound to vfio-pci:"
  say "       lspci -nnk -s ${guest_gpu}"
  if [[ -n "$guest_audio_csv" ]]; then
    say "       lspci -nnk -s ${guest_audio_csv//,/ }"
  fi
  if [[ -n "$host_audio_bdfs_csv" ]]; then
    say "  3) Verify host audio device is NOT on vfio-pci:"
    say "       lspci -nnk -s ${host_audio_bdfs_csv%%,*}"
  fi
  say "  4) In your VM manager, passthrough the guest GPU and any selected guest audio PCI functions."
}

main() {
  parse_args "$@"

  # Core tools used across modes
  need_cmd lspci
  need_cmd sed
  need_cmd awk
  need_cmd grep
  need_cmd install
  need_cmd mktemp
  need_cmd stat

  # modprobe is only required for modes that actually manipulate
  # kernel modules / bindings. Self-test and detect should be able
  # to run in "thin" environments (containers, chroots) where
  # modprobe may be absent.
  if [[ "$MODE" != "self-test" && "$MODE" != "detect" ]]; then
    need_cmd modprobe
  fi

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

  detect_system
  user_selection
  apply_configuration
}

main "$@"
