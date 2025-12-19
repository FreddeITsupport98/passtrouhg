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

CONF_FILE="/etc/vfio-gpu-passthrough.conf"
BIND_SCRIPT="/usr/local/sbin/vfio-bind-selected-gpu.sh"
AUDIO_SCRIPT="/usr/local/bin/vfio-set-host-audio.sh"
SYSTEMD_UNIT="/etc/systemd/system/vfio-bind-selected-gpu.service"
MODULES_LOAD="/etc/modules-load.d/vfio.conf"
BLACKLIST_FILE="/etc/modprobe.d/vfio-optional-blacklist.conf"

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
C_RED="${CSI}31m"
C_GREEN="${CSI}32m"
C_BLUE="${CSI}34m"

# Track backups for rollback script generation
declare -A BACKUP_MAP=()
BACKUP_ENTRIES=()

say() { printf '%s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

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
  while true; do
    if [[ "$def" =~ ^[Yy]$ ]]; then
      printf '%s [Y/n] ' "$q"
    else
      printf '%s [y/N] ' "$q"
    fi
    read -r ans
    ans="${ans:-$def}"
    case "$ans" in
      y|Y) return 0;;
      n|N) return 1;;
      *) say "Please answer y or n.";;
    esac
  done
}

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [--debug] [--dry-run] [--verify]

  --debug    Enable verbose debug logging (and bash xtrace).
  --dry-run  Show actions but do not write files / run system-changing commands.
  --verify   Do not change anything; validate an existing setup (reads $CONF_FILE).
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

  # verify implies dry-run
  if [[ "$MODE" == "verify" ]]; then
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

  # Always print to stdout, and also to /dev/tty when available.
  local in="/dev/stdin"
  local tty=""
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    tty="/dev/tty"
    in="/dev/tty"
  fi

  printf '%s\n' "$prompt"
  printf '%s\n' "Type exactly: $phrase"
  if [[ -n "$tty" ]]; then
    printf '%s\n' "$prompt" >"$tty"
    printf '%s\n' "Type exactly: $phrase" >"$tty"
  fi

  printf '> '
  [[ -n "$tty" ]] && printf '> ' >"$tty"

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
  # Best-effort: warn/fail if something appears to be using the selected guest GPU.
  local bdf="$1"

  local drv
  drv="$(bdf_driver_name "$bdf")"

  # If already vfio-pci, fine.
  [[ "$drv" == "vfio-pci" ]] && return 0

  # If no driver, likely safe.
  [[ "$drv" == "<none>" ]] && return 0

  # If the GPU is bound to a graphics driver, it *might* be in active use.
  local card
  if card="$(drm_card_for_bdf "$bdf" 2>/dev/null)"; then
    say "WARN: Guest GPU $bdf is currently a DRM device: $card (driver: $drv)"

    if command -v lsof >/dev/null 2>&1; then
      if lsof "$card" >/dev/null 2>&1; then
        say "WARN: $card is currently opened by some process(es)."
      fi
    fi

    if ! confirm_phrase "Refusing to continue by default (binding an in-use GPU can crash your desktop)." "I UNDERSTAND"; then
      die "Aborted: guest GPU appears to be in use"
    fi
  fi
}

pipewire_sinks_for_pci_bdf() {
  # Emits TSV: NODE_NAME \t LABEL for sinks that match the PCI tag of this BDF.
  local bdf="$1"
  command -v wpctl >/dev/null 2>&1 || return 1

  local pci_tag
  pci_tag="$(echo "$bdf" | sed -E 's/^0000:/pci-0000_/; s/:/_/g')"

  local sid sname slabel
  while IFS=$'\t' read -r sid sname slabel; do
    if wpctl inspect "$sid" 2>/dev/null | grep -Fq "$pci_tag"; then
      printf '%s\t%s\n' "$sname" "$slabel"
    fi
  done < <(pipewire_sinks_discover)
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
  [[ -d /run/systemd/system ]] || die "systemd not detected (/run/systemd/system missing)."
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

select_from_list() {
  local prompt="$1"; shift
  local -a options=("$@")
  local idx

  # Always print to stdout, and also to /dev/tty when available.
  local in="/dev/stdin"
  local tty=""
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    tty="/dev/tty"
    in="/dev/tty"
  fi

  while true; do
    printf '\n%s\n' "$prompt"
    for i in "${!options[@]}"; do
      printf '  [%d] %s\n' "$((i+1))" "${options[$i]}"
    done

    if [[ -n "$tty" ]]; then
      printf '\n%s\n' "$prompt" >"$tty"
      for i in "${!options[@]}"; do
        printf '  [%d] %s\n' "$((i+1))" "${options[$i]}" >"$tty"
      done
    fi

    printf '\nEnter number: '
    [[ -n "$tty" ]] && printf '\nEnter number: ' >"$tty"

    read -r idx <"$in"

    [[ "$idx" =~ ^[0-9]+$ ]] || { printf 'Invalid number\n'; [[ -n "$tty" ]] && printf 'Invalid number\n' >"$tty"; continue; }
    (( idx >= 1 && idx <= ${#options[@]} )) || { printf 'Out of range\n'; [[ -n "$tty" ]] && printf 'Out of range\n' >"$tty"; continue; }
    echo "$((idx-1))"
    return 0
  done
}

# ---------------- Discovery ----------------

gpu_discover_all() {
  # Emits TSV per GPU:
  # GPU_BDF \t GPU_DESC \t VENDOR_ID \t DEVICE_ID \t AUDIO_BDFS(comma) \t AUDIO_DESCS(pipe)
  local line bdf desc ids vendor dev slot
  local audio_bdfs audio_descs audio_line

  while IFS= read -r line; do
    bdf="$(awk '{print $1}' <<<"$line")"
    desc="$(cut -d']' -f2- <<<"$line" | sed 's/^: *//')"
    ids="$(grep -oE '\[[0-9a-f]{4}:[0-9a-f]{4}\]' <<<"$line" | head -n1 | tr -d '[]')"
    vendor="${ids%%:*}"
    dev="${ids##*:}"

    slot="${bdf%.*}"
    audio_bdfs=""
    audio_descs=""

    # Find all Audio device functions in the same slot (covers AMD/NVIDIA/other).
    while IFS= read -r audio_line; do
      local abdf adesc
      abdf="$(awk '{print $1}' <<<"$audio_line")"
      adesc="$(cut -d']' -f2- <<<"$audio_line" | sed 's/^: *//')"
      audio_bdfs+="${audio_bdfs:+,}$abdf"
      audio_descs+="${audio_descs:+|}$(trim "$adesc")"
    done < <(lspci -Dnn -s "${slot}.*" 2>/dev/null | awk '/Audio device/ {print}')

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$bdf" "$(trim "$desc")" "$vendor" "$dev" "$audio_bdfs" "$audio_descs"
  done < <(lspci -Dnn | awk '/(VGA compatible controller|3D controller|Display controller)/ {print}')
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
  command -v wpctl >/dev/null 2>&1 || return 1

  local -a ids=()
  mapfile -t ids < <(
    wpctl status | awk '
      /Sinks:/{in=1;next}
      /Sources:/{in=0}
      in{
        for(i=1;i<=NF;i++){
          if($i ~ /^[0-9]+\.$/){ gsub("\\.","",$i); print $i; break }
        }
      }
    '
  )

  local id
  for id in "${ids[@]}"; do
    local node_name label
    node_name="$(wpctl inspect "$id" 2>/dev/null | awk -F' = ' '/node\.name/{gsub(/\"/,"",$2); print $2; exit}')"
    label="$(wpctl inspect "$id" 2>/dev/null | awk -F' = ' '
      /node\.description/{gsub(/\"/,"",$2); print $2; exit}
      /device\.description/{gsub(/\"/,"",$2); print $2; exit}
    ' | head -n1)"

    [[ -n "$node_name" ]] || continue
    label="${label:-$node_name}"
    printf '%s\t%s\t%s\n' "$id" "$node_name" "$label"
  done
}

# ---------------- Writes ----------------

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

  write_file_atomic "$MODULES_LOAD" 0644 "root:root" <<'EOF'
# Load VFIO modules at boot
vfio
vfio_pci
vfio_iommu_type1
vfio_virqfd
EOF
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

  # Replace EXACTLY that line number.
  # Use sed -i without appending anything.
  sed -i "${ln}s|^${key}=.*|${key}=\"${new_cmdline//|/\\|}\"|" /etc/default/grub
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

detect_bootloader() {
  if [[ -f /etc/default/grub ]]; then
    echo "grub"
    return 0
  fi
  if [[ -d /boot/loader/entries || -d /efi/loader/entries ]]; then
    echo "systemd-boot"
    return 0
  fi
  if [[ -f /boot/refind_linux.conf || -f /efi/EFI/refind/refind.conf ]]; then
    echo "refind"
    return 0
  fi
  echo "unknown"
}

print_manual_iommu_instructions() {
  local param
  param="$(cpu_iommu_param)"
  say "Bootloader auto-edit is not supported on this system." 
  say "Manually add these kernel parameters, then reboot:"
  say "  $param iommu=pt"
  say "Optional (risky): pcie_acs_override=downstream,multifunction"
}

grub_add_kernel_params() {
  local -a params_to_add=("$(cpu_iommu_param)" "iommu=pt")

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

  if prompt_yn "Add optional ACS override (pcie_acs_override=downstream,multifunction)?" N; then
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
  else
    die "Neither update-grub nor grub-mkconfig found"
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
    say "Updating initramfs via dracut -f ..."
    run dracut -f
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
      /Sinks:/{in=1;next}
      /Sources:/{in=0}
      in{
        for(i=1;i<=NF;i++){
          if($i ~ /^[0-9]+\.$/){ gsub("\\.","",$i); print $i; break }
        }
      }
    '
  )

  for id in "${sink_ids[@]}"; do
    node_name="$(wpctl inspect "$id" 2>/dev/null | awk -F' = ' '/node\.name/{gsub(/\"/,"",$2); print $2; exit}')"
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
        /Sinks:/{in=1;next}
        /Sources:/{in=0}
        in{
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
  runuser -u "$user" -- systemctl --user daemon-reload || true
  runuser -u "$user" -- systemctl --user enable vfio-set-host-audio.service || true
}

# ---------------- Main ----------------

verify_setup() {
  [[ -f "$CONF_FILE" ]] || die "Missing $CONF_FILE (nothing to verify)."
  # shellcheck disable=SC1090
  . "$CONF_FILE"

  local ok=1

  if [[ -n "${GUEST_GPU_BDF:-}" ]]; then
    if [[ "$(bdf_driver_name "$GUEST_GPU_BDF")" != "vfio-pci" ]]; then
      say "FAIL: Guest GPU $GUEST_GPU_BDF is not bound to vfio-pci (driver: $(bdf_driver_name "$GUEST_GPU_BDF"))"
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

  # GRUB config sanity (if available)
  if [[ -f /etc/default/grub ]]; then
    local key current
    key="$(grub_get_key 2>/dev/null || true)"
    if [[ -n "$key" ]]; then
      current="$(grub_read_cmdline "$key" 2>/dev/null || true)"
      if ! grep -qw "iommu=pt" <<<"$current"; then
        say "WARN: /etc/default/grub missing iommu=pt (did you skip GRUB edit or forget to reboot?)"
      fi
    fi
  fi

  if (( ok )); then
    return 0
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
    "$CONF_FILE"
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
fi

# Rebuild initramfs (best-effort)
if command -v update-initramfs >/dev/null 2>&1 && [ -d /etc/initramfs-tools ]; then
  update-initramfs -u || true
elif command -v mkinitcpio >/dev/null 2>&1; then
  mkinitcpio -P || true
elif command -v dracut >/dev/null 2>&1; then
  dracut -f || true
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

main() {
  parse_args "$@"

  need_cmd lspci
  need_cmd modprobe
  need_cmd sed
  need_cmd awk
  need_cmd grep
  need_cmd install
  need_cmd mktemp

  if [[ "$MODE" == "verify" ]]; then
    verify_setup
    exit $?
  fi

  require_root
  require_systemd

  say
  say "VFIO GPU Passthrough Setup (multi-vendor)"
  say "- Select host GPU, guest GPU"
  say "- Bind guest GPU (and selected PCI functions) by BDF (safer than vendor:device IDs)"
  if (( DRY_RUN )); then
    say "- DRY RUN: no files/commands will be applied"
  fi
  if (( DEBUG )); then
    say "- DEBUG enabled"
  fi
  say

  # Discover GPUs
  local -a gpu_bdfs=() gpu_descs=() gpu_vendor_ids=() gpu_audio_bdfs_csv=() gpu_audio_descs=()
  local gpu_bdf gpu_desc vendor_id device_id audio_csv audio_descs
  while IFS=$'\t' read -r gpu_bdf gpu_desc vendor_id device_id audio_csv audio_descs; do
    [[ -n "${gpu_bdf:-}" ]] || continue
    gpu_bdfs+=("$gpu_bdf")
    gpu_descs+=("$gpu_desc")
    gpu_vendor_ids+=("$vendor_id")
    gpu_audio_bdfs_csv+=("$audio_csv")
    gpu_audio_descs+=("$audio_descs")
  done < <(gpu_discover_all)

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
    options+=("${gpu_bdfs[$i]}  ::  $(vendor_label "${gpu_vendor_ids[$i]}")  ::  ${gpu_descs[$i]}  (slot audio: ${gpu_audio_bdfs_csv[$i]})")
  done

  local guest_idx host_idx
  guest_idx="$(select_from_list "Select the GPU to PASSTHROUGH (bind to vfio-pci):" "${options[@]}")"

  if (( ${#gpu_bdfs[@]} == 2 )); then
    if (( guest_idx == 0 )); then host_idx=1; else host_idx=0; fi
  else
    host_idx="$(select_from_list "Select the GPU to use for HOST display:" "${options[@]}")"
    (( host_idx != guest_idx )) || die "Host GPU and guest GPU cannot be the same."
  fi

  local guest_gpu host_gpu guest_vendor
  guest_gpu="${gpu_bdfs[$guest_idx]}"
  host_gpu="${gpu_bdfs[$host_idx]}"
  guest_vendor="${gpu_vendor_ids[$guest_idx]}"

  assert_not_equal "$guest_gpu" "$host_gpu" "Host GPU and guest GPU are the same (refusing)."
  assert_pci_bdf_exists "$guest_gpu"
  assert_pci_bdf_exists "$host_gpu"

  # Guest audio selection (default: audio functions in the same PCI slot)
  local guest_audio_csv="${gpu_audio_bdfs_csv[$guest_idx]}"
  if [[ -n "$guest_audio_csv" ]]; then
    prompt_yn "Passthrough the guest GPU HDMI/DP audio function(s) too?" Y || guest_audio_csv=""
  else
    say "NOTE: No Audio device found in the same PCI slot as guest GPU."
  fi

  # Preflight: detect if the selected guest GPU looks in-use by the host.
  gpu_in_use_preflight "$guest_gpu"

  # Preflight: IOMMU group gate.
  iommu_group_preflight "$guest_gpu" "$guest_audio_csv"

  # Host audio selection (important when AMD HDMI audio IDs repeat, e.g. 1002:ab28)
  local host_audio_bdfs_csv="${gpu_audio_bdfs_csv[$host_idx]}"

  say
  say "Select which AUDIO PCI device(s) must stay on the HOST (NOT vfio)."
  say "Tip: picking the audio device in the SAME PCI slot as the host GPU is usually correct."
  say "(This is where you avoid the 1002:ab28 problem: pick by BDF, not by 1002:ab28.)"

  local -a aud_opts=() aud_bdfs=()
  local abdf adesc avendor adev
  while IFS=$'\t' read -r abdf adesc avendor adev; do
    aud_bdfs+=("$abdf")
    aud_opts+=("$abdf  ::  $(vendor_label "$avendor")  ::  $adesc  [$avendor:$adev]")
  done < <(audio_devices_discover_all)

  if (( ${#aud_bdfs[@]} > 0 )); then
    local host_audio_idx
    host_audio_idx="$(select_from_list "Select HOST audio PCI device:" "${aud_opts[@]}")"
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
      local -a sink_opts=() sink_node_names=()

      # Prefer sinks that match the selected host audio BDF (if available).
      if [[ -n "$host_audio_bdfs_csv" ]]; then
        while IFS=$'\t' read -r sname slabel; do
          sink_node_names+=("$sname")
          sink_opts+=("$sname  ::  $slabel  (matches host PCI audio $host_audio_bdfs_csv)")
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
        sink_idx="$(select_from_list "Select host default sink:" "${sink_opts[@]}")"
        host_audio_node_name="${sink_node_names[$sink_idx]}"
      else
        say "NOTE: Could not enumerate PipeWire sinks; skipping."
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

  prompt_yn "Proceed and write system config / install services?" N || die "Aborted by user"

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
  install_bind_script
  install_systemd_unit

  if prompt_yn "Add IOMMU kernel parameters to GRUB (and optionally ACS override)?" Y; then
    grub_add_kernel_params
  else
    # Still show manual instructions if not using GRUB auto-edit.
    if [[ "$(detect_bootloader)" != "grub" ]]; then
      print_manual_iommu_instructions
    fi
  fi

  # Optional driver blacklisting
  if prompt_yn "Optional: create a driver blacklist file for the GUEST GPU vendor?" N; then
    local -a mods=()
    case "${guest_vendor,,}" in
      10de)
        mods=(nouveau nvidia nvidia_drm nvidia_modeset nvidia_uvm)
        ;;
      1002)
        # Many people prefer NOT to blacklist amdgpu on dual-GPU systems, so make it explicit.
        if prompt_yn "Blacklist amdgpu (can break host graphics if you picked wrong)?" N; then
          mods+=(amdgpu)
        fi
        if prompt_yn "Blacklist radeon (legacy driver)?" Y; then
          mods+=(radeon)
        fi
        ;;
      8086)
        mods=(i915)
        ;;
      *)
        say "Unknown vendor; no suggested modules."
        ;;
    esac

    if (( ${#mods[@]} > 0 )); then
      write_optional_blacklist "$guest_vendor" "${mods[@]}"
      say "Wrote $BLACKLIST_FILE"
      say "NOTE: If you blacklist modules, updating initramfs is strongly recommended."
    else
      say "No modules selected; skipping blacklist file."
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
