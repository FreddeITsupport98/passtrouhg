#!/usr/bin/env bash
set -euo pipefail

# vfio-gpu-passthrough-setup.sh
# Interactive multi-vendor (AMD/NVIDIA/Intel) GPU passthrough helper.
#
# Goals:
# - Bind ONLY the selected guest GPU (and selected associated PCI functions) to vfio-pci.
# - Avoid common HDMI-audio mistakes (example: BOTH AMD HDMI audio devices share the same PCI ID 1002:ab28).
# - Optional driver blacklisting (user choice).
# - Adaptive kernel IOMMU params (intel_iommu=on vs amd_iommu=on).
# - Optional user-systemd unit to force the host default audio sink after login.
#
# Notes:
# - This script intentionally prefers PCI addresses (BDF) over vendor:device IDs.
# - Requires systemd for services.

SCRIPT_NAME="$(basename "$0")"

CONF_FILE="/etc/vfio-gpu-passthrough.conf"
BIND_SCRIPT="/usr/local/sbin/vfio-bind-selected-gpu.sh"
AUDIO_SCRIPT="/usr/local/bin/vfio-set-host-audio.sh"
SYSTEMD_UNIT="/etc/systemd/system/vfio-bind-selected-gpu.service"
MODULES_LOAD="/etc/modules-load.d/vfio.conf"
BLACKLIST_FILE="/etc/modprobe.d/vfio-optional-blacklist.conf"

say() { printf '%s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

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

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      exec sudo -E "$0" "$@"
    fi
    die "Run as root (or install sudo)."
  fi
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  cp -a "$f" "${f}.bak.${ts}"
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

select_from_list() {
  local prompt="$1"; shift
  local -a options=("$@")
  local idx

  while true; do
    say "$prompt"
    for i in "${!options[@]}"; do
      say "  [$((i+1))] ${options[$i]}"
    done
    printf 'Enter number: '
    read -r idx
    [[ "$idx" =~ ^[0-9]+$ ]] || { say "Invalid number"; continue; }
    (( idx >= 1 && idx <= ${#options[@]} )) || { say "Out of range"; continue; }
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
  cat >"$CONF_FILE" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
#
# IMPORTANT:
# - Use PCI addresses (BDF) to avoid accidentally binding the wrong device when IDs repeat.
#   Example: both AMD HDMI audio controllers can share the same PCI ID (1002:ab28).

HOST_GPU_BDF="$host_gpu"
HOST_AUDIO_BDFS_CSV="$host_audio_bdfs_csv"
HOST_AUDIO_NODE_NAME="$host_audio_node_name"

GUEST_GPU_BDF="$guest_gpu"
GUEST_AUDIO_BDFS_CSV="$guest_audio_bdfs_csv"
GUEST_GPU_VENDOR_ID="$guest_vendor"
EOF

  chmod 0644 "$CONF_FILE"
}

install_vfio_modules_load() {
  backup_file "$MODULES_LOAD"
  cat >"$MODULES_LOAD" <<'EOF'
# Load VFIO modules at boot
vfio
vfio_pci
vfio_iommu_type1
vfio_virqfd
EOF
  chmod 0644 "$MODULES_LOAD"
}

write_optional_blacklist() {
  local vendor_id="$1"; shift
  local -a mods=("$@")

  backup_file "$BLACKLIST_FILE"
  {
    echo "# Optional driver blacklisting for VFIO (generated by $SCRIPT_NAME on $(date -Is))"
    echo "# Vendor: $(vendor_name "$vendor_id") ($vendor_id)"
    echo "# Only enable if you understand the impact (can break host graphics if you pick the wrong modules)."
    echo
    local m
    for m in "${mods[@]}"; do
      echo "blacklist $m"
    done
  } >"$BLACKLIST_FILE"

  chmod 0644 "$BLACKLIST_FILE"
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

grub_add_kernel_params() {
  local -a params_to_add=("$(cpu_iommu_param)" "iommu=pt")

  [[ -f /etc/default/grub ]] || die "/etc/default/grub not found (GRUB required for auto-edit)."
  backup_file /etc/default/grub

  local key
  if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub; then
    key='GRUB_CMDLINE_LINUX_DEFAULT'
  elif grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
    key='GRUB_CMDLINE_LINUX'
  else
    die "Could not find GRUB_CMDLINE_LINUX_DEFAULT or GRUB_CMDLINE_LINUX in /etc/default/grub"
  fi

  local current
  current="$(grep -E "^${key}=" /etc/default/grub | head -n1 | sed -E "s/^${key}=(\"|')(.*)(\"|')\s*$/\2/")"

  local new="$current"
  local p
  for p in "${params_to_add[@]}"; do
    if ! grep -qw "$p" <<<"$new"; then
      new="$new $p"
    fi
  done

  if prompt_yn "Add optional ACS override (pcie_acs_override=downstream,multifunction)?" N; then
    p="pcie_acs_override=downstream,multifunction"
    if ! grep -qw "$p" <<<"$new"; then
      new="$new $p"
    fi
  fi

  new="$(trim "$new")"
  perl -0777 -i -pe "s/^${key}=([\"']).*?\1/${key}=\"$new\"/m" /etc/default/grub

  if command -v update-grub >/dev/null 2>&1; then
    say "Updating GRUB config via update-grub..."
    update-grub
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
    grub-mkconfig -o "$out"
  else
    die "Neither update-grub nor grub-mkconfig found"
  fi
}

maybe_update_initramfs() {
  if command -v update-initramfs >/dev/null 2>&1 && [[ -d /etc/initramfs-tools ]]; then
    say "Updating initramfs via update-initramfs -u ..."
    update-initramfs -u
    return 0
  fi

  if command -v mkinitcpio >/dev/null 2>&1; then
    say "Updating initramfs via mkinitcpio -P ..."
    mkinitcpio -P
    return 0
  fi

  if command -v dracut >/dev/null 2>&1; then
    say "Updating initramfs via dracut -f ..."
    dracut -f
    return 0
  fi

  say "NOTE: No initramfs update tool detected (update-initramfs, mkinitcpio, dracut). Skipping."
}

# ---------------- VFIO binding service ----------------

install_bind_script() {
  backup_file "$BIND_SCRIPT"
  cat >"$BIND_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/vfio-gpu-passthrough.conf"

say() { printf '%s\n' "$*"; }

[[ -f "$CONF_FILE" ]] || { say "Missing $CONF_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF_FILE"

: "${GUEST_GPU_BDF:?}"

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
  [[ -d "$sys" ]] || { say "WARN: $dev not present in sysfs"; return 0; }

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

# Bind guest GPU first.
bind_one "$GUEST_GPU_BDF"

# Bind selected guest audio functions.
while IFS= read -r dev; do
  bind_one "$dev"
done < <(csv_to_array "${GUEST_AUDIO_BDFS_CSV:-}")

# Ensure host audio functions are NOT overridden.
while IFS= read -r dev; do
  clear_override "$dev"
done < <(csv_to_array "${HOST_AUDIO_BDFS_CSV:-}")

say "vfio-pci binding complete: $GUEST_GPU_BDF ${GUEST_AUDIO_BDFS_CSV:-}"
EOF
  chmod 0755 "$BIND_SCRIPT"
}

install_systemd_unit() {
  backup_file "$SYSTEMD_UNIT"
  cat >"$SYSTEMD_UNIT" <<EOF
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

  chmod 0644 "$SYSTEMD_UNIT"
  systemctl daemon-reload
  systemctl enable vfio-bind-selected-gpu.service
}

# ---------------- Host audio default (PipeWire/PulseAudio) ----------------

install_audio_script() {
  backup_file "$AUDIO_SCRIPT"
  cat >"$AUDIO_SCRIPT" <<'EOF'
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
  chmod 0755 "$AUDIO_SCRIPT"
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

main() {
  need_cmd lspci
  need_cmd systemctl
  need_cmd modprobe

  require_root "$@"

  say
  say "VFIO GPU Passthrough Setup (multi-vendor)"
  say "- Select host GPU, guest GPU"
  say "- Bind guest GPU (and selected PCI functions) by BDF (safer than vendor:device IDs)"
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

  local -a options=()
  local i
  for i in "${!gpu_bdfs[@]}"; do
    options+=("${gpu_bdfs[$i]}  ::  $(vendor_name "${gpu_vendor_ids[$i]}")  ::  ${gpu_descs[$i]}  (slot audio: ${gpu_audio_bdfs_csv[$i]})")
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

  # Guest audio selection (default: audio functions in the same PCI slot)
  local guest_audio_csv="${gpu_audio_bdfs_csv[$guest_idx]}"
  if [[ -n "$guest_audio_csv" ]]; then
    prompt_yn "Passthrough the guest GPU HDMI/DP audio function(s) too?" Y || guest_audio_csv=""
  else
    say "NOTE: No Audio device found in the same PCI slot as guest GPU."
  fi

  # Host audio selection (important when AMD HDMI audio IDs repeat, e.g. 1002:ab28)
  local host_audio_bdfs_csv="${gpu_audio_bdfs_csv[$host_idx]}"

  say
  say "Select which AUDIO PCI device(s) must stay on the HOST (NOT vfio)."
  say "This is where you avoid the 1002:ab28 problem: pick the correct BDF for the host GPU HDMI audio."

  local -a aud_opts=() aud_bdfs=()
  local abdf adesc avendor adev
  while IFS=$'\t' read -r abdf adesc avendor adev; do
    aud_bdfs+=("$abdf")
    aud_opts+=("$abdf  ::  $(vendor_name "$avendor")  ::  $adesc  [$avendor:$adev]")
  done < <(audio_devices_discover_all)

  if (( ${#aud_bdfs[@]} > 0 )); then
    local host_audio_idx
    host_audio_idx="$(select_from_list "Select HOST audio PCI device:" "${aud_opts[@]}")"
    host_audio_bdfs_csv="${aud_bdfs[$host_audio_idx]}"
  else
    say "WARN: No PCI audio devices found via lspci."
    host_audio_bdfs_csv=""
  fi

  # PipeWire default sink selection (user-session)
  local host_audio_node_name=""
  if command -v wpctl >/dev/null 2>&1; then
    if prompt_yn "Do you want to select the DEFAULT AUDIO SINK for the host user session (PipeWire/WirePlumber)?" Y; then
      local -a sink_opts=() sink_node_names=()
      local sid sname slabel
      while IFS=$'\t' read -r sid sname slabel; do
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

  write_conf "$host_gpu" "$host_audio_bdfs_csv" "$host_audio_node_name" "$guest_gpu" "$guest_audio_csv" "$guest_vendor"
  install_vfio_modules_load
  install_bind_script
  install_systemd_unit

  if prompt_yn "Add IOMMU kernel parameters to GRUB (and optionally ACS override)?" Y; then
    grub_add_kernel_params
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
