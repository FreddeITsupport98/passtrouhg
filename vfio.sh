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
OPENBOX_MONITOR_SCRIPT="/usr/local/bin/vfio-openbox-activate-monitors.sh"
OPENBOX_AUTOSTART_FILE="/etc/xdg/openbox/autostart"
SYSTEMD_UNIT="/etc/systemd/system/vfio-bind-selected-gpu.service"
MODULES_LOAD="/etc/modules-load.d/vfio.conf"
BLACKLIST_FILE="/etc/modprobe.d/vfio-optional-blacklist.conf"
SOFTDEP_FILE="/etc/modprobe.d/vfio-softdep.conf"
DRACUT_VFIO_CONF="/etc/dracut.conf.d/10-vfio.conf"
UDEV_ISOLATION_RULE="/etc/udev/rules.d/99-vfio-isolation.rules"
USB_BT_SCRIPT="/usr/local/sbin/vfio-usb-bluetooth.sh"
USB_BT_SYSTEMD_UNIT="/etc/systemd/system/vfio-disable-usb-bluetooth.service"
USB_BT_UDEV_RULE="/etc/udev/rules.d/99-vfio-disable-usb-bluetooth.rules"
USB_BT_MATCH_CONF="/etc/vfio-usb-bluetooth-match.conf"
LIGHTDM_FALLBACK_CONF="/etc/lightdm/lightdm.conf.d/90-vfio-greeter-fallback.conf"
XORG_HOST_GPU_CONF="/etc/X11/xorg.conf.d/20-vfio-host-gpu.conf"
LIGHTDM_HOST_GPU_CONF="/etc/lightdm/lightdm.conf.d/90-vfio-host-gpu.conf"
GRAPHICS_DAEMON_SCRIPT="/usr/local/sbin/vfio-graphics-protocold.sh"
GRAPHICS_DAEMON_UNIT="/etc/systemd/system/vfio-graphics-protocold.service"
GRAPHICS_DAEMON_WANTS_LINK="/etc/systemd/system/multi-user.target.wants/vfio-graphics-protocold.service"

DEBUG=0
DRY_RUN=0
JSON_OUTPUT=0
DEBUG_CMDLINE_TOKENS=0
DEBUG_CMDLINE_TOKENS_ENTRY_FILTER=""
MODE="install"   # install | verify | detect | sync-bls-only | debug-cmdline-tokens | verify-bls-sync | verify-bls-nosnapper | create-fallback-entry | self-test | health-check | reset | install-bootlog | install-graphics-daemon | completion printers
BOOT_VGA_POLICY_OVERRIDE=""   # AUTO | STRICT (empty = use script default)
GRAPHICS_PROTOCOL_OVERRIDE="" # AUTO | X11 | WAYLAND (empty = auto-detect)
INSTALL_GRAPHICS_DAEMON=1     # 1=install graphics protocol daemon, 0=skip
GRAPHICS_DAEMON_INTERVAL_DEFAULT=2
GRAPHICS_WATCHDOG_RETENTION_DAYS_DEFAULT=10
GRAPHICS_WATCHDOG_MAX_LINES_DEFAULT=5000
GRAPHICS_DAEMON_INTERVAL_OVERRIDE="" # positive integer seconds (empty = default)
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
# Regression guard: tracks attempted writes to snapper-* BLS entries.
VFIO_BLS_SNAPPER_WRITE_ATTEMPTS=0
declare -ag VFIO_BLS_SNAPPER_WRITE_ATTEMPT_PATHS=()

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
normalize_display_manager_name() {
  # Normalize service/script names to canonical display-manager IDs.
  # Examples:
  #   sddm.service -> sddm
  #   /usr/lib/X11/displaymanagers/sddm -> sddm
  local raw="${1:-}"
  raw="${raw##*/}"
  raw="${raw%.service}"
  raw="${raw,,}"
  case "$raw" in
    lightdm|sddm|lxdm|xdm) printf '%s\n' "$raw"; return 0 ;;
    gdm|gdm3) printf '%s\n' "gdm"; return 0 ;;
  esac
  return 1
}


detect_display_manager() {
  # Return one of: lightdm | sddm | gdm | lxdm | xdm | none
  # Prefer the active display-manager.service symlink when present.
  local dm_link base dm
  if [[ -L /etc/systemd/system/display-manager.service ]]; then
    dm_link="$(readlink -f /etc/systemd/system/display-manager.service 2>/dev/null || true)"
    base="$(basename "$dm_link")"
    if dm="$(normalize_display_manager_name "$base")"; then
      echo "$dm"
      return 0
    fi
    case "$dm_link" in
      *lightdm*) echo "lightdm"; return 0;;
      *sddm*) echo "sddm"; return 0;;
      *gdm*) echo "gdm"; return 0;;
      *lxdm*) echo "lxdm"; return 0;;
      *xdm*) echo "xdm"; return 0;;
    esac
  fi

  # openSUSE frequently points display-manager.service to a wrapper script.
  # In that case resolve the active DM through alternatives.
  if [[ -L /usr/lib/X11/displaymanagers/default-displaymanager ]]; then
    dm_link="$(readlink -f /usr/lib/X11/displaymanagers/default-displaymanager 2>/dev/null || true)"
    base="$(basename "$dm_link")"
    if dm="$(normalize_display_manager_name "$base")"; then
      echo "$dm"
      return 0
    fi
  fi

  # Fall back to installed unit files / config presence.
  if have_cmd systemctl; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^lightdm\.service'; then echo "lightdm"; return 0; fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^sddm\.service'; then echo "sddm"; return 0; fi
    if systemctl list-unit-files 2>/dev/null | grep -Eq '^gdm(3)?\.service'; then echo "gdm"; return 0; fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^lxdm\.service'; then echo "lxdm"; return 0; fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^xdm\.service'; then echo "xdm"; return 0; fi
  fi

  if have_cmd lightdm || [[ -d /etc/lightdm ]]; then echo "lightdm"; return 0; fi
  if have_cmd sddm || [[ -d /etc/sddm.conf.d || -f /etc/sddm.conf ]]; then echo "sddm"; return 0; fi
  if have_cmd gdm || have_cmd gdm3 || [[ -d /etc/gdm || -d /etc/gdm3 ]]; then echo "gdm"; return 0; fi
  if have_cmd lxdm || [[ -d /etc/lxdm ]]; then echo "lxdm"; return 0; fi
  if have_cmd xdm || [[ -f /etc/X11/xdm/xdm-config ]]; then echo "xdm"; return 0; fi

  echo "none"
  return 1
}

lightdm_is_present() {
  [[ "$(detect_display_manager 2>/dev/null || true)" == "lightdm" ]]
}

display_manager_dependency_status() {
  # Tri-state status for display-manager dependency readiness:
  # WORKS | NOT_WORK | NOT_PRESENT
  local dm="${1:-none}"
  case "$dm" in
    lightdm)
      if accountsservice_is_present; then
        echo "WORKS"
      else
        echo "NOT_WORK"
      fi
      ;;
    sddm|gdm|lxdm|xdm)
      echo "WORKS"
      ;;
    none|"")
      echo "NOT_PRESENT"
      ;;
    *)
      echo "WORKS"
      ;;
  esac
}

xorg_stack_status() {
  # WORKS if both Xorg server and X11 session files are present.
  # NOT_PRESENT if neither is present.
  # NOT_WORK for partial/incomplete state.
  local has_server=0 has_sessions=0
  if have_cmd Xorg || [[ -x /usr/bin/Xorg || -x /usr/libexec/Xorg || -x /usr/bin/X ]]; then
    has_server=1
  fi
  if compgen -G "/usr/share/xsessions/*.desktop" >/dev/null 2>&1; then
    has_sessions=1
  fi
  if have_cmd startx || have_cmd xinit; then
    has_sessions=1
  fi

  if (( has_server && has_sessions )); then
    echo "WORKS"
  elif (( ! has_server && ! has_sessions )); then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}

wayland_stack_status() {
  # WORKS if Wayland session files are present and at least one session
  # Exec target resolves to an installed command/binary.
  # Fallback: common compositor/launcher command detection.
  # NOT_PRESENT if neither is present.
  # NOT_WORK for partial/incomplete state.
  local has_sessions=0 has_runtime=0
  local f exec_line exec_cmd exec_base
  if compgen -G "/usr/share/wayland-sessions/*.desktop" >/dev/null 2>&1; then
    has_sessions=1
    for f in /usr/share/wayland-sessions/*.desktop; do
      [[ -f "$f" ]] || continue
      exec_line="$(grep -m1 -E '^Exec=' "$f" 2>/dev/null || true)"
      exec_line="${exec_line#Exec=}"
      exec_cmd="$(printf '%s\n' "$exec_line" | sed -E 's/[[:space:]]+--.*$//; s/[[:space:]].*$//; s/%[fFuUdDnNickvm]//g' | tr -d '"' | head -n1)"
      exec_base="$(basename "${exec_cmd:-}")"
      if [[ -n "$exec_cmd" ]] && { command -v "$exec_cmd" >/dev/null 2>&1 || command -v "$exec_base" >/dev/null 2>&1 || [[ -x "$exec_cmd" ]]; }; then
        has_runtime=1
        break
      fi
    done
  fi
  if have_cmd gnome-shell || have_cmd kwin_wayland || have_cmd startplasma-wayland || have_cmd weston || have_cmd sway || have_cmd hyprland || have_cmd wayfire || have_cmd labwc || have_cmd river || have_cmd niri || have_cmd cage || have_cmd hikari || have_cmd qtile; then
    has_runtime=1
    has_sessions=1
  fi

  if (( has_sessions && has_runtime )); then
    echo "WORKS"
  elif (( ! has_sessions && ! has_runtime )); then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}
x11_wayland_support_status() {
  # Overall graphics protocol support gate for this helper.
  # WORKS: at least one of X11(Xorg) or Wayland stacks is WORKS.
  # NOT_PRESENT: both stacks are NOT_PRESENT.
  # NOT_WORK: partial/broken state where neither stack is WORKS.
  local xorg_status="$1"
  local wayland_status="$2"
  if [[ "$xorg_status" == "WORKS" || "$wayland_status" == "WORKS" ]]; then
    echo "WORKS"
  elif [[ "$xorg_status" == "NOT_PRESENT" && "$wayland_status" == "NOT_PRESENT" ]]; then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}
x11_wayland_supported_mode() {
  # Return BOTH | X11 | WAYLAND | NONE | PARTIAL
  local xorg_status="$1"
  local wayland_status="$2"
  if [[ "$xorg_status" == "WORKS" && "$wayland_status" == "WORKS" ]]; then
    echo "BOTH"
  elif [[ "$xorg_status" == "WORKS" ]]; then
    echo "X11"
  elif [[ "$wayland_status" == "WORKS" ]]; then
    echo "WAYLAND"
  elif [[ "$xorg_status" == "NOT_PRESENT" && "$wayland_status" == "NOT_PRESENT" ]]; then
    echo "NONE"
  else
    echo "PARTIAL"
  fi
}

openbox_stack_status() {
  # WORKS if Openbox binary and an X session entry are present.
  # NOT_PRESENT if neither is present.
  # NOT_WORK for partial/incomplete state.
  local has_openbox=0 has_session=0
  if have_cmd openbox || [[ -x /usr/bin/openbox || -x /usr/local/bin/openbox ]]; then
    has_openbox=1
  fi
  if compgen -G "/usr/share/xsessions/openbox*.desktop" >/dev/null 2>&1 || compgen -G "/usr/share/xsessions/*openbox*.desktop" >/dev/null 2>&1; then
    has_session=1
  fi

  if (( has_openbox && has_session )); then
    echo "WORKS"
  elif (( ! has_openbox && ! has_session )); then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}
openbox_connected_outputs_from_xrandr_query() {
  # Read xrandr --query output from stdin and print output names that are
  # currently connected.
  awk '$2 == "connected" { print $1 }'
}
openbox_activate_all_connected_monitors() {
  # Enable all currently connected outputs via xrandr.
  # Accept an optional xrandr binary path for regression testing.
  local xrandr_bin="${1:-xrandr}"
  command -v "$xrandr_bin" >/dev/null 2>&1 || return 0
  [[ -n "${DISPLAY:-}" ]] || return 0

  local query
  query="$("$xrandr_bin" --query 2>/dev/null || true)"
  [[ -n "$query" ]] || return 0

  local -a outputs=()
  mapfile -t outputs < <(printf '%s\n' "$query" | openbox_connected_outputs_from_xrandr_query)
  (( ${#outputs[@]} > 0 )) || return 0

  local output
  for output in "${outputs[@]}"; do
    "$xrandr_bin" --output "$output" --auto >/dev/null 2>&1 || true
  done
}
i3_stack_status() {
  # WORKS if i3 binary and an X session entry are present.
  # NOT_PRESENT if neither is present.
  # NOT_WORK for partial/incomplete state.
  local has_i3=0 has_session=0
  if have_cmd i3 || have_cmd i3wm || [[ -x /usr/bin/i3 || -x /usr/local/bin/i3 ]]; then
    has_i3=1
  fi
  if compgen -G "/usr/share/xsessions/i3*.desktop" >/dev/null 2>&1 || compgen -G "/usr/share/xsessions/*i3*.desktop" >/dev/null 2>&1; then
    has_session=1
  fi

  if (( has_i3 && has_session )); then
    echo "WORKS"
  elif (( ! has_i3 && ! has_session )); then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}
bspwm_stack_status() {
  # WORKS if bspwm binary and an X session entry are present.
  # NOT_PRESENT if neither is present.
  # NOT_WORK for partial/incomplete state.
  local has_bspwm=0 has_session=0
  if have_cmd bspwm || [[ -x /usr/bin/bspwm || -x /usr/local/bin/bspwm ]]; then
    has_bspwm=1
  fi
  if compgen -G "/usr/share/xsessions/bspwm*.desktop" >/dev/null 2>&1 || compgen -G "/usr/share/xsessions/*bspwm*.desktop" >/dev/null 2>&1; then
    has_session=1
  fi

  if (( has_bspwm && has_session )); then
    echo "WORKS"
  elif (( ! has_bspwm && ! has_session )); then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}
awesome_stack_status() {
  # WORKS if awesome binary and an X session entry are present.
  # NOT_PRESENT if neither is present.
  # NOT_WORK for partial/incomplete state.
  local has_awesome=0 has_session=0
  if have_cmd awesome || [[ -x /usr/bin/awesome || -x /usr/local/bin/awesome ]]; then
    has_awesome=1
  fi
  if compgen -G "/usr/share/xsessions/awesome*.desktop" >/dev/null 2>&1 || compgen -G "/usr/share/xsessions/*awesome*.desktop" >/dev/null 2>&1; then
    has_session=1
  fi

  if (( has_awesome && has_session )); then
    echo "WORKS"
  elif (( ! has_awesome && ! has_session )); then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}
dwm_stack_status() {
  # WORKS if dwm binary and an X session entry are present.
  # NOT_PRESENT if neither is present.
  # NOT_WORK for partial/incomplete state.
  local has_dwm=0 has_session=0
  if have_cmd dwm || [[ -x /usr/bin/dwm || -x /usr/local/bin/dwm ]]; then
    has_dwm=1
  fi
  if compgen -G "/usr/share/xsessions/dwm*.desktop" >/dev/null 2>&1 || compgen -G "/usr/share/xsessions/*dwm*.desktop" >/dev/null 2>&1; then
    has_session=1
  fi

  if (( has_dwm && has_session )); then
    echo "WORKS"
  elif (( ! has_dwm && ! has_session )); then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}
qtile_stack_status() {
  # WORKS if qtile binary and an X session entry are present.
  # NOT_PRESENT if neither is present.
  # NOT_WORK for partial/incomplete state.
  local has_qtile=0 has_session=0
  if have_cmd qtile || [[ -x /usr/bin/qtile || -x /usr/local/bin/qtile ]]; then
    has_qtile=1
  fi
  if compgen -G "/usr/share/xsessions/qtile*.desktop" >/dev/null 2>&1 || compgen -G "/usr/share/xsessions/*qtile*.desktop" >/dev/null 2>&1; then
    has_session=1
  fi

  if (( has_qtile && has_session )); then
    echo "WORKS"
  elif (( ! has_qtile && ! has_session )); then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}
xfwm4_stack_status() {
  # WORKS if xfwm4 binary and an X session entry are present.
  # NOTE: xfwm4 usually ships with XFCE session files (xfce*.desktop),
  # not necessarily xfwm4.desktop.
  # NOT_PRESENT if neither is present.
  # NOT_WORK for partial/incomplete state.
  local has_xfwm4=0 has_session=0
  if have_cmd xfwm4 || [[ -x /usr/bin/xfwm4 || -x /usr/local/bin/xfwm4 ]]; then
    has_xfwm4=1
  fi
  if compgen -G "/usr/share/xsessions/xfwm4*.desktop" >/dev/null 2>&1 || compgen -G "/usr/share/xsessions/xfce*.desktop" >/dev/null 2>&1 || compgen -G "/usr/share/xsessions/*xfce*.desktop" >/dev/null 2>&1; then
    has_session=1
  fi

  if (( has_xfwm4 && has_session )); then
    echo "WORKS"
  elif (( ! has_xfwm4 && ! has_session )); then
    echo "NOT_PRESENT"
  else
    echo "NOT_WORK"
  fi
}
format_tri_state_status() {
  # Render WORKS / NOT WORK / NOT PRESENT with color when enabled.
  local status="$1"
  case "$status" in
    WORKS)
      if (( ENABLE_COLOR )); then
        printf '%s' "${C_GREEN}WORKS${C_RESET}"
      else
        printf '%s' "WORKS"
      fi
      ;;
    NOT_WORK)
      if (( ENABLE_COLOR )); then
        printf '%s' "${C_RED}NOT WORK${C_RESET}"
      else
        printf '%s' "NOT WORK"
      fi
      ;;
    NOT_PRESENT)
      if (( ENABLE_COLOR )); then
        printf '%s' "${C_YELLOW}NOT PRESENT${C_RESET}"
      else
        printf '%s' "NOT PRESENT"
      fi
      ;;
    *)
      printf '%s' "$status"
      ;;
  esac
}

accountsservice_is_present() {
  # AccountsService provides org.freedesktop.Accounts over system DBus.
  # LightDM often relies on this; when missing, LightDM may fail in a restart loop.
  if have_cmd accounts-daemon; then
    return 0
  fi
  # Some systems may ship the DBus service file without an actual daemon
  # backend; do not treat the DBus file alone as "installed".
  local p
  for p in /usr/lib/accounts-daemon /usr/libexec/accounts-daemon /lib/accounts-daemon /usr/sbin/accounts-daemon; do
    [[ -x "$p" ]] && return 0
  done
  [[ -f /usr/lib/systemd/system/accounts-daemon.service ]] && return 0
  [[ -f /lib/systemd/system/accounts-daemon.service ]] && return 0
  return 1
}

install_accountsservice_pkg() {
  # Best-effort install across common distro families.
  local use_sudo=0
  if [[ "${EUID:-$(id -u)}" -ne 0 ]] && have_cmd sudo; then
    use_sudo=1
  fi
  if have_cmd apt-get; then
    if (( use_sudo )); then
      run sudo apt-get -y install accountsservice
    else
      run apt-get -y install accountsservice
    fi
    return $?
  fi
  if have_cmd dnf; then
    if (( use_sudo )); then
      run sudo dnf -y install accountsservice
    else
      run dnf -y install accountsservice
    fi
    return $?
  fi
  if have_cmd zypper; then
    if (( use_sudo )); then
      run sudo zypper --non-interactive in accountsservice
    else
      run zypper --non-interactive in accountsservice
    fi
    return $?
  fi
  if have_cmd pacman; then
    if (( use_sudo )); then
      run sudo pacman --noconfirm -S accountsservice
    else
      run pacman --noconfirm -S accountsservice
    fi
    return $?
  fi
  return 1
}

enable_accountsservice_unit() {
  have_cmd systemctl || return 1
  if [[ "${EUID:-$(id -u)}" -ne 0 ]] && have_cmd sudo; then
    run sudo systemctl enable --now accounts-daemon.service 2>/dev/null || true
    run sudo systemctl enable --now accounts-daemon 2>/dev/null || true
  else
    run systemctl enable --now accounts-daemon.service 2>/dev/null || true
    run systemctl enable --now accounts-daemon 2>/dev/null || true
  fi
  return 0
}

install_lightdm_accountsservice_fallback() {
  # Fallback for systems where AccountsService cannot be installed immediately:
  # hide user list in greeter to reduce dependency on org.freedesktop.Accounts.
  local d="/etc/lightdm/lightdm.conf.d"
  backup_file "$LIGHTDM_FALLBACK_CONF"
  if (( ! DRY_RUN )); then
    mkdir -p "$d"
  fi
  write_file_atomic "$LIGHTDM_FALLBACK_CONF" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
# Fallback for systems where org.freedesktop.Accounts is unavailable.
# This reduces LightDM's dependency on AccountsService by not requesting user list rendering.
[Seat:*]
greeter-hide-users=true
EOF
}

print_fish_completion() {
  local cmd="$SCRIPT_NAME"
  cat <<EOF
# fish completion for $cmd (generated by $SCRIPT_NAME)
complete -c $cmd -f
complete -c $cmd -s h -l help -d 'Show help'
complete -c $cmd -l debug -d 'Enable verbose debug logging'
complete -c $cmd -l dry-run -d 'Show actions without changing the system'
complete -c $cmd -l no-tui -d 'Force plain-text prompts'
complete -c $cmd -l boot-vga-policy -r -a 'auto strict' -d 'Install-mode Boot-VGA policy override'
complete -c $cmd -l graphics-protocol -r -a 'auto x11 wayland' -d 'Install-mode graphics protocol override'
complete -c $cmd -l graphics-daemon-interval -r -d 'Set graphics daemon polling interval in seconds (1-3600)'
complete -c $cmd -l no-graphics-daemon -d 'Do not install graphics protocol daemon service'
complete -c $cmd -l verify -d 'Validate existing setup'
complete -c $cmd -l detect -d 'Print detailed existing-setup report'
complete -c $cmd -l sync-bls-only -d 'Sync BLS entry options from /etc/kernel/cmdline and verify drift'
complete -c $cmd -l debug-cmdline-tokens -d 'Trace BLS root/rootflags token source selection (read-only)'
complete -c $cmd -l entry -r -d 'Filter BLS entry basenames (glob) for --debug-cmdline-tokens'
complete -c $cmd -l verify-bls-sync -d 'Verify BLS entry options are synchronized with /etc/kernel/cmdline'
complete -c $cmd -l verify-bls-nosnapper -d 'Regression check: assert snapper BLS entries are never write targets'
complete -c $cmd -l create-fallback-entry -d 'Create/update a non-VFIO fallback BLS entry from the current system entry'
complete -c $cmd -l print-effective-config -d 'Print effective Boot-VGA policy decision path'
complete -c $cmd -l json -d 'Machine-readable output with --detect or --debug-cmdline-tokens'
complete -c $cmd -l self-test -d 'Run self-tests and exit'
complete -c $cmd -l health-check -d 'Audit current kernel/logs for VFIO friendliness'
complete -c $cmd -l health-check-previous -d 'Audit previous boot for VFIO friendliness'
complete -c $cmd -l health-check-all -d 'Audit all detected GPUs'
complete -c $cmd -l usb-health-check -d 'Audit USB/xHCI instability markers'
complete -c $cmd -l reset -d 'Remove VFIO setup installed by this script'
complete -c $cmd -l disable-bootlog -d 'Disable/remove optional VFIO boot-log dumper'
complete -c $cmd -l boot-remove -d 'Alias of --disable-bootlog'
complete -c $cmd -l install-bootlog -d 'Install/reinstall only optional VFIO boot-log dumper'
complete -c $cmd -l install-graphics-daemon -d 'Install/reinstall only VFIO graphics protocol daemon'
complete -c $cmd -l install-usb-bt-mitigation -d 'Install only optional USB Bluetooth mitigation'
complete -c $cmd -l print-fish-completion -d 'Print fish completion script'
complete -c $cmd -l print-bash-completion -d 'Print bash completion script'
complete -c $cmd -l print-zsh-completion -d 'Print zsh completion script'
EOF
}

print_bash_completion() {
  local cmd="$SCRIPT_NAME"
  cat <<EOF
# bash completion for $cmd (generated by $SCRIPT_NAME)
_vfio_sh_complete() {
  local cur prev opts
  COMPREPLY=()
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  opts="--help -h --debug --dry-run --no-tui --boot-vga-policy --graphics-protocol --graphics-daemon-interval --no-graphics-daemon --verify --detect --sync-bls-only --debug-cmdline-tokens --entry --verify-bls-sync --verify-bls-nosnapper --create-fallback-entry --print-effective-config --json --self-test --health-check --health-check-previous --health-check-all --usb-health-check --reset --disable-bootlog --boot-remove --install-bootlog --install-graphics-daemon --install-usb-bt-mitigation --print-fish-completion --print-bash-completion --print-zsh-completion"

  if [[ "\$prev" == "--boot-vga-policy" ]]; then
    COMPREPLY=(\$(compgen -W "auto strict" -- "\$cur"))
    return 0
  fi
  if [[ "\$prev" == "--graphics-protocol" ]]; then
    COMPREPLY=(\$(compgen -W "auto x11 wayland" -- "\$cur"))
    return 0
  fi
  if [[ "\$prev" == "--graphics-daemon-interval" ]]; then
    COMPREPLY=(\$(compgen -W "5 10 15 30 60" -- "\$cur"))
    return 0
  fi
  if [[ "\$prev" == "--entry" ]]; then
    COMPREPLY=(\$(compgen -W "system-*.conf snapper-*.conf *.conf" -- "\$cur"))
    return 0
  fi

  COMPREPLY=(\$(compgen -W "\$opts" -- "\$cur"))
  return 0
}
complete -F _vfio_sh_complete $cmd
EOF
}

print_zsh_completion() {
  local cmd="$SCRIPT_NAME"
  cat <<EOF
#compdef $cmd
# zsh completion for $cmd (generated by $SCRIPT_NAME)
_vfio_sh_complete() {
  _arguments \\
    '(-h --help)'{-h,--help}'[Show help]' \\
    '--debug[Enable verbose debug logging]' \\
    '--dry-run[Show actions without changing the system]' \\
    '--no-tui[Force plain-text prompts]' \\
    '--boot-vga-policy=[Install-mode Boot-VGA policy override]:policy:(auto strict)' \\
    '--graphics-protocol=[Install-mode graphics protocol override]:protocol:(auto x11 wayland)' \\
    '--graphics-daemon-interval=[Set graphics daemon polling interval in seconds (1-3600)]:seconds:(5 10 15 30 60)' \\
    '--no-graphics-daemon[Do not install graphics protocol daemon service]' \\
    '--verify[Validate existing setup]' \\
    '--detect[Print detailed existing-setup report]' \\
    '--sync-bls-only[Sync BLS entry options from /etc/kernel/cmdline and verify drift]' \
    '--debug-cmdline-tokens[Trace BLS root/rootflags token source selection (read-only)]' \
    '--entry=[Filter BLS entry basenames (glob) for --debug-cmdline-tokens]:pattern:(system-*.conf snapper-*.conf *.conf)' \
    '--verify-bls-sync[Verify BLS entry options are synchronized with /etc/kernel/cmdline]' \
    '--verify-bls-nosnapper[Regression check: assert snapper BLS entries are never write targets]' \
    '--create-fallback-entry[Create/update a non-VFIO fallback BLS entry from the current system entry]' \
    '--print-effective-config[Print effective Boot-VGA policy decision path]' \\
    '--json[Machine-readable output with --detect or --debug-cmdline-tokens]' \\
    '--self-test[Run self-tests and exit]' \\
    '--health-check[Audit current kernel/logs for VFIO friendliness]' \\
    '--health-check-previous[Audit previous boot for VFIO friendliness]' \\
    '--health-check-all[Audit all detected GPUs]' \\
    '--usb-health-check[Audit USB/xHCI instability markers]' \\
    '--reset[Remove VFIO setup installed by this script]' \\
    '--disable-bootlog[Disable/remove optional VFIO boot-log dumper]' \\
    '--boot-remove[Alias of --disable-bootlog]' \\
    '--install-bootlog[Install/reinstall only optional VFIO boot-log dumper]' \
    '--install-graphics-daemon[Install/reinstall only VFIO graphics protocol daemon]' \
    '--install-usb-bt-mitigation[Install only optional USB Bluetooth mitigation]' \\
    '--print-fish-completion[Print fish completion script]' \\
    '--print-bash-completion[Print bash completion script]' \\
    '--print-zsh-completion[Print zsh completion script]'
}
compdef _vfio_sh_complete $cmd
EOF
}

maybe_offer_detect_accountsservice_install() {
  # Detect mode is read-only by default, but when the user explicitly confirms
  # this action we perform the install as a one-off fix because the goal of
  # this mode is troubleshooting and remediation guidance.
  [[ "${MODE:-}" == "detect" ]] || return 0
  lightdm_is_present || return 0
  accountsservice_is_present && return 0

  say
  hdr "Detect action (optional)"
  note "LightDM is installed but org.freedesktop.Accounts is missing."
  note "This is a known cause of LightDM restart-loop failures at boot."
  if ! prompt_yn "Install accountsservice now from detect mode?" N "LightDM dependency"; then
    return 0
  fi
  if ! confirm_phrase "This will install packages on your system now." "INSTALL ACCOUNTSERVICE"; then
    note "Skipping accountsservice install (confirmation phrase not provided)."
    return 0
  fi

  local prev_dry="${DRY_RUN:-0}"
  DRY_RUN=0
  if install_accountsservice_pkg; then
    enable_accountsservice_unit || true
    if accountsservice_is_present; then
      say "Installed AccountsService from detect mode."
    else
      note "Install command ran, but AccountsService is still not detected; verify package/service state manually."
    fi
  else
    note "Automatic accountsservice install from detect mode failed."
    note "You can install manually, then re-run --detect."
  fi
  DRY_RUN="$prev_dry"
}

list_stale_vfio_user_audio_units() {
  # Emit TSV: user<TAB>unit_path for user units that reference the
  # optional vfio-set-host-audio service while the helper script is missing.
  [[ -x "$AUDIO_SCRIPT" ]] && return 0

  local d user unit
  for d in /home/*; do
    [[ -d "$d" ]] || continue
    user="$(basename "$d")"
    unit="$d/.config/systemd/user/vfio-set-host-audio.service"
    [[ -f "$unit" ]] || continue
    printf '%s\t%s\n' "$user" "$unit"
  done
}

maybe_offer_detect_stale_user_audio_unit_cleanup() {
  [[ "${MODE:-}" == "detect" ]] || return 0

  local stale
  stale="$(list_stale_vfio_user_audio_units || true)"
  [[ -n "$stale" ]] || return 0

  say
  hdr "Detect action (optional): stale user audio unit cleanup"
  note "Found vfio-set-host-audio user unit(s) but $AUDIO_SCRIPT is missing."
  note "This can spam user-session failures and be mistaken for display-manager issues."
  printf '%s\n' "$stale" | awk -F'\t' '{print "  - user=" $1 " unit=" $2}'

  if ! prompt_yn "Remove stale vfio-set-host-audio user unit(s) now from detect mode?" Y "User audio unit cleanup"; then
    return 0
  fi
  if ! confirm_phrase "This will remove stale user service files now." "REMOVE STALE AUDIO UNIT"; then
    note "Skipping stale unit cleanup (confirmation phrase not provided)."
    return 0
  fi

  local prev_dry="${DRY_RUN:-0}"
  DRY_RUN=0

  local user unit uid
  while IFS=$'\t' read -r user unit; do
    [[ -n "$unit" ]] || continue
    [[ -f "$unit" ]] || continue
    if have_cmd runuser; then
      uid="$(id -u "$user" 2>/dev/null || true)"
      if [[ -n "$uid" ]]; then
        runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user disable --now vfio-set-host-audio.service >/dev/null 2>&1 || true
      fi
    fi
    run rm -f "$unit"
    say "Removed stale unit for user '$user': $unit"
  done <<<"$stale"

  DRY_RUN="$prev_dry"
}

list_user_audio_units_missing_condition_guard() {
  # Emit TSV: user<TAB>unit_path for vfio audio user units missing
  # ConditionPathExists guard.
  local d user unit guard
  guard="ConditionPathExists=$AUDIO_SCRIPT"
  for d in /home/*; do
    [[ -d "$d" ]] || continue
    user="$(basename "$d")"
    unit="$d/.config/systemd/user/vfio-set-host-audio.service"
    [[ -f "$unit" ]] || continue
    grep -Fq "$guard" "$unit" 2>/dev/null && continue
    printf '%s\t%s\n' "$user" "$unit"
  done
}

repair_user_audio_unit_condition_guard() {
  local user="$1" unit="$2"
  [[ -n "$unit" && -f "$unit" ]] || return 1

  local guard tmp mode owner group uid
  guard="ConditionPathExists=$AUDIO_SCRIPT"
  tmp="$(mktemp)"

  awk -v guard="$guard" '
    BEGIN { inserted=0; had_guard=0 }
    {
      if ($0 == guard) {
        had_guard=1
      }
      print
      if ($0 ~ /^After=pipewire\.service wireplumber\.service$/ && !inserted && !had_guard) {
        print guard
        inserted=1
      }
    }
    END {
      if (!inserted && !had_guard) {
        print guard
      }
    }
  ' "$unit" >"$tmp"

  mode="$(stat -c '%a' "$unit" 2>/dev/null || echo 644)"
  owner="$(stat -c '%u' "$unit" 2>/dev/null || id -u)"
  group="$(stat -c '%g' "$unit" 2>/dev/null || id -g)"
  run install -o "$owner" -g "$group" -m "$mode" "$tmp" "$unit"
  run rm -f "$tmp"

  if have_cmd runuser; then
    uid="$(id -u "$user" 2>/dev/null || true)"
    if [[ -n "$uid" ]]; then
      runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user daemon-reload >/dev/null 2>&1 || true
      runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user reset-failed vfio-set-host-audio.service >/dev/null 2>&1 || true
    fi
  fi
  return 0
}

maybe_offer_detect_user_audio_unit_guard_repair() {
  [[ "${MODE:-}" == "detect" ]] || return 0

  local missing_guard
  missing_guard="$(list_user_audio_units_missing_condition_guard || true)"
  [[ -n "$missing_guard" ]] || return 0

  say
  hdr "Detect action (optional): repair legacy user audio unit guard"
  note "Found vfio-set-host-audio user unit(s) missing ConditionPathExists guard."
  note "This can fail user session startup after restore/rollback when helper script is absent."
  printf '%s\n' "$missing_guard" | awk -F'\t' '{print "  - user=" $1 " unit=" $2}'

  if ! prompt_yn "Repair these user unit(s) now (add ConditionPathExists guard)?" Y "User audio unit repair"; then
    return 0
  fi
  if ! confirm_phrase "This will edit user service files now." "REPAIR AUDIO UNIT"; then
    note "Skipping unit repair (confirmation phrase not provided)."
    return 0
  fi

  local prev_dry="${DRY_RUN:-0}"
  DRY_RUN=0

  local user unit
  while IFS=$'\t' read -r user unit; do
    [[ -n "$unit" ]] || continue
    [[ -f "$unit" ]] || continue
    repair_user_audio_unit_condition_guard "$user" "$unit" || true
    say "Repaired user unit for '$user': $unit"
  done <<<"$missing_guard"

  DRY_RUN="$prev_dry"
}

auto_repair_legacy_user_audio_unit_guards() {
  # Non-interactive self-heal for normal install flow:
  # ensure legacy user audio units have ConditionPathExists guard.
  [[ "${MODE:-install}" == "install" ]] || return 0

  local missing_guard
  missing_guard="$(list_user_audio_units_missing_condition_guard || true)"
  [[ -n "$missing_guard" ]] || return 0

  say
  hdr "Install self-heal: legacy user audio unit guard"
  note "Found legacy vfio-set-host-audio user unit(s) missing ConditionPathExists guard."
  note "Applying automatic repair to reduce user-session failures after restore/rollback."

  local prev_dry="${DRY_RUN:-0}"
  DRY_RUN=0

  local user unit
  while IFS=$'\t' read -r user unit; do
    [[ -n "$unit" ]] || continue
    [[ -f "$unit" ]] || continue
    repair_user_audio_unit_condition_guard "$user" "$unit" || true
    say "Auto-repaired user unit for '$user': $unit"
  done <<<"$missing_guard"

  DRY_RUN="$prev_dry"
}
host_has_amd_gpu() {
  have_cmd lspci || return 1
  lspci -n 2>/dev/null | grep -q '1002:'
}
recent_kernel_logs() {
  # Print current + previous boot kernel logs when available.
  if have_cmd journalctl; then
    journalctl -k -b --no-pager 2>/dev/null || true
    journalctl -k -b -1 --no-pager 2>/dev/null || true
    return 0
  fi
  if have_cmd dmesg; then
    dmesg 2>/dev/null || true
    return 0
  fi
  return 1
}

amd_reset_issue_signatures_present() {
  # Return 0 only when kernel logs show signatures consistent with
  # VFIO/AMD reset failures. This avoids static GPU-family hardcoding.
  local logs
  logs="$(recent_kernel_logs || true)"
  [[ -n "$logs" ]] || return 1

  printf '%s\n' "$logs" \
    | grep -Ei '(vfio-pci|amdgpu).*(reset|flr|d3)' \
    | grep -Ei '(fail|failed|timeout|timed out|not ready|stuck|unable|can.t|error)' \
    >/dev/null 2>&1
}

amd_reset_issue_signatures_present_for_bdf() {
  # BDF-specific variant to scope reset-failure checks to the selected guest GPU.
  local bdf="${1:-}"
  [[ -n "$bdf" ]] || return 1
  local logs slot
  logs="$(recent_kernel_logs || true)"
  [[ -n "$logs" ]] || return 1
  slot="${bdf%.*}"

  printf '%s\n' "$logs" \
    | grep -Ei '(vfio-pci|amdgpu).*(reset|flr|d3)' \
    | grep -Ei '(fail|failed|timeout|timed out|not ready|stuck|unable|can.t|error)' \
    | grep -Ei "($bdf|$slot)" \
    >/dev/null 2>&1
}

vendor_reset_is_present() {
  [[ -d /sys/module/vendor_reset ]] && return 0
  have_cmd modinfo && modinfo vendor_reset >/dev/null 2>&1 && return 0
  return 1
}

install_vendor_reset_pkg() {
  # Best-effort install for common distro package names.
  local use_sudo=0
  if [[ "${EUID:-$(id -u)}" -ne 0 ]] && have_cmd sudo; then
    use_sudo=1
  fi

  if have_cmd apt-get; then
    local -a candidates=(vendor-reset-dkms vendor-reset)
    if have_cmd apt-cache; then
      local p
      while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        candidates+=("$p")
      done < <(apt-cache search -n '^vendor[-]reset' 2>/dev/null | awk '{print $1}')
    fi

    local tried=""
    local pkg
    for pkg in "${candidates[@]}"; do
      [[ -n "$pkg" ]] || continue
      if grep -Eq "(^|[[:space:]])${pkg}([[:space:]]|$)" <<<"$tried"; then
        continue
      fi
      tried="${tried:+$tried }$pkg"
      if (( use_sudo )); then
        if run sudo apt-get -y install "$pkg"; then
          return 0
        fi
      else
        if run apt-get -y install "$pkg"; then
          return 0
        fi
      fi
    done
    return 1
  fi
  if have_cmd dnf; then
    if (( use_sudo )); then
      run sudo dnf -y install kmod-vendor-reset || run sudo dnf -y install vendor-reset
    else
      run dnf -y install kmod-vendor-reset || run dnf -y install vendor-reset
    fi
    return $?
  fi
  if have_cmd zypper; then
    if (( use_sudo )); then
      run sudo zypper --non-interactive in vendor-reset || run sudo zypper --non-interactive in vendor-reset-kmp-default
    else
      run zypper --non-interactive in vendor-reset || run zypper --non-interactive in vendor-reset-kmp-default
    fi
    return $?
  fi
  if have_cmd pacman; then
    if (( use_sudo )); then
      run sudo pacman --noconfirm -S vendor-reset-dkms || run sudo pacman --noconfirm -S vendor-reset
    else
      run pacman --noconfirm -S vendor-reset-dkms || run pacman --noconfirm -S vendor-reset
    fi
    return $?
  fi
  return 1
}

cleanup_tmp_dir_best_effort() {
  local tmp_dir="${1:-}"
  if [[ -n "$tmp_dir" && -d "$tmp_dir" ]]; then
    run rm -rf "$tmp_dir" || true
  fi
  return 0
}
install_vendor_reset_dkms_from_source() {
  # Optional fallback for apt-based systems where vendor-reset packages are
  # unavailable in enabled repositories.
  have_cmd apt-get || return 1
  have_cmd git || return 1
  have_cmd dkms || return 1

  local use_sudo=0
  if [[ "${EUID:-$(id -u)}" -ne 0 ]] && have_cmd sudo; then
    use_sudo=1
  fi

  local krel headers_pkg
  krel="$(uname -r)"
  headers_pkg="linux-headers-$krel"
  if (( use_sudo )); then
    run sudo apt-get -y install "$headers_pkg" || true
  else
    run apt-get -y install "$headers_pkg" || true
  fi

  local tmp src
  tmp="$(mktemp -d /tmp/vendor-reset-dkms.XXXXXX)"
  src="$tmp/vendor-reset"

  if ! run git clone --depth 1 https://github.com/gnif/vendor-reset "$src"; then
    cleanup_tmp_dir_best_effort "$tmp"
    return 1
  fi
  if [[ ! -f "$src/dkms.conf" ]]; then
    cleanup_tmp_dir_best_effort "$tmp"
    return 1
  fi

  local pkg_name pkg_ver
  pkg_name="$(awk -F= '/^PACKAGE_NAME=/{gsub(/[[:space:]"]/, "", $2); print $2; exit}' "$src/dkms.conf")"
  pkg_ver="$(awk -F= '/^PACKAGE_VERSION=/{gsub(/[[:space:]"]/, "", $2); print $2; exit}' "$src/dkms.conf")"
  if [[ -z "$pkg_name" || -z "$pkg_ver" ]]; then
    cleanup_tmp_dir_best_effort "$tmp"
    return 1
  fi

  if (( use_sudo )); then
    run sudo dkms remove "$pkg_name/$pkg_ver" --all 2>/dev/null || true
    run sudo dkms add "$src"
    run sudo dkms install "$pkg_name/$pkg_ver"
  else
    run dkms remove "$pkg_name/$pkg_ver" --all 2>/dev/null || true
    run dkms add "$src"
    run dkms install "$pkg_name/$pkg_ver"
  fi

  cleanup_tmp_dir_best_effort "$tmp"
}

maybe_offer_detect_vendor_reset_install() {
  [[ "${MODE:-}" == "detect" ]] || return 0
  host_has_amd_gpu || return 0
  amd_reset_issue_signatures_present || return 0
  vendor_reset_is_present && return 0

  say
  hdr "Detect action (optional): vendor-reset"
  note "AMD reset-failure markers were detected in kernel logs and vendor-reset is missing."
  note "Installing vendor-reset can help when VFIO GPU reset fails after VM shutdown/restart."
  if ! prompt_yn "Install vendor-reset now from detect mode?" N "AMD reset mitigation"; then
    return 0
  fi
  if ! confirm_phrase "This will install packages on your system now." "INSTALL VENDOR RESET"; then
    note "Skipping vendor-reset install (confirmation phrase not provided)."
    return 0
  fi

  local prev_dry="${DRY_RUN:-0}"
  DRY_RUN=0
  if install_vendor_reset_pkg; then
    if have_cmd modprobe; then
      if [[ "${EUID:-$(id -u)}" -ne 0 ]] && have_cmd sudo; then
        run sudo modprobe vendor_reset 2>/dev/null || true
      else
        run modprobe vendor_reset 2>/dev/null || true
      fi
    fi
    if vendor_reset_is_present; then
      say "Installed vendor-reset from detect mode."
    else
      note "Install command ran, but vendor-reset is still not detected for this kernel."
      note "A reboot or matching kernel headers/dkms build may be required."
    fi
  else
    note "Automatic vendor-reset install from detect mode failed."
    if have_cmd apt-get; then
      note "Package not found in enabled apt repositories. Optional fallback: build DKMS module from upstream source."
      if prompt_yn "Try source-based DKMS install for vendor-reset now? (advanced)" N "AMD reset mitigation"; then
        if confirm_phrase "This will clone/build a kernel module from source now." "BUILD VENDOR RESET"; then
          if install_vendor_reset_dkms_from_source; then
            if have_cmd modprobe; then
              if [[ "${EUID:-$(id -u)}" -ne 0 ]] && have_cmd sudo; then
                run sudo modprobe vendor_reset 2>/dev/null || true
              else
                run modprobe vendor_reset 2>/dev/null || true
              fi
            fi
            if vendor_reset_is_present; then
              say "Installed vendor-reset from source (DKMS) in detect mode."
            else
              note "Source DKMS install completed, but module is not yet detected for this kernel."
              note "Reboot, then re-run --detect."
            fi
          else
            note "Source-based DKMS install failed."
            note "Install it manually, then re-run --detect."
          fi
        else
          note "Skipping source-based install (confirmation phrase not provided)."
        fi
      else
        note "Skipping source-based install."
      fi
    else
      note "Install it manually, then re-run --detect."
    fi
  fi
  DRY_RUN="$prev_dry"
}
lightdm_accountsservice_preflight() {
  # Guardrail based on observed failure mode:
  # LightDM exits with status=1 and start-limit-hit when org.freedesktop.Accounts is missing.
  if ! lightdm_is_present; then
    return 0
  fi
  if accountsservice_is_present; then
    return 0
  fi

  say
  hdr "LightDM dependency preflight"
  note "Detected LightDM, but AccountsService appears missing (org.freedesktop.Accounts)."
  note "This can cause a LightDM restart loop at boot (status=1 / start-limit-hit) even when VFIO binding is successful."
  note "Recommended: install accountsservice now."

  if prompt_yn "Install accountsservice now? (recommended)" Y "LightDM dependency"; then
    if install_accountsservice_pkg; then
      enable_accountsservice_unit || true
      if accountsservice_is_present; then
        say "Installed AccountsService for LightDM."
        return 0
      fi
      note "AccountsService install command returned success but service detection is still inconclusive."
    else
      note "Automatic accountsservice install failed (or package manager unavailable)."
    fi
  fi

  note "Applying LightDM fallback configuration to reduce reliance on AccountsService."
  if prompt_yn "Install LightDM fallback config (greeter-hide-users=true)?" Y "LightDM fallback"; then
    install_lightdm_accountsservice_fallback
    note "Fallback installed at $LIGHTDM_FALLBACK_CONF"
    note "If LightDM still fails, install AccountsService manually and reboot."
  fi
}

display_manager_dependency_preflight() {
  # Display-manager guardrail:
  # - LightDM gets explicit AccountsService + fallback checks.
  # - SDDM/GDM/LXDM/XDM are treated as supported without LightDM-specific fallback.
  local dm
  dm="$(detect_display_manager 2>/dev/null || true)"
  [[ -n "$dm" ]] || dm="none"

  case "$dm" in
    lightdm)
      lightdm_accountsservice_preflight
      ;;
    sddm|gdm|lxdm|xdm)
      say
      hdr "Display manager dependency preflight"
      note "Detected ${dm}; no LightDM-specific AccountsService fallback is required."
      ;;
    none)
      note "No display manager detected; skipping display-manager dependency preflight."
      ;;
    *)
      note "Detected display manager '${dm}'; no specific dependency preflight is implemented for it."
      ;;
  esac
}
graphics_protocol_preflight() {
  # This helper officially supports only X11(Xorg) and Wayland desktop stacks.
  # At least one stack must be fully WORKS for install mode.
  local xorg_status wayland_status support mode
  xorg_status="$(xorg_stack_status)"
  wayland_status="$(wayland_stack_status)"
  support="$(x11_wayland_support_status "$xorg_status" "$wayland_status")"
  mode="$(x11_wayland_supported_mode "$xorg_status" "$wayland_status")"

  say
  hdr "Graphics protocol preflight (X11/Wayland)"
  note "X11 (Xorg): $(format_tri_state_status "$xorg_status")"
  note "Wayland: $(format_tri_state_status "$wayland_status")"
  note "Supported protocol mode: $mode"

  if [[ "$support" != "WORKS" ]]; then
    die "Unsupported desktop stack state. This helper supports only X11 (Xorg) and Wayland, and requires at least one of them to be WORKS."
  fi
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
Usage: $SCRIPT_NAME [--debug] [--dry-run] [--no-tui] [--boot-vga-policy auto|strict] [--graphics-protocol auto|x11|wayland] [--graphics-daemon-interval seconds] [--no-graphics-daemon] [--verify] [--detect] [--sync-bls-only] [--debug-cmdline-tokens] [--entry pattern] [--verify-bls-sync] [--verify-bls-nosnapper] [--create-fallback-entry] [--print-effective-config] [--json] [--self-test] [--health-check] [--health-check-previous] [--health-check-all] [--usb-health-check] [--reset] [--disable-bootlog] [--boot-remove] [--install-bootlog] [--install-graphics-daemon] [--install-usb-bt-mitigation] [--print-fish-completion] [--print-bash-completion] [--print-zsh-completion]

  --debug           Enable verbose debug logging (and bash xtrace).
  --dry-run         Show actions but do not write files / run system-changing commands.
  --no-tui          Force plain-text prompts even if whiptail is installed.
  --boot-vga-policy Install-mode override for generated Boot-VGA policy:
                   auto (default behavior, dynamic host-assisted detection) or
                   strict (requires explicit VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1).
  --graphics-protocol
                   Install-mode graphics protocol override:
                   auto (default, protocol-agnostic), x11, or wayland.
  --graphics-daemon-interval
                   Set the independent graphics daemon polling interval in seconds
                   (valid range: 1-3600, default: $GRAPHICS_DAEMON_INTERVAL_DEFAULT).
  --no-graphics-daemon
                   Skip installation of the independent graphics protocol daemon service.
  --verify          Do not change anything; validate an existing setup (reads $CONF_FILE).
  --detect          Print a detailed report of existing VFIO/passthrough configuration and exit.
  --sync-bls-only   Non-interactive mode: sync BLS entry options from /etc/kernel/cmdline, then run strict drift verification.
                   Intended for openSUSE BLS/systemd-boot workflows and snapshot recovery.
  --debug-cmdline-tokens
                   Non-interactive read-only mode: trace baseline and per-entry root/rootflags source selection
                   used by sync_bls_entries_from_kernel_cmdline().
  --entry          Optional non-empty basename glob filter for --debug-cmdline-tokens (for example: system-*.conf).
  --verify-bls-sync Non-interactive regression check: verify BLS entry options against /etc/kernel/cmdline.
                   Prints final PASS/FAIL summary and exits non-zero on drift.
  --verify-bls-nosnapper
                   Non-interactive regression check: assert sync logic does not attempt writes to snapper-* BLS entries.
                   Prints final PASS/FAIL summary and exits non-zero on any snapper write attempt.
  --create-fallback-entry
                   Non-interactive mode: create or update a dedicated non-VFIO fallback Boot Loader Spec entry
                   from the current system entry by removing VFIO-forcing kernel parameters.
  --print-effective-config
                   Read-only report of effective Boot-VGA policy and runtime decision path
                   using $CONF_FILE plus current sysfs topology.
  --json            With --detect, print machine-readable JSON only (tri-state values: WORKS / NOT_WORK / NOT_PRESENT).
                   With --debug-cmdline-tokens, emit machine-readable JSON debug lines.
  --self-test       Run automated checks for common issues (awk compatibility, PipeWire access) and exit.
  --health-check    Audit the running kernel and logs for VFIO-friendliness (no changes made) and exit.
  --health-check-previous
                     Audit the PREVIOUS boot's kernel logs for VFIO-friendliness (no changes made) and exit.
  --usb-health-check
                   Audit current and previous boot kernel logs for USB/xHCI crash signatures and print optional stability mitigation guidance.
                   Tip: run with full kernel-log access: sudo ./$SCRIPT_NAME --usb-health-check
  --reset           Reset/remove VFIO passthrough settings installed by this script (systemd/modprobe/grub/initramfs/user units).
  --disable-bootlog Disable only the optional VFIO boot log dumper service/unit, keeping the rest of the VFIO setup intact.
  --boot-remove     Alias of --disable-bootlog.
  --install-bootlog Install/reinstall only the optional VFIO boot log dumper helper + systemd unit.
                   Useful after snapshot rollbacks where /etc systemd state differs from user-home helper state.
  --install-graphics-daemon
                   Install/reinstall only the VFIO graphics protocol daemon + systemd unit.
                   Useful for rolling out daemon/watchdog logic updates without re-running the full wizard.
  --install-usb-bt-mitigation
                   Install ONLY the optional USB Bluetooth reset-spam mitigation (systemd+udev). This detaches USB Bluetooth adapters from btusb on the host but keeps them available for VM passthrough.
  --print-fish-completion
                   Print fish completion script to stdout (no install required).
                   Example: source ($SCRIPT_NAME --print-fish-completion)
  --print-bash-completion
                   Print bash completion script to stdout (no install required).
                   Example: source <($SCRIPT_NAME --print-bash-completion)
  --print-zsh-completion
                   Print zsh completion script to stdout (no install required).
                   Example: source <($SCRIPT_NAME --print-zsh-completion)
EOF
}

normalize_boot_vga_policy_arg() {
  local raw="${1:-}" val
  val="${raw^^}"
  case "$val" in
    AUTO|STRICT)
      printf '%s\n' "$val"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}
normalize_graphics_protocol_arg() {
  local raw="${1:-}" val
  val="${raw^^}"
  case "$val" in
    AUTO|X11|WAYLAND)
      printf '%s\n' "$val"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}
normalize_graphics_daemon_interval_arg() {
  local raw="${1:-}"
  [[ "$raw" =~ ^[0-9]+$ ]] || return 1
  if (( 10#$raw < 1 || 10#$raw > 3600 )); then
    return 1
  fi
  printf '%s\n' "$((10#$raw))"
}
normalize_debug_cmdline_entry_filter_arg() {
  local raw="${1:-}" trimmed
  trimmed="$(trim "$raw")"
  [[ -n "$trimmed" ]] || return 1
  printf '%s\n' "$raw"
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
      --boot-vga-policy)
        shift
        (( $# > 0 )) || die "--boot-vga-policy requires a value: auto|strict"
        BOOT_VGA_POLICY_OVERRIDE="$(normalize_boot_vga_policy_arg "$1")" || die "Invalid --boot-vga-policy value: $1 (expected: auto|strict)"
        ;;
      --boot-vga-policy=*)
        BOOT_VGA_POLICY_OVERRIDE="$(normalize_boot_vga_policy_arg "${1#*=}")" || die "Invalid --boot-vga-policy value: ${1#*=} (expected: auto|strict)"
        ;;
      --graphics-protocol)
        shift
        (( $# > 0 )) || die "--graphics-protocol requires a value: auto|x11|wayland"
        GRAPHICS_PROTOCOL_OVERRIDE="$(normalize_graphics_protocol_arg "$1")" || die "Invalid --graphics-protocol value: $1 (expected: auto|x11|wayland)"
        ;;
      --graphics-protocol=*)
        GRAPHICS_PROTOCOL_OVERRIDE="$(normalize_graphics_protocol_arg "${1#*=}")" || die "Invalid --graphics-protocol value: ${1#*=} (expected: auto|x11|wayland)"
        ;;
      --graphics-daemon-interval)
        shift
        (( $# > 0 )) || die "--graphics-daemon-interval requires a value: 1-3600"
        GRAPHICS_DAEMON_INTERVAL_OVERRIDE="$(normalize_graphics_daemon_interval_arg "$1")" || die "Invalid --graphics-daemon-interval value: $1 (expected integer range 1-3600)"
        ;;
      --graphics-daemon-interval=*)
        GRAPHICS_DAEMON_INTERVAL_OVERRIDE="$(normalize_graphics_daemon_interval_arg "${1#*=}")" || die "Invalid --graphics-daemon-interval value: ${1#*=} (expected integer range 1-3600)"
        ;;
      --no-graphics-daemon)
        INSTALL_GRAPHICS_DAEMON=0
        ;;
      --verify)
        MODE="verify"
        ;;
      --detect)
        MODE="detect"
        ;;
      --sync-bls-only)
        MODE="sync-bls-only"
        ;;
      --debug-cmdline-tokens)
        MODE="debug-cmdline-tokens"
        ;;
      --entry)
        shift
        (( $# > 0 )) || die "--entry requires a basename glob pattern (example: system-*.conf)"
        DEBUG_CMDLINE_TOKENS_ENTRY_FILTER="$(normalize_debug_cmdline_entry_filter_arg "$1")" || die "Invalid --entry value: $1 (expected non-empty basename glob pattern, example: system-*.conf)"
        ;;
      --entry=*)
        DEBUG_CMDLINE_TOKENS_ENTRY_FILTER="$(normalize_debug_cmdline_entry_filter_arg "${1#*=}")" || die "Invalid --entry value: ${1#*=} (expected non-empty basename glob pattern, example: system-*.conf)"
        ;;
      --verify-bls-sync)
        MODE="verify-bls-sync"
        ;;
      --verify-bls-nosnapper)
        MODE="verify-bls-nosnapper"
        ;;
      --create-fallback-entry)
        MODE="create-fallback-entry"
        ;;
      --print-effective-config)
        MODE="print-effective-config"
        ;;
      --json)
        JSON_OUTPUT=1
        ;;
      --self-test)
        MODE="self-test"
        ;;
      --health-check)
        MODE="health-check"
        ;;
      --health-check-previous)
        MODE="health-check-prev"
        ;;
      --health-check-all)
        MODE="health-check-all"
        ;;
      --usb-health-check)
        MODE="usb-health-check"
        ;;
      --reset)
        MODE="reset"
        ;;
      --disable-bootlog)
        MODE="disable-bootlog"
        ;;
      --boot-remove)
        MODE="disable-bootlog"
        ;;
      --install-bootlog)
        MODE="install-bootlog"
        ;;
      --install-graphics-daemon)
        MODE="install-graphics-daemon"
        ;;
      --install-usb-bt-mitigation)
        MODE="install-usb-bt-mitigation"
        ;;
      --print-fish-completion)
        MODE="print-fish-completion"
        ;;
      --print-bash-completion)
        MODE="print-bash-completion"
        ;;
      --print-zsh-completion)
        MODE="print-zsh-completion"
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

  # verify/detect/self-test/print-effective-config/completion modes imply dry-run
  if [[ "$MODE" == "verify" || "$MODE" == "detect" || "$MODE" == "debug-cmdline-tokens" || "$MODE" == "verify-bls-sync" || "$MODE" == "verify-bls-nosnapper" || "$MODE" == "self-test" || "$MODE" == "print-effective-config" || "$MODE" == "print-fish-completion" || "$MODE" == "print-bash-completion" || "$MODE" == "print-zsh-completion" ]]; then
    DRY_RUN=1
  fi

  if (( JSON_OUTPUT )) && [[ "$MODE" != "detect" && "$MODE" != "debug-cmdline-tokens" ]]; then
    die "--json is currently supported only with --detect or --debug-cmdline-tokens"
  fi
  if [[ -n "${DEBUG_CMDLINE_TOKENS_ENTRY_FILTER:-}" ]] && [[ "$MODE" != "debug-cmdline-tokens" ]]; then
    die "--entry is supported only with --debug-cmdline-tokens"
  fi
}

json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

debug_cmdline_tokens_print_json_lines() {
  local raw_output="${1:-}" exit_code="${2:-0}"
  local filter="${DEBUG_CMDLINE_TOKENS_ENTRY_FILTER:-}"
  local -a lines=()
  local idx line
  if [[ -n "$raw_output" ]]; then
    mapfile -t lines <<<"$raw_output"
  fi

  printf '{\n'
  printf '  "mode": "debug-cmdline-tokens",\n'
  printf '  "entry_filter": "%s",\n' "$(json_escape "$filter")"
  printf '  "exit_code": %s,\n' "$exit_code"
  printf '  "lines": [\n'
  for idx in "${!lines[@]}"; do
    line="${lines[$idx]}"
    printf '    "%s"' "$(json_escape "$line")"
    if (( idx + 1 < ${#lines[@]} )); then
      printf ','
    fi
    printf '\n'
  done
  printf '  ]\n'
  printf '}\n'
}

# Disable and remove the optional VFIO boot log dumper without touching the
# rest of the VFIO configuration.
disable_bootlog_dumper() {
  hdr "Disable VFIO boot log dumper"

  local unit="/etc/systemd/system/vfio-dump-boot-log.service"
  local bin
  bin="$(bootlog_bin_path)"

  if ! [[ -f "$unit" || -f "$bin" ]]; then
    note "Boot log dumper unit/script not found; nothing to disable."
    return 0
  fi

  if command -v systemctl >/dev/null 2>&1 && [[ -f "$unit" ]]; then
    note "Disabling and stopping vfio-dump-boot-log.service (VFIO setup will remain active)."
    run systemctl disable --now vfio-dump-boot-log.service 2>/dev/null || true
    run systemctl daemon-reload 2>/dev/null || true
  elif ! command -v systemctl >/dev/null 2>&1; then
    note "systemctl not found; disabling the service automatically is not possible."
  fi

  # Remove the unit and helper script (if present). This mirrors the paths
  # used by install_bootlog_dumper and reset_vfio_all.
  run rm -f "$unit" "$bin" 2>/dev/null || true

  say "Boot log dumper disabled and removed. Existing log files under ~/Desktop/vfio-boot-logs are left untouched."
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
write_file_atomic_if_changed() {
  # write_file_atomic_if_changed /path mode owner:group [backup_existing]
  # Returns:
  #   0 -> file content changed and was written (or would be written in DRY_RUN)
  #   1 -> destination already had identical content; write skipped
  local dst="$1" mode="$2" owner_group="$3" backup_existing="${4:-0}"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"

  if [[ -f "$dst" ]] && have_cmd cmp && cmp -s "$tmp" "$dst"; then
    rm -f "$tmp" || true
    return 1
  fi

  if (( backup_existing )) && [[ -f "$dst" ]]; then
    backup_file "$dst"
  fi
  if (( DRY_RUN )); then
    rm -f "$tmp" || true
    return 0
  fi
  install -o "${owner_group%%:*}" -g "${owner_group##*:}" -m "$mode" "$tmp" "$dst"
  rm -f "$tmp" || true
  return 0
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

pci_boot_vga_flag() {
  # Returns:
  #   1 / 0 when boot_vga is available for this PCI BDF
  #   unknown when sysfs does not expose boot_vga for this device
  local bdf="$1"
  local f="/sys/bus/pci/devices/$bdf/boot_vga"
  if [[ -f "$f" ]]; then
    cat "$f" 2>/dev/null || echo "unknown"
    return 0
  fi
  echo "unknown"
  return 0
}

host_assisted_boot_vga_policy_default() {
  # Auto-enable host-assisted Boot-VGA bind only when:
  # - guest GPU is Boot VGA (1)
  # - host GPU is a different adapter with boot_vga=0
  local host_gpu="$1"
  local guest_gpu="$2"
  [[ -n "$host_gpu" && -n "$guest_gpu" ]] || { echo "0"; return 0; }
  [[ "$host_gpu" != "$guest_gpu" ]] || { echo "0"; return 0; }

  local host_boot_vga guest_boot_vga
  host_boot_vga="$(pci_boot_vga_flag "$host_gpu")"
  guest_boot_vga="$(pci_boot_vga_flag "$guest_gpu")"

  if [[ "$guest_boot_vga" == "1" && "$host_boot_vga" == "0" ]]; then
    echo "1"
    return 0
  fi
  echo "0"
  return 0
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
      local snd card_id
      for snd in /sys/bus/pci/devices/"$audio_bdf"/sound/card*; do
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
        # keep this mitigation explicitly opt-in on openSUSE, because it can
        # over-constrain display init on snapshot-heavy rollback workflows.
        local fb_prompt_default="Y"
        if is_opensuse_like; then
          fb_prompt_default="N"
          note "openSUSE detected: framebuffer-disable flags stay opt-in by default. Enable only if you confirm framebuffer lock symptoms."
        fi
        if prompt_yn "Add '$fb_param' to boot kernel parameters?" "$fb_prompt_default" "Boot framebuffer options"; then
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
resolve_desktop_user_home() {
  # Resolve the primary desktop user and home directory.
  # 1) Prefer SUDO_USER when valid and mapped to an existing home.
  # 2) Fallback to first non-system user with an existing /home/* directory.
  local home user uid shell

  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    home="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)"
    if [[ -n "$home" && -d "$home" ]]; then
      printf '%s\t%s\n' "$SUDO_USER" "$home"
      return 0
    fi
  fi

  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    (( uid >= 1000 )) || continue
    [[ "$user" == "nobody" ]] && continue
    [[ -n "$home" && "$home" == /home/* && -d "$home" ]] || continue
    case "$shell" in
      */false|*/nologin) continue ;;
    esac
    printf '%s\t%s\n' "$user" "$home"
    return 0
  done </etc/passwd

  return 1
}

bootlog_bin_path() {
  local pair home
  pair="$(resolve_desktop_user_home 2>/dev/null || true)"
  if [[ -n "$pair" ]]; then
    home="${pair#*$'\t'}"
    [[ -n "$home" ]] && { printf '%s\n' "$home/.local/bin/vfio-dump-boot-log.sh"; return 0; }
  fi
  printf '%s\n' "/home/${SUDO_USER:-root}/.local/bin/vfio-dump-boot-log.sh"
}
report_vm_network_precheck() {
  # Detect a common host-side cause of "VM has no internet":
  # net.ipv4.ip_forward=0 while using libvirt NAT (virbr0/default network).
  # This is informational and does not change system state.
  say
  if (( ENABLE_COLOR )); then
    say "${C_CYAN}-- VM internet precheck (libvirt / virt-manager) --${C_RESET}"
  else
    say "-- VM internet precheck (libvirt / virt-manager) --"
  fi

  local ip4_fwd="unknown" ip6_fwd="unknown"
  if [[ -r /proc/sys/net/ipv4/ip_forward ]]; then
    read -r ip4_fwd </proc/sys/net/ipv4/ip_forward || ip4_fwd="unknown"
  fi
  if [[ -r /proc/sys/net/ipv6/conf/all/forwarding ]]; then
    read -r ip6_fwd </proc/sys/net/ipv6/conf/all/forwarding || ip6_fwd="unknown"
  fi

  local virbr0_state="missing"
  if [[ -d /sys/class/net/virbr0 ]]; then
    virbr0_state="present"
  fi

  local sysctl_zero_file=""
  if [[ -f /etc/sysctl.d/70-yast.conf ]] && \
     grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*0([[:space:]]|$)' /etc/sysctl.d/70-yast.conf; then
    sysctl_zero_file="/etc/sysctl.d/70-yast.conf"
  elif [[ -d /etc/sysctl.d ]]; then
    local sf
    shopt -s nullglob
    for sf in /etc/sysctl.d/*.conf; do
      if grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*0([[:space:]]|$)' "$sf"; then
        sysctl_zero_file="$sf"
        break
      fi
    done
    shopt -u nullglob
  fi

  print_kv "virbr0 bridge" "$virbr0_state"
  print_kv "net.ipv4.ip_forward" "$ip4_fwd"
  print_kv "net.ipv6.forwarding" "$ip6_fwd"

  if [[ "$ip4_fwd" == "0" ]]; then
    if (( ENABLE_COLOR )); then
      say "${C_YELLOW}WARN${C_RESET}: net.ipv4.ip_forward=0 can break VM internet on libvirt NAT (guest gets DHCP but no outbound internet)."
    else
      say "WARN: net.ipv4.ip_forward=0 can break VM internet on libvirt NAT (guest gets DHCP but no outbound internet)."
    fi
    note "Fix now (temporary): sudo sysctl -w net.ipv4.ip_forward=1"
    if [[ -n "$sysctl_zero_file" ]]; then
      note "Persistent blocker found: $sysctl_zero_file sets net.ipv4.ip_forward = 0"
      note "Set it to: net.ipv4.ip_forward = 1, then run: sudo sysctl --system"
    else
      note "Persistent fix: set net.ipv4.ip_forward = 1 in /etc/sysctl.d/*.conf, then run: sudo sysctl --system"
    fi
    return 1
  fi

  if [[ "$virbr0_state" == "missing" ]]; then
    note "INFO: virbr0 bridge is missing. If you use virt-manager NAT, start/autostart the default libvirt network."
    note "Try: sudo virsh -c qemu:///system net-start default && sudo virsh -c qemu:///system net-autostart default"
  fi

  if (( ENABLE_COLOR )); then
    say "${C_GREEN}OK${C_RESET}: no obvious host forwarding blocker detected for libvirt NAT networking."
  else
    say "OK: no obvious host forwarding blocker detected for libvirt NAT networking."
  fi
  return 0
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

# Plymouth splash can keep GPUs/DRM devices busy during early boot on some
# desktop setups (especially KDE Plasma + Wayland), which can interfere with
# vfio-pci claiming the guest GPU. We disable Plymouth in two ways:
#  1) kernel cmdline: rd.plymouth=0 plymouth.enable=0 and remove splash tokens
#  2) systemd: mask common plymouth unit names (best-effort)
plymouth_units() {
  # Print a whitespace-separated list of common Plymouth unit names.
  # (Not all distros ship all of these.)
  printf '%s\n' \
    plymouth-start.service \
    plymouth-read-write.service \
    plymouth-quit.service \
    plymouth-quit-wait.service \
    plymouth-switch-root.service \
    plymouth-halt.service \
    plymouth-reboot.service
}

disable_plymouth_services() {
  have_cmd systemctl || return 0

  note "Disabling Plymouth boot splash (masking plymouth systemd units; best-effort)."

  local u
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    # Mask each unit individually so one missing unit doesn't prevent the rest.
    run systemctl mask --now "$u" 2>/dev/null || true
  done < <(plymouth_units)

  run systemctl daemon-reload 2>/dev/null || true
}

unmask_plymouth_services() {
  have_cmd systemctl || return 0

  note "Re-enabling Plymouth (unmasking plymouth systemd units; best-effort)."

  local u
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    run systemctl unmask "$u" 2>/dev/null || true
  done < <(plymouth_units)

  run systemctl daemon-reload 2>/dev/null || true
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

# Return 0 if any of the typical early framebuffers (simpledrm/sysfb/efifb/
# vesafb) appear as reserved memory in /proc/iomem. This is a strong hint
# that the boot console is still attached to the GPU and can interfere with
# VFIO binding.
simplefb_lock_active() {
  grep -qiE '(simple-framebuffer|simpledrm|efifb|vesafb|EFI Framebuffer)' /proc/iomem 2>/dev/null
}

# Return 0 if we detect that the GPU's BARs are mapped above the 4G
# boundary. This is a strong indication that "Above 4G Decoding" (a.k.a.
# 64-bit BAR support / Large BAR) is effectively active for this device.
#
# We consider Above 4G Decoding to be effectively enabled when at least
# one Memory BAR for the device has an address whose hex representation
# is longer than 8 characters (i.e. above 0xFFFFFFFF).
above_4g_decoding_enabled_for_bdf() {
  local bdf="$1"
  have_cmd lspci || return 1

  # Use -v (not -vv) to keep output smaller; region lines are the same.
  local line addr raw
  while read -r line; do
    # Typical line: "Region 0: Memory at 380000000000 (64-bit, prefetchable)"
    if [[ "$line" == *"Memory at"* ]]; then
      # Third field is the hex address right after "Memory" and "at".
      raw="$(awk '{print $3}' <<<"$line")"
      # Strip anything after an opening parenthesis, just in case.
      addr="${raw%%(*}"
      # Strip any 0x prefix if present (some lspci builds may add it).
      addr="${addr#0x}"
      # If the hex string is longer than 8 characters, it's above 4G.
      if [[ ${#addr} -gt 8 ]]; then
        return 0
      fi
    fi
  done < <(lspci -v -s "$bdf" 2>/dev/null || true)

  return 1
}

# Human-readable Above 4G Decoding status string for a given BDF.
above_4g_decoding_status_for_bdf() {
  local bdf="$1"
  have_cmd lspci || { echo "unknown (lspci missing)"; return 0; }
  if above_4g_decoding_enabled_for_bdf "$bdf"; then
    echo "ENABLED (GPU BARs mapped above 4GB)"
  else
    echo "DISABLED or not used (all GPU BARs fit under 4GB)"
  fi
}

# Return 0 if lspci reports that Resizable BAR is enabled for this PCI
# device. We use this as a heuristic because large BARs combined with some
# vendor drivers/firmware combinations have been observed to cause black
# screens or other instability when doing GPU passthrough on certain
# consumer platforms.
rebar_enabled_for_bdf() {
  local bdf="$1"
  have_cmd lspci || return 1
  # If capabilities are not readable (for example when bound to vfio-pci),
  # lspci prints "Capabilities: <access denied>" and we cannot reliably
  # determine ReBAR state. In that case we return 1 ("not confirmed") and
  # higher-level callers should avoid claiming it is disabled.
  local out
  out="$(lspci -s "$bdf" -vv 2>/dev/null || true)"
  [[ -n "$out" ]] || return 1
  if grep -q 'Capabilities: <access denied>' <<<"$out"; then
    return 1
  fi
  # Look for a "Resizable BAR" capability block mentioning "Enabled" for
  # at least one BAR on this device.
  if printf '%s\n' "$out" | awk '/Resizable BAR/{flag=1;next} /^[^[:space:]]/{flag=0} flag{print}' | grep -qi 'Enabled'; then
    return 0
  fi
  return 1
}

# Human-readable ReBAR status string for a given BDF. Unlike
# rebar_enabled_for_bdf(), this does not try to return a boolean; instead it
# describes what we can see from lspci in a way that is safe when the device
# is already bound to vfio-pci and capabilities are not readable.
rebar_status_for_bdf() {
  local bdf="$1"
  have_cmd lspci || { echo "unknown (lspci missing)"; return 0; }

  local out
  out="$(lspci -s "$bdf" -vv 2>/dev/null || true)"
  [[ -n "$out" ]] || { echo "unknown (device not found)"; return 0; }

  if grep -q 'Capabilities: <access denied>' <<<"$out"; then
    echo "unknown (PCI capabilities not readable; device is likely bound to vfio-pci)"
    return 0
  fi

  local bar_block
  bar_block="$(printf '%s\n' "$out" | awk '/Resizable BAR/{flag=1;next} /^[^[:space:]]/{flag=0} flag{print}')"
  if [[ -z "$bar_block" ]]; then
    echo "not reported"
    return 0
  fi

  if grep -qi 'Enabled' <<<"$bar_block"; then
    echo "ENABLED"
  else
    # We can see a Resizable BAR capability block but no BAR marked
    # as "Enabled". All we can state with certainty is what lspci
    # shows for this device.
    echo "present (lspci does not show any BAR as Enabled for this device)"
  fi
}
extract_drm_panic_registration_lines() {
  # DRM panic registration lines are informational (panic handler registration),
  # not proof of a real kernel panic.
  local logs="${1:-}"
  [[ -n "$logs" ]] || return 0
  printf '%s\n' "$logs" | grep -E '\[drm\] Registered [0-9]+ planes with drm panic' || true
}

extract_real_kernel_panic_lines() {
  # Strong panic/oops signatures only (avoid broad false positives).
  local logs="${1:-}"
  [[ -n "$logs" ]] || return 0
  printf '%s\n' "$logs" | grep -Ei '(Kernel panic - not syncing|BUG: unable to handle kernel|Oops:|general protection fault:|fatal exception)' || true
}

# Audit whether the *currently running* kernel looks hostile to VFIO for the
# selected guest GPU. This is a diagnostic only; it does not change any
# configuration. Results are summarized in CTX[kernel_vfio_risk]:
#   0 = no obvious risk markers detected
#   1 = one or more risk markers detected (kernel version, IOMMU, logs, etc.)
#
# Additionally CTX[kernel_vfio_log_error]=1 is set if we find concrete
# vfio-pci probe/BAR errors in the logs.
#
# If a GPU BDF is supplied, we also check who currently owns the device.
# This is most useful AFTER you have already tried to boot with VFIO enabled.
audit_vfio_health() {
  local gpu_bdf="${1:-}"

  hdr "VFIO Kernel Health Audit"

  CTX[kernel_vfio_risk]=0
  CTX[kernel_vfio_log_error]=0
  CTX[kernel_vfio_env_ok]=1

  # 1) Kernel version is now treated as informational only. Static
  # version-based "high risk" heuristics (for example ">= 6.13 is bad")
  # are fragile once distributions ship fixes. Real regression detection
  # is handled via the log-based checks further below.
  local kver
  kver="$(uname -r 2>/dev/null || echo unknown)"
  if (( ENABLE_COLOR )); then
    say "${C_GREEN}INFO${C_RESET}: Running kernel: $kver"
  else
    say "INFO: Running kernel: $kver"
  fi

  # 2) Check IOMMU and VFIO module availability.
  say
  say "Checking IOMMU and VFIO module availability ..."

  if [[ -d /sys/kernel/iommu_groups ]] && ls /sys/kernel/iommu_groups/* >/dev/null 2>&1; then
    say "OK: IOMMU groups directory present."
  else
    CTX[kernel_vfio_risk]=1
    CTX[kernel_vfio_env_ok]=0
    say "WARN: /sys/kernel/iommu_groups missing or empty (IOMMU may be disabled in BIOS or kernel cmdline)."
  fi

  if vfio_pci_available; then
    say "OK: vfio-pci module is available for this kernel."
  else
    CTX[kernel_vfio_risk]=1
    CTX[kernel_vfio_env_ok]=0
    say "WARN: vfio-pci module not found by modinfo; VFIO GPU binding cannot work on this kernel."
  fi

  # 3) Runtime owner of the GPU (if a BDF was provided). This is *not* a
  # definitive regression check on its own because before the first reboot
  # we still expect the host driver to own the device. It is mostly useful
  # when you run this audit AFTER a failed VFIO boot.
  if [[ -n "$gpu_bdf" ]]; then
    say
    say "Checking current driver for GPU $gpu_bdf ..."
    if [[ ! -e "/sys/bus/pci/devices/$gpu_bdf" ]]; then
      CTX[kernel_vfio_risk]=1
      if (( ENABLE_COLOR )); then
        say "${C_YELLOW}WARN${C_RESET}: PCI device $gpu_bdf not present in sysfs (hot-unplugged or wrong BDF?)."
      else
        say "WARN: PCI device $gpu_bdf not present in sysfs (hot-unplugged or wrong BDF?)."
      fi
    elif [[ ! -e "/sys/bus/pci/devices/$gpu_bdf/driver" ]]; then
      CTX[kernel_vfio_risk]=1
      if (( ENABLE_COLOR )); then
        say "${C_YELLOW}WARN${C_RESET}: Device is not bound to ANY driver right now."
      else
        say "WARN: Device is not bound to ANY driver right now."
      fi
    else
      local driver_path driver_name
      driver_path="$(readlink -f "/sys/bus/pci/devices/$gpu_bdf/driver" 2>/dev/null || true)"
      driver_name="${driver_path##*/}"
      if [[ "$driver_name" == "vfio-pci" ]]; then
        if (( ENABLE_COLOR )); then
          say "${C_GREEN}OK${C_RESET}: GPU $gpu_bdf is currently bound to vfio-pci."
        else
          say "OK: GPU $gpu_bdf is currently bound to vfio-pci."
        fi
      else
        # Not necessarily a regression (especially before the first reboot),
        # but worth surfacing.
        if (( ENABLE_COLOR )); then
          say "${C_YELLOW}INFO${C_RESET}: GPU $gpu_bdf is currently bound to '$driver_name' (not vfio-pci)."
        else
          say "INFO: GPU $gpu_bdf is currently bound to '$driver_name' (not vfio-pci)."
        fi
      fi
    fi
  fi

  # 4) Check for active simpledrm/sysfb/efifb/vesafb locks.
  say
  say "Checking for active system framebuffers (simpledrm/sysfb/efifb/vesafb) ..."
  if simplefb_lock_active; then
    CTX[kernel_vfio_risk]=1
    CTX[kernel_vfio_env_ok]=0
    if (( ENABLE_COLOR )); then
      say "${C_YELLOW}WARN${C_RESET}: A system framebuffer (simpledrm/sysfb/efifb/vesafb) is active in /proc/iomem."
    else
      say "WARN: A system framebuffer (simpledrm/sysfb/efifb/vesafb) is active in /proc/iomem."
    fi
    note "This often means the boot console is still attached to the GPU and can block vfio-pci from claiming it."
    note "Consider enabling the framebuffer mitigation options (video=efifb:off video=vesafb:off initcall_blacklist=sysfb_init)."
  else
    say "OK: No obvious simpledrm/sysfb/efifb/vesafb regions in /proc/iomem."
  fi

  # 5) Log scan for typical vfio-pci BAR / probe failures. These are
  # strong indicators that the kernel (or another early driver like
  # simpledrm/sysfb) refused to give vfio-pci ownership of the device.
  say
  say "Scanning kernel logs for vfio-pci probe / BAR reservation errors ..."

  local log_data
  if have_cmd journalctl; then
    # Allow callers to choose which boot to inspect via VFIO_HEALTH_BOOT_OFFSET.
    #  0 or unset: current boot (-b)
    # -1: previous boot (-b -1)
    local boot_opt="-b"
    if [[ -n "${VFIO_HEALTH_BOOT_OFFSET:-}" ]]; then
      if [[ "${VFIO_HEALTH_BOOT_OFFSET}" =~ ^-?[0-9]+$ && "${VFIO_HEALTH_BOOT_OFFSET}" != "0" ]]; then
        boot_opt="-b${VFIO_HEALTH_BOOT_OFFSET}"
      fi
    fi
    log_data="$(journalctl -k "${boot_opt}" --no-pager 2>/dev/null || true)"
  else
    if ! have_cmd dmesg; then
      say "No journalctl or dmesg command available; skipping log-based checks."
      log_data=""
    else
      log_data="$(dmesg 2>/dev/null || true)"
    fi
  fi

  local dmesg_filter dmesg_out
  if [[ -n "$gpu_bdf" ]]; then
    # Match either the full BDF or just the slot (some messages only print slot)
    dmesg_filter="$(printf '%s' "$gpu_bdf" | sed 's/\\./:/')"
  else
    dmesg_filter="vfio-pci"
  fi

  if [[ -n "$log_data" ]]; then
    local drm_panic_lines real_panic_lines
    drm_panic_lines="$(extract_drm_panic_registration_lines "$log_data")"
    real_panic_lines="$(extract_real_kernel_panic_lines "$log_data")"

    if [[ -n "$real_panic_lines" ]]; then
      CTX[kernel_vfio_risk]=1
      CTX[kernel_vfio_log_error]=1
      if (( ENABLE_COLOR )); then
        say "${C_RED}CRITICAL${C_RESET}: Real kernel panic/oops markers were detected in kernel logs."
      else
        say "CRITICAL: Real kernel panic/oops markers were detected in kernel logs."
      fi
      say "--- panic markers ---"
      printf '%s\n' "$real_panic_lines"
      say "---------------------"
    elif [[ -n "$drm_panic_lines" ]]; then
      if (( ENABLE_COLOR )); then
        say "${C_BLUE}INFO${C_RESET}: Detected DRM panic-handler registration lines."
      else
        say "INFO: Detected DRM panic-handler registration lines."
      fi
      note "\"[drm] Registered ... with drm panic\" means the DRM panic handler is available; it is not a kernel panic by itself."
    fi
    # Filter for vfio-pci messages that are strongly indicative of BAR or
    # probe failures for this device. We intentionally avoid generic
    # "error" matches here to reduce false positives across distros.
    dmesg_out="$(printf '%s\n' "$log_data" \
      | grep -i "vfio-pci" \
      | grep -Ei "(BAR|cannot reserve|can't reserve|probe|failed to (enable|assign))" \
      | grep -i "$dmesg_filter" || true)"
  else
    dmesg_out=""
  fi

  if [[ -n "$dmesg_out" ]]; then
    CTX[kernel_vfio_risk]=1
    CTX[kernel_vfio_log_error]=1
    if (( ENABLE_COLOR )); then
      say "${C_RED}CRITICAL${C_RESET}: Detected vfio-pci probe/BAR errors in kernel logs that match this GPU/kernel."
    else
      say "CRITICAL: Detected vfio-pci probe/BAR errors in kernel logs that match this GPU/kernel."
    fi
    say "--- log matches ---"
    printf '%s\n' "$dmesg_out"
    say "-------------------"
    note "This strongly suggests the simpledrm/sysfb regression where the kernel refuses to release the GPU BARs to vfio-pci."
  else
    if (( ENABLE_COLOR )); then
      say "${C_GREEN}OK${C_RESET}: No obvious vfio-pci probe/BAR reservation errors found in current boot logs."
    else
      say "OK: No obvious vfio-pci probe/BAR reservation errors found in current boot logs."
    fi
  fi

  # 6) Final summary + exit code grading for --health-check.
  local risk="${CTX[kernel_vfio_risk]:-0}"
  local log_bad="${CTX[kernel_vfio_log_error]:-0}"
  local env_ok="${CTX[kernel_vfio_env_ok]:-1}"

  say
  if (( risk == 0 )); then
    if (( ENABLE_COLOR )); then
      say "${C_GREEN}✔ HEALTH: PASS${C_RESET} (no obvious VFIO-hostile markers detected)"
      say "${C_GREEN}Kernel regression (known VFIO/simpledrm issue): NO${C_RESET}"
      if (( env_ok == 1 )); then
        say "${C_GREEN}VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): YES${C_RESET}"
      else
        say "${C_YELLOW}VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): NO${C_RESET}"
      fi
    else
      say "HEALTH: PASS (no obvious VFIO-hostile markers detected)"
      say "Kernel regression (known VFIO/simpledrm issue): NO"
      if (( env_ok == 1 )); then
        say "VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): YES"
      else
        say "VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): NO"
      fi
    fi
    return 0
  elif (( log_bad == 1 )); then
    if (( ENABLE_COLOR )); then
      say "${C_RED}✖ HEALTH: FAIL${C_RESET} (critical kernel log errors seen: vfio-pci probe/BAR or panic/oops markers)"
      say "${C_RED}Kernel regression (known VFIO/simpledrm issue): YES${C_RESET}"
      if (( env_ok == 1 )); then
        say "${C_GREEN}VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): YES${C_RESET}"
      else
        say "${C_YELLOW}VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): NO${C_RESET}"
      fi
    else
      say "HEALTH: FAIL (critical kernel log errors seen: vfio-pci probe/BAR or panic/oops markers)"
      say "Kernel regression (known VFIO/simpledrm issue): YES"
      if (( env_ok == 1 )); then
        say "VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): YES"
      else
        say "VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): NO"
      fi
    fi
    return 2
  else
    if (( ENABLE_COLOR )); then
      say "${C_YELLOW}⚠ HEALTH: WARN${C_RESET} (one or more VFIO risk markers detected; no hard vfio-pci errors yet)"
      say "${C_YELLOW}Kernel regression (known VFIO/simpledrm issue): NO (no vfio-pci BAR/probe failures found for this GPU)${C_RESET}"
      if (( env_ok == 1 )); then
        say "${C_GREEN}VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): YES${C_RESET}"
      else
        say "${C_YELLOW}VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): NO${C_RESET}"
      fi
    else
      say "HEALTH: WARN (one or more VFIO risk markers detected; no hard vfio-pci errors yet)"
      say "Kernel regression (known VFIO/simpledrm issue): NO (no vfio-pci BAR/probe failures found for this GPU)"
      if (( env_ok == 1 )); then
        say "VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): YES"
      else
        say "VFIO environment OK (IOMMU, vfio-pci, no framebuffer lock): NO"
      fi
    fi
    return 1
  fi
}

# Run a VFIO kernel health audit for all detected GPUs. Exit code is the
# worst status across all devices: 0=all PASS, 1=at least one WARN, 2=at
# least one FAIL.
health_check_all() {
  hdr "VFIO Kernel Health Audit (all GPUs)"

  local -a gpu_bdfs=()
  local gpu_bdf gpu_desc vendor_id device_id_unused audio_csv audio_descs
  while IFS=$'\t' read -r gpu_bdf gpu_desc vendor_id device_id_unused audio_csv audio_descs; do
    [[ -n "${gpu_bdf:-}" ]] || continue
    : "${device_id_unused:-}"
    gpu_bdfs+=("$gpu_bdf")
  done < <(gpu_discover_all_sysfs)

  if (( ${#gpu_bdfs[@]} == 0 )); then
    say "No GPUs found via sysfs; nothing to audit."
    return 1
  fi

  local worst=0 ec
  for gpu_bdf in "${gpu_bdfs[@]}"; do
    say
    say "=== GPU ${gpu_bdf} ==="
    if audit_vfio_health "$gpu_bdf"; then
      ec=0
    else
      ec=$?
    fi
    if (( ec > worst )); then
      worst=$ec
    fi
  done

  say
  case "$worst" in
    0)
      say "Overall health (all GPUs): PASS"
      ;;
    1)
      say "Overall health (all GPUs): WARN (at least one GPU reported VFIO risk markers)"
      ;;
    2)
      say "Overall health (all GPUs): FAIL (at least one GPU reported critical kernel log errors: vfio-pci or panic/oops markers)"
      ;;
  esac
  return "$worst"
}
usb_health_check() {
  hdr "USB/xHCI Stability Health Audit"
  note "This audit scans kernel logs for USB host-controller crash signatures and common instability markers."
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    note "Tip: for full log visibility, rerun with sudo: sudo ./$SCRIPT_NAME --usb-health-check"
  fi

  local worst=0
  local inspected=0
  local -a labels=("current boot" "previous boot")
  local -a boot_opts=("-b" "-b -1")
  local i label boot_opt log_data log_source
  local crash_count timeout_count enum_err_count disconnect_count netdev_watchdog_count score

  for i in "${!labels[@]}"; do
    label="${labels[$i]}"
    boot_opt="${boot_opts[$i]}"
    log_data=""
    log_source=""

    if have_cmd journalctl; then
      if [[ "$boot_opt" == "-b -1" ]]; then
        log_data="$(journalctl -k -b -1 --no-pager 2>/dev/null || true)"
        [[ -n "$log_data" ]] && log_source="journalctl -k -b -1"
      else
        log_data="$(journalctl -k -b --no-pager 2>/dev/null || true)"
        [[ -n "$log_data" ]] && log_source="journalctl -k -b"
      fi
    fi

    if [[ -z "$log_data" && "$boot_opt" == "-b" ]] && have_cmd dmesg; then
      # dmesg only covers the current boot.
      log_data="$(dmesg 2>/dev/null || true)"
      [[ -n "$log_data" ]] && log_source="dmesg"
    fi

    if [[ -z "$log_data" ]]; then
      local -a fallback_files=()
      local f
      if [[ "$boot_opt" == "-b -1" ]]; then
        fallback_files=(/var/log/kern.log.1 /var/log/syslog.1)
      else
        fallback_files=(/var/log/kern.log /var/log/syslog)
      fi
      for f in "${fallback_files[@]}"; do
        [[ -r "$f" ]] || continue
        log_data+=$'\n'"$(cat "$f" 2>/dev/null || true)"
        log_source+="${log_source:+, }$f"
      done
    fi

    if [[ -z "$log_data" ]]; then
      note "No kernel log data available for ${label}."
      continue
    fi

    inspected=$((inspected + 1))

    crash_count="$(awk 'BEGIN{IGNORECASE=1} /xHCI host controller not responding|HC died; cleaning up|host controller halted/ {c++} END{print c+0}' <<<"$log_data")"
    timeout_count="$(awk 'BEGIN{IGNORECASE=1} /tx timeout|Read reg16 failed|command 0x[0-9a-f]+ tx timeout/ {c++} END{print c+0}' <<<"$log_data")"
    enum_err_count="$(awk 'BEGIN{IGNORECASE=1} /unable to enumerate USB device|device descriptor read\/64|can.t set config|can.t set address|over-current/ {c++} END{print c+0}' <<<"$log_data")"
    disconnect_count="$(awk 'BEGIN{IGNORECASE=1} /USB disconnect, device number/ {c++} END{print c+0}' <<<"$log_data")"
    netdev_watchdog_count="$(awk 'BEGIN{IGNORECASE=1} /NETDEV WATCHDOG/ {c++} END{print c+0}' <<<"$log_data")"

    score=0
    if (( crash_count > 0 )); then
      score=2
    elif (( timeout_count > 0 || enum_err_count > 0 || netdev_watchdog_count > 0 || disconnect_count >= 8 )); then
      score=1
    fi

    if (( score > worst )); then
      worst=$score
    fi

    say
    say "-- ${label} --"
    [[ -n "$log_source" ]] && print_kv "Log source" "$log_source"
    print_kv "xHCI fatal markers" "$crash_count"
    print_kv "USB/BT timeout markers" "$timeout_count"
    print_kv "USB enumeration errors" "$enum_err_count"
    print_kv "USB disconnect events" "$disconnect_count"
    print_kv "NETDEV WATCHDOG markers" "$netdev_watchdog_count"

    if (( score == 2 )); then
      if (( ENABLE_COLOR )); then
        say "${C_RED}CRITICAL${C_RESET}: USB host-controller crash markers were detected in ${label}."
      else
        say "CRITICAL: USB host-controller crash markers were detected in ${label}."
      fi
    elif (( score == 1 )); then
      if (( ENABLE_COLOR )); then
        say "${C_YELLOW}WARN${C_RESET}: USB instability markers were detected in ${label}."
      else
        say "WARN: USB instability markers were detected in ${label}."
      fi
    else
      if (( ENABLE_COLOR )); then
        say "${C_GREEN}OK${C_RESET}: No obvious USB/xHCI crash markers detected in ${label}."
      else
        say "OK: No obvious USB/xHCI crash markers detected in ${label}."
      fi
    fi

    if (( score > 0 )); then
      say "Key matching log lines:"
      awk -v max=20 'BEGIN{IGNORECASE=1; n=0} /xHCI host controller not responding|HC died; cleaning up|host controller halted|USB disconnect, device number|tx timeout|NETDEV WATCHDOG|unable to enumerate USB device|device descriptor read\/64|Read reg16 failed|can.t set config|can.t set address|over-current|reset (high-speed|SuperSpeed) USB device/ {print "  " $0; n++; if (n>=max) exit}' <<<"$log_data"
    fi
  done

  if (( inspected == 0 )); then
    say "No usable kernel log source found (journalctl/dmesg unavailable)."
    return 1
  fi

  say
  if (( worst == 2 )); then
    if (( ENABLE_COLOR )); then
      say "${C_RED}✖ USB HEALTH: FAIL${C_RESET} (controller crash signatures detected)"
    else
      say "USB HEALTH: FAIL (controller crash signatures detected)"
    fi
    note "Optional mitigation to test:"
    note "  usbcore.autosuspend=-1 pcie_aspm=off"
    note "These are optional stability workarounds. Trade-off: higher idle power usage."
    return 2
  elif (( worst == 1 )); then
    if (( ENABLE_COLOR )); then
      say "${C_YELLOW}⚠ USB HEALTH: WARN${C_RESET} (instability markers detected)"
    else
      say "USB HEALTH: WARN (instability markers detected)"
    fi
    note "Optional mitigation to test:"
    note "  usbcore.autosuspend=-1 pcie_aspm=off"
    note "These are optional stability workarounds. Trade-off: higher idle power usage."
    return 1
  fi

  if (( ENABLE_COLOR )); then
    say "${C_GREEN}✔ USB HEALTH: PASS${C_RESET} (no obvious crash markers detected)"
  else
    say "USB HEALTH: PASS (no obvious crash markers detected)"
  fi
  return 0
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
        add_reason WARN "Service is enabled but guest GPU is not currently bound to vfio-pci (likely needs reboot or Boot-VGA safety policy skipped binding): $GUEST_GPU_BDF"
      fi
      if [[ -n "${HOST_GPU_BDF:-}" ]]; then
        local host_assisted_default boot_vga_policy
        host_assisted_default="$(host_assisted_boot_vga_policy_default "$HOST_GPU_BDF" "$GUEST_GPU_BDF")"
        boot_vga_policy="${VFIO_BOOT_VGA_POLICY:-STRICT}"
        boot_vga_policy="${boot_vga_policy^^}"
        case "$boot_vga_policy" in
          AUTO|STRICT) ;;
          *) boot_vga_policy="STRICT" ;;
        esac
        if [[ "$host_assisted_default" == "1" && "$boot_vga_policy" != "AUTO" && "${VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU:-0}" != "1" ]]; then
          add_reason WARN "Guest GPU is Boot VGA while HOST_GPU_BDF has boot_vga=0; set VFIO_BOOT_VGA_POLICY=AUTO (recommended) or VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1 in $CONF_FILE to allow safe host-assisted binding."
        fi
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

  # Openbox monitor parser regression smoke check
  local openbox_parser_sample openbox_parser_out
  openbox_parser_sample=$'Screen 0: minimum 8 x 8, current 4480 x 1440, maximum 32767 x 32767\nHDMI-1 connected primary 2560x1440+0+0\nDP-1 connected 1920x1080+2560+0\nDP-2 disconnected\n'
  openbox_parser_out="$(printf '%s\n' "$openbox_parser_sample" | openbox_connected_outputs_from_xrandr_query | paste -sd',' -)"
  if [[ "$openbox_parser_out" == "HDMI-1,DP-1" ]]; then
    print_kv "Openbox monitor parser" "OK"
  else
    print_kv "Openbox monitor parser" "FAIL (got: ${openbox_parser_out:-<empty>})"
    fail=1
  fi

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
  # Basic host state
  local dm_name dm_dep_status xorg_status wayland_status graphics_protocol_support graphics_protocol_mode openbox_status i3_status bspwm_status awesome_status dwm_status qtile_status xfwm4_status
  dm_name="$(detect_display_manager 2>/dev/null || true)"
  [[ -n "$dm_name" ]] || dm_name="none"
  dm_dep_status="$(display_manager_dependency_status "$dm_name")"
  xorg_status="$(xorg_stack_status)"
  wayland_status="$(wayland_stack_status)"
  graphics_protocol_support="$(x11_wayland_support_status "$xorg_status" "$wayland_status")"
  graphics_protocol_mode="$(x11_wayland_supported_mode "$xorg_status" "$wayland_status")"
  openbox_status="$(openbox_stack_status)"
  i3_status="$(i3_stack_status)"
  bspwm_status="$(bspwm_stack_status)"
  awesome_status="$(awesome_stack_status)"
  dwm_status="$(dwm_stack_status)"
  qtile_status="$(qtile_stack_status)"
  xfwm4_status="$(xfwm4_stack_status)"

  if (( JSON_OUTPUT )); then
    local opensuse_like_json accountsservice_present_json configured_graphics_protocol_mode configured_graphics_daemon_interval configured_graphics_watchdog_retention_days configured_graphics_watchdog_max_lines hc status
    local fallback_report fallback_status fallback_reason fallback_source_entry fallback_target_entry fallback_source_name fallback_target_name fallback_applicable_json
    opensuse_like_json=false
    accountsservice_present_json=false
    configured_graphics_protocol_mode="AUTO"
    configured_graphics_daemon_interval="$GRAPHICS_DAEMON_INTERVAL_DEFAULT"
    configured_graphics_watchdog_retention_days="$GRAPHICS_WATCHDOG_RETENTION_DAYS_DEFAULT"
    configured_graphics_watchdog_max_lines="$GRAPHICS_WATCHDOG_MAX_LINES_DEFAULT"
    fallback_status="NOT_APPLICABLE"
    fallback_reason=""
    fallback_source_entry=""
    fallback_target_entry=""
    fallback_source_name=""
    fallback_target_name=""
    fallback_applicable_json=false
    if opensuse_like_detection_reason >/dev/null 2>&1; then
      opensuse_like_json=true
    fi
    if accountsservice_is_present; then
      accountsservice_present_json=true
    fi
    if readable_file "$CONF_FILE"; then
      configured_graphics_protocol_mode="$(awk -F= '/^GRAPHICS_PROTOCOL_MODE=/{v=$2; gsub(/"/,"",v); print v; exit}' "$CONF_FILE" 2>/dev/null || true)"
      configured_graphics_protocol_mode="$(trim "${configured_graphics_protocol_mode:-}")"
      configured_graphics_protocol_mode="${configured_graphics_protocol_mode^^}"
      case "$configured_graphics_protocol_mode" in
        X11|WAYLAND|AUTO) ;;
        *) configured_graphics_protocol_mode="AUTO" ;;
      esac
      configured_graphics_daemon_interval="$(graphics_daemon_interval_from_conf_or_default)"
      configured_graphics_watchdog_retention_days="$(graphics_watchdog_retention_days_from_conf_or_default)"
      configured_graphics_watchdog_max_lines="$(graphics_watchdog_max_lines_from_conf_or_default)"
    fi
    hc="$(vfio_config_health)"
    status="$(printf '%s\n' "$hc" | awk -F= '/^STATUS=/{print $2; exit}')"
    status="${status:-UNKNOWN}"
    fallback_report="$(bls_fallback_entry_detect_status)"
    local key value
    while IFS='=' read -r key value; do
      case "$key" in
        STATUS) fallback_status="$value" ;;
        REASON) fallback_reason="$value" ;;
        SOURCE_ENTRY) fallback_source_entry="$value" ;;
        TARGET_ENTRY) fallback_target_entry="$value" ;;
      esac
    done <<<"$fallback_report"
    if [[ "$fallback_status" != "NOT_APPLICABLE" ]]; then
      fallback_applicable_json=true
    fi
    if [[ -n "$fallback_source_entry" ]]; then
      fallback_source_name="$(basename "$fallback_source_entry")"
    fi
    if [[ -n "$fallback_target_entry" ]]; then
      fallback_target_name="$(basename "$fallback_target_entry")"
    fi

    printf '{\n'
    printf '  \"mode\": \"detect\",\n'
    printf '  \"bootloader\": \"%s\",\n' "$(detect_bootloader)"
    printf '  \"opensuse_like\": %s,\n' "$opensuse_like_json"
    printf '  \"display_manager\": \"%s\",\n' "$dm_name"
    printf '  \"display_manager_health\": \"%s\",\n' "$dm_dep_status"
    printf '  \"graphics_stack_xorg\": \"%s\",\n' "$xorg_status"
    printf '  \"graphics_stack_wayland\": \"%s\",\n' "$wayland_status"
    printf '  \"graphics_protocol_support\": \"%s\",\n' "$graphics_protocol_support"
    printf '  \"graphics_protocol_mode\": \"%s\",\n' "$graphics_protocol_mode"
    printf '  \"configured_graphics_protocol_mode\": \"%s\",\n' "$configured_graphics_protocol_mode"
    printf '  \"configured_graphics_daemon_interval_seconds\": %s,\n' "$configured_graphics_daemon_interval"
    printf '  \"configured_graphics_watchdog_retention_days\": %s,\n' "$configured_graphics_watchdog_retention_days"
    printf '  \"configured_graphics_watchdog_max_lines\": %s,\n' "$configured_graphics_watchdog_max_lines"
    printf '  \"window_manager_openbox\": \"%s\",\n' "$openbox_status"
    printf '  \"window_manager_i3\": \"%s\",\n' "$i3_status"
    printf '  \"window_manager_bspwm\": \"%s\",\n' "$bspwm_status"
    printf '  \"window_manager_awesome\": \"%s\",\n' "$awesome_status"
    printf '  \"window_manager_dwm\": \"%s\",\n' "$dwm_status"
    printf '  \"window_manager_qtile\": \"%s\",\n' "$qtile_status"
    printf '  \"window_manager_xfwm4\": \"%s\",\n' "$xfwm4_status"
    printf '  \"bls_fallback_applicable\": %s,\n' "$fallback_applicable_json"
    printf '  \"bls_fallback_status\": \"%s\",\n' "${fallback_status:-NOT_APPLICABLE}"
    printf '  \"bls_fallback_reason\": \"%s\",\n' "${fallback_reason:-}"
    printf '  \"bls_fallback_source_entry\": \"%s\",\n' "${fallback_source_name:-}"
    printf '  \"bls_fallback_target_entry\": \"%s\",\n' "${fallback_target_name:-}"
    printf '  \"accountsservice_present\": %s,\n' "$accountsservice_present_json"
    printf '  \"vfio_health\": \"%s\"\n' "$status"
    printf '}\n'
    return 0
  fi
  say
  if (( ENABLE_COLOR )); then
    say "${C_CYAN}${C_BOLD}==== Existing VFIO / Passthrough Detection Report ==== ${C_RESET}"
  else
    say "==== Existing VFIO / Passthrough Detection Report ===="
  fi
  if (( ENABLE_COLOR )); then
    print_kv "Kernel" "${C_GREEN}$(uname -r)${C_RESET}"
    print_kv "Current cmdline" "${C_DIM}$(cat /proc/cmdline 2>/dev/null || true)${C_RESET}"
    print_kv "Bootloader" "${C_GREEN}$(detect_bootloader)${C_RESET}"
    print_kv "openSUSE-like detection" "${C_GREEN}$(opensuse_like_detection_reason)${C_RESET}"
    if [[ "$dm_name" == "none" ]]; then
      print_kv "Display manager" "${C_YELLOW}NOT PRESENT${C_RESET} (none detected)"
    else
      print_kv "Display manager" "${C_GREEN}${dm_name}${C_RESET}"
    fi
    if [[ "$dm_name" == "lightdm" && "$dm_dep_status" == "NOT_WORK" ]]; then
      print_kv "Display manager health" "$(format_tri_state_status "$dm_dep_status") (LightDM detected; AccountsService missing)"
    else
      print_kv "Display manager health" "$(format_tri_state_status "$dm_dep_status")"
    fi
    print_kv "Graphics stack (Xorg)" "$(format_tri_state_status "$xorg_status")"
    print_kv "Graphics stack (Wayland)" "$(format_tri_state_status "$wayland_status")"
    print_kv "Graphics protocol support" "$(format_tri_state_status "$graphics_protocol_support")"
    print_kv "Graphics protocol mode" "$graphics_protocol_mode"
    print_kv "Window manager (Openbox)" "$(format_tri_state_status "$openbox_status")"
    print_kv "Window manager (i3)" "$(format_tri_state_status "$i3_status")"
    print_kv "Window manager (bspwm)" "$(format_tri_state_status "$bspwm_status")"
    print_kv "Window manager (awesome)" "$(format_tri_state_status "$awesome_status")"
    print_kv "Window manager (dwm)" "$(format_tri_state_status "$dwm_status")"
    print_kv "Window manager (qtile)" "$(format_tri_state_status "$qtile_status")"
    print_kv "Window manager (xfwm4)" "$(format_tri_state_status "$xfwm4_status")"
  else
    print_kv "Kernel" "$(uname -r)"
    print_kv "Current cmdline" "$(cat /proc/cmdline 2>/dev/null || true)"
    print_kv "Bootloader" "$(detect_bootloader)"
    print_kv "openSUSE-like detection" "$(opensuse_like_detection_reason)"
    if [[ "$dm_name" == "none" ]]; then
      print_kv "Display manager" "NOT PRESENT (none detected)"
    else
      print_kv "Display manager" "$dm_name"
    fi
    if [[ "$dm_name" == "lightdm" && "$dm_dep_status" == "NOT_WORK" ]]; then
      print_kv "Display manager health" "$(format_tri_state_status "$dm_dep_status") (LightDM detected; AccountsService missing)"
    else
      print_kv "Display manager health" "$(format_tri_state_status "$dm_dep_status")"
    fi
    print_kv "Graphics stack (Xorg)" "$(format_tri_state_status "$xorg_status")"
    print_kv "Graphics stack (Wayland)" "$(format_tri_state_status "$wayland_status")"
    print_kv "Graphics protocol support" "$(format_tri_state_status "$graphics_protocol_support")"
    print_kv "Graphics protocol mode" "$graphics_protocol_mode"
    print_kv "Window manager (Openbox)" "$(format_tri_state_status "$openbox_status")"
    print_kv "Window manager (i3)" "$(format_tri_state_status "$i3_status")"
    print_kv "Window manager (bspwm)" "$(format_tri_state_status "$bspwm_status")"
    print_kv "Window manager (awesome)" "$(format_tri_state_status "$awesome_status")"
    print_kv "Window manager (dwm)" "$(format_tri_state_status "$dwm_status")"
    print_kv "Window manager (qtile)" "$(format_tri_state_status "$qtile_status")"
    print_kv "Window manager (xfwm4)" "$(format_tri_state_status "$xfwm4_status")"
  fi

  # In detect mode, offer immediate remediation interactively.
  maybe_offer_detect_accountsservice_install
  maybe_offer_detect_user_audio_unit_guard_repair
  maybe_offer_detect_stale_user_audio_unit_cleanup
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
    local configured_graphics_protocol configured_graphics_daemon_interval_effective configured_graphics_watchdog_retention_days_effective configured_graphics_watchdog_max_lines_effective
    configured_graphics_protocol="${GRAPHICS_PROTOCOL_MODE:-AUTO}"
    configured_graphics_protocol="${configured_graphics_protocol^^}"
    case "$configured_graphics_protocol" in
      X11|WAYLAND|AUTO) ;;
      *) configured_graphics_protocol="AUTO" ;;
    esac
    configured_graphics_daemon_interval_effective="$(graphics_daemon_interval_from_conf_or_default)"
    configured_graphics_watchdog_retention_days_effective="$(graphics_watchdog_retention_days_from_conf_or_default)"
    configured_graphics_watchdog_max_lines_effective="$(graphics_watchdog_max_lines_from_conf_or_default)"
    print_kv "Configured host GPU" "${HOST_GPU_BDF:-<unset>}"
    print_kv "Configured guest GPU" "${GUEST_GPU_BDF:-<unset>}"
    print_kv "Configured host audio" "${HOST_AUDIO_BDFS_CSV:-<unset>}"
    print_kv "Configured guest audio" "${GUEST_AUDIO_BDFS_CSV:-<unset>}"
    print_kv "Configured graphics protocol" "$configured_graphics_protocol"
    print_kv "Configured graphics daemon interval" "${configured_graphics_daemon_interval_effective}s"
    print_kv "Configured watchdog retention" "${configured_graphics_watchdog_retention_days_effective} day(s)"
    print_kv "Configured watchdog max lines" "$configured_graphics_watchdog_max_lines_effective"
    if [[ -n "${GUEST_GPU_BDF:-}" ]]; then
      local rebar_state above4g_state
      rebar_state="$(rebar_status_for_bdf "$GUEST_GPU_BDF")"
      above4g_state="$(above_4g_decoding_status_for_bdf "$GUEST_GPU_BDF")"
      if (( ENABLE_COLOR )); then
        print_kv "Guest GPU ReBAR" "${C_BLUE}${rebar_state}${C_RESET}"
        print_kv "Guest GPU Above 4G" "${C_BLUE}${above4g_state}${C_RESET}"
      else
        print_kv "Guest GPU ReBAR" "$rebar_state"
        print_kv "Guest GPU Above 4G" "$above4g_state"
      fi
    fi
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

  # vendor-reset module (only recommended when reset-failure markers are seen)
  if [[ -d /sys/module/vendor_reset ]]; then
    if (( ENABLE_COLOR )); then
      print_kv "vendor-reset" "${C_GREEN}Loaded${C_RESET}"
    else
      print_kv "vendor-reset" "Loaded"
    fi
  else
    if host_has_amd_gpu && amd_reset_issue_signatures_present; then
      if (( ENABLE_COLOR )); then
        print_kv "vendor-reset" "${C_YELLOW}MISSING (Recommended: reset-failure markers detected in logs)${C_RESET}"
      else
        print_kv "vendor-reset" "MISSING (Recommended: reset-failure markers detected in logs)"
      fi
    elif host_has_amd_gpu; then
      if (( ENABLE_COLOR )); then
        print_kv "vendor-reset" "${C_DIM}N/A (No AMD reset-failure markers detected in recent logs)${C_RESET}"
      else
        print_kv "vendor-reset" "N/A (No AMD reset-failure markers detected in recent logs)"
      fi
    else
      print_kv "vendor-reset" "Not loaded"
    fi
  fi
  # In detect mode, offer immediate vendor-reset remediation on AMD hosts.
  maybe_offer_detect_vendor_reset_install

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
  # openSUSE-specific BLS fallback recommendation/remediation path.
  maybe_offer_detect_fallback_entry_create

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
    print_kv "hook files" "$(find /etc/libvirt/hooks -maxdepth 1 -type f -printf '%f ' 2>/dev/null || true)"
  else
    print_kv "/etc/libvirt/hooks" "missing"
  fi
  report_vm_network_precheck || true

  say "==== End report ===="
}

print_effective_config() {
  readable_file "$CONF_FILE" || die "Missing or unreadable config: $CONF_FILE"

  # shellcheck disable=SC1090
  . "$CONF_FILE"

  local guest_gpu host_gpu
  guest_gpu="${GUEST_GPU_BDF:-}"
  host_gpu="${HOST_GPU_BDF:-}"

  [[ -n "$guest_gpu" ]] || die "GUEST_GPU_BDF is missing in $CONF_FILE"

  local boot_vga_policy guest_boot_vga host_boot_vga
  local allow_boot_vga allow_boot_vga_if_host
  local host_assisted_default allow_boot_vga_bind
  local decision decision_reason

  boot_vga_policy="${VFIO_BOOT_VGA_POLICY:-STRICT}"
  boot_vga_policy="${boot_vga_policy^^}"
  case "$boot_vga_policy" in
    AUTO|STRICT) ;;
    *) boot_vga_policy="STRICT" ;;
  esac

  allow_boot_vga="${VFIO_ALLOW_BOOT_VGA:-0}"
  allow_boot_vga_if_host="${VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU:-0}"

  guest_boot_vga="$(pci_boot_vga_flag "$guest_gpu")"
  host_boot_vga="n/a"
  if [[ -n "$host_gpu" ]]; then
    host_boot_vga="$(pci_boot_vga_flag "$host_gpu")"
  fi
  host_assisted_default="$(host_assisted_boot_vga_policy_default "$host_gpu" "$guest_gpu")"

  allow_boot_vga_bind=1
  decision_reason="guest_not_boot_vga_or_force_enabled"
  if [[ "$guest_boot_vga" == "1" ]] && [[ "$allow_boot_vga" != "1" ]]; then
    allow_boot_vga_bind=0
    decision_reason="boot_vga_guard"
    if [[ "$host_assisted_default" == "1" ]]; then
      if [[ "$allow_boot_vga_if_host" == "1" ]]; then
        allow_boot_vga_bind=1
        decision_reason="explicit_opt_in"
      fi
      if [[ "$boot_vga_policy" == "AUTO" ]]; then
        allow_boot_vga_bind=1
        decision_reason="auto_detect"
      fi
      if [[ "$allow_boot_vga_bind" != "1" ]]; then
        decision_reason="host_assisted_available_but_not_enabled"
      fi
    else
      decision_reason="no_host_assisted_topology"
    fi
  fi

  if [[ "$allow_boot_vga_bind" == "1" ]]; then
    decision="ALLOW_BIND"
  else
    decision="SKIP_BIND"
  fi

  say
  hdr "Effective Boot-VGA Policy Report"
  print_kv "Config file" "$CONF_FILE"
  print_kv "Host GPU BDF" "${host_gpu:-<unset>}"
  print_kv "Guest GPU BDF" "$guest_gpu"
  print_kv "Guest boot_vga" "$guest_boot_vga"
  print_kv "Host boot_vga" "$host_boot_vga"
  print_kv "Host-assisted topology" "$host_assisted_default"
  print_kv "VFIO_BOOT_VGA_POLICY" "$boot_vga_policy"
  print_kv "VFIO_ALLOW_BOOT_VGA" "$allow_boot_vga"
  print_kv "VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU" "$allow_boot_vga_if_host"
  print_kv "Effective decision" "$decision"
  print_kv "Decision reason" "$decision_reason"

  if [[ "$decision" == "ALLOW_BIND" ]]; then
    note "Result: bind helper would proceed with vfio-pci binding for this boot."
  else
    note "Result: bind helper would skip vfio-pci binding for this boot."
  fi
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
require_writable_root_or_die() {
  # Install/reset/disable modes must be able to write system state.
  # openSUSE snapshot boots can be read-only (e.g. /.snapshots/*/snapshot),
  # which would make deployment silently fail later.
  (( DRY_RUN )) && return 0

  local marker="/etc/.vfio-write-test.$$"
  if ! : >"$marker" 2>/dev/null; then
    local cmdline rootflags msg
    cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
    rootflags="$(sed -nE 's/.*rootflags=([^ ]+).*/\1/p' <<<"$cmdline")"
    msg="Root filesystem appears read-only (cannot write to /etc)."
    if [[ -n "$rootflags" ]]; then
      msg+=" Current rootflags=${rootflags}."
    fi
    msg+=" Boot a writable subvolume/snapshot and rerun."
    die "$msg"
  fi
  rm -f "$marker" || true
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
  # Accept no arguments to emit a blank line.
  local msg="${1:-}"
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
  local graphics_protocol_mode="${7:-AUTO}"
  local boot_vga_policy_mode="${8:-${BOOT_VGA_POLICY_OVERRIDE:-AUTO}}"
  local graphics_daemon_interval="${9:-${GRAPHICS_DAEMON_INTERVAL_OVERRIDE:-$GRAPHICS_DAEMON_INTERVAL_DEFAULT}}"
  local boot_vga_host_assisted_default="0"
  graphics_protocol_mode="${graphics_protocol_mode^^}"
  if [[ "$graphics_protocol_mode" != "X11" && "$graphics_protocol_mode" != "WAYLAND" ]]; then
    graphics_protocol_mode="AUTO"
  fi
  boot_vga_policy_mode="${boot_vga_policy_mode^^}"
  case "$boot_vga_policy_mode" in
    AUTO|STRICT) ;;
    *) boot_vga_policy_mode="AUTO" ;;
  esac
  if [[ ! "$graphics_daemon_interval" =~ ^[0-9]+$ ]] || (( 10#$graphics_daemon_interval < 1 || 10#$graphics_daemon_interval > 3600 )); then
    graphics_daemon_interval="$GRAPHICS_DAEMON_INTERVAL_DEFAULT"
  fi

  boot_vga_host_assisted_default="$(host_assisted_boot_vga_policy_default "$host_gpu" "$guest_gpu")"

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
# Boot-VGA safety policy:
# - 1 allows host-assisted binding when guest GPU is Boot VGA AND host GPU is a different adapter with boot_vga=0.
# - 0 keeps Boot-VGA skip behavior unless fully forced via VFIO_ALLOW_BOOT_VGA=1.
VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU="$boot_vga_host_assisted_default"
# Boot-VGA host-assisted policy mode:
# - AUTO: dynamically allows host-assisted Boot-VGA bind when runtime topology is safe
#         (guest boot_vga=1, host boot_vga=0, different GPUs), and skips otherwise.
# - STRICT: requires explicit VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1.
VFIO_BOOT_VGA_POLICY="$boot_vga_policy_mode"
HOST_AUDIO_BDFS_CSV="$host_audio_bdfs_csv"
HOST_AUDIO_NODE_NAME="$host_audio_node_name"

GUEST_GPU_BDF="$guest_gpu"
GUEST_AUDIO_BDFS_CSV="$guest_audio_bdfs_csv"
GUEST_GPU_VENDOR_ID="$guest_vendor"
GRAPHICS_PROTOCOL_MODE="$graphics_protocol_mode"
VFIO_GRAPHICS_DAEMON_INTERVAL="$graphics_daemon_interval"
# Watchdog log retention and growth controls for vfio-graphics-protocold:
# - retention days is best-effort timestamp pruning window.
# - max lines is a hard cap after pruning to prevent unbounded growth.
VFIO_GRAPHICS_WATCHDOG_RETENTION_DAYS="10"
VFIO_GRAPHICS_WATCHDOG_MAX_LINES="5000"
# AUTO-mode X11 pinning policy:
# - 1 (default): allow X11 host-GPU pinning in AUTO mode for pre-login X11
#                display managers (for example SDDM/LightDM) and active X11 sessions.
#                This avoids \"no screens found\" failures when the guest GPU is
#                already bound to vfio-pci before the display manager starts.
# - 0: keep AUTO conservative for active user sessions; pre-login safety pinning
#      for X11 display managers still applies.
VFIO_GRAPHICS_AUTO_X11_PINNING=\"1\"
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

  local file="$SOFTDEP_FILE"
  backup_file "$file"

  write_file_atomic "$file" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
# Ensures vfio-pci loads before the graphics driver to prevent race conditions.
# Use exact module names only; wildcard module names are not valid in modprobe softdep entries.

softdep $target_driver pre: vfio-pci
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

  line="${line#"${key}"=}"
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
    trim "$cmdline $param"
  fi
}

remove_param_all() {
  # Remove a cmdline token (exact token) if present.
  local cmdline="$1" param="$2"
  # Split on spaces to be safe.
  local out="" tok
  local IFS=$' \t\n'
  for tok in $cmdline; do
    if [[ "$tok" == "$param" ]]; then
      continue
    fi
    out+="${out:+ }$tok"
  done
  trim "$out"
}
remove_param_prefix() {
  # Remove cmdline tokens that start with a given prefix (e.g. key=).
  local cmdline="$1" prefix="$2"
  local out="" tok
  local IFS=$' \t\n'
  for tok in $cmdline; do
    if [[ "$tok" == "${prefix}"* ]]; then
      continue
    fi
    out+="${out:+ }$tok"
  done
  trim "$out"
}
preview_cmdline_change_interactive() {
  # preview_cmdline_change_interactive "<current_cmdline>" "<updated_cmdline>" "<target_label>"
  local current="$1"
  local updated="$2"
  local target="$3"
  local current_trim updated_trim
  current_trim="$(trim "${current:-}")"
  updated_trim="$(trim "${updated:-}")"
  [[ "$current_trim" != "$updated_trim" ]] || return 0

  say
  hdr "Preview ${target} update"
  note "Current ${target}:"
  say "  ${current_trim:-<empty>}"
  note "Proposed ${target}:"
  say "  ${updated_trim:-<empty>}"
  if prompt_yn "Apply this ${target} update?" Y "Boot options preview"; then
    return 0
  fi
  note "Skipped ${target} update by user choice."
  return 1
}
append_guest_vfio_ids_with_detect_fallback() {
  # append_guest_vfio_ids_with_detect_fallback "<current_cmdline>" "<target_label>"
  # Always attempts to add vfio-pci.ids for the selected guest GPU.
  # If the selected guest is Boot VGA AND VFIO risk/failure markers were
  # detected in this run, it falls back by removing vfio-pci.ids again.
  local current="$1"
  local target="$2"
  local updated="$current"
  local out guest_ids guest_boot_vga="0" risk_detected=0
  out="/dev/stderr"
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    out="/dev/tty"
  fi

  guest_ids="${CTX[guest_vfio_ids]:-}"
  [[ -n "$guest_ids" ]] || {
    printf '%s\n' "$updated"
    return 0
  }

  updated="$(add_param_once "$updated" "vfio-pci.ids=$guest_ids")"

  if [[ -n "${CTX[guest_gpu]:-}" && -f "/sys/bus/pci/devices/${CTX[guest_gpu]}/boot_vga" ]]; then
    guest_boot_vga="$(cat "/sys/bus/pci/devices/${CTX[guest_gpu]}/boot_vga" 2>/dev/null || echo 0)"
  fi

  if [[ "${CTX[kernel_vfio_risk]:-0}" == "1" || "${CTX[kernel_vfio_log_error]:-0}" == "1" ]]; then
    risk_detected=1
  fi

  if [[ "$guest_boot_vga" == "1" ]]; then
    note "Boot VGA guest detected (${CTX[guest_gpu]:-unknown}); adding vfio-pci.ids in ${target} with automatic risk fallback enabled." >"$out"
    if (( risk_detected )); then
      note "Detected VFIO risk/failure markers in this run; fallback applied in ${target} by removing vfio-pci.ids for safer boot behavior." >"$out"
      updated="$(remove_param_all "$updated" "vfio-pci.ids=$guest_ids")"
      CTX[guest_vfio_ids_fallback]=1
    fi
  fi

  printf '%s\n' "$updated"
  return 0
}
add_custom_kernel_params_interactive() {
  # add_custom_kernel_params_interactive "<current_cmdline>" "<target_label>"
  local current="$1"
  local target="$2"
  local updated="$current"
  local in out extra tok
  in="/dev/stdin"
  out="/dev/stderr"
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    in="/dev/tty"
    out="/dev/tty"
  fi

  # IMPORTANT: this helper is used in command substitution. Keep all UI text
  # off stdout so only the final updated cmdline is returned to the caller.
  printf '\n' >"$out"
  hdr "Custom kernel parameters (optional)" >"$out"
  note "You can append extra kernel parameter(s) for ${target}." >"$out"
  note "This can be useful for distro-specific or X11-specific passthrough tweaks." >"$out"
  note "Leave blank to keep defaults." >"$out"

  if ! prompt_yn "Add custom kernel parameter(s) to ${target} now?" N "Boot options (custom)"; then
    printf '%s\n' "$updated"
    return 0
  fi

  printf '%s' "Enter extra kernel parameter(s), space-separated: " >"$out"
  read -r extra <"$in" || extra=""
  extra="$(trim "${extra:-}")"
  if [[ -z "$extra" ]]; then
    note "No custom kernel parameters entered." >"$out"
    printf '%s\n' "$updated"
    return 0
  fi

  for tok in $extra; do
    updated="$(add_param_once "$updated" "$tok")"
  done
  note "Added custom kernel parameter(s): $extra" >"$out"
  printf '%s\n' "$updated"
  return 0
}

# Return 0 if the running kernel looks like an openSUSE default kernel
# ("*-default") with a version at or above a given threshold. This is used
# to warn users about known/expected VFIO binding issues on very new
# default kernels, and to suggest booting the long-term kernel instead.
opensuse_default_kernel_is_at_least() {
  local min_major="$1" min_minor="$2"
  local kver base major minor

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
  # Some openSUSE GRUB deployments still boot via Boot Loader Spec entries
  # even when GRUB_ENABLE_BLSCFG/LOADER_TYPE markers are absent or stale.
  # If /etc/kernel/cmdline exists and loader entries contain options with
  # root=..., treat this as GRUB2-BLS so we follow the safe cmdline+BLS flow.
  if is_opensuse_like && [[ -f /etc/kernel/cmdline ]] && [[ -d /boot/grub || -d /boot/grub2 ]]; then
    local bls_dir bls_entry
    bls_dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
    if [[ -n "$bls_dir" ]]; then
      shopt -s nullglob
      for bls_entry in "$bls_dir"/system-*.conf "$bls_dir"/grub-*.conf "$bls_dir"/*.conf; do
        [[ -f "$bls_entry" ]] || continue
        if grep -qE '^options[[:space:]]+.*\<root=' "$bls_entry" 2>/dev/null; then
          shopt -u nullglob
          echo "grub2-bls"
          return 0
        fi
      done
      shopt -u nullglob
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

# Read /etc/os-release fields used by distro gating. Emits:
#   <id>\t<id_like>
# (Both values may be empty when unknown.)
os_release_id_and_like() {
  local os_id="" os_like=""
  if [[ -r /etc/os-release ]]; then
    local k v
    while IFS='=' read -r k v; do
      [[ -n "${k:-}" ]] || continue
      case "$k" in
        ID)
          v="${v%\"}"
          v="${v#\"}"
          os_id="$v"
          ;;
        ID_LIKE)
          v="${v%\"}"
          v="${v#\"}"
          os_like="$v"
          ;;
      esac
    done </etc/os-release
  fi
  printf '%s\t%s\n' "$os_id" "$os_like"
}

# Diagnostic string for openSUSE-family detection used by --detect.
# Example outputs:
#   yes (ID=opensuse-tumbleweed matched opensuse*)
#   yes (ID_LIKE token opensuse matched opensuse*)
#   no (ID=sparky; ID_LIKE=debian)
opensuse_like_detection_reason() {
  local pair os_id os_like tok
  pair="$(os_release_id_and_like)"
  os_id="${pair%%$'\t'*}"
  os_like="${pair#*$'\t'}"
  [[ "$os_like" == "$pair" ]] && os_like=""

  if [[ "${os_id,,}" == opensuse* ]]; then
    printf 'yes (ID=%s matched opensuse*)\n' "${os_id:-<empty>}"
    return 0
  fi
  for tok in $os_like; do
    if [[ "${tok,,}" == opensuse* ]]; then
      printf 'yes (ID_LIKE token %s matched opensuse*)\n' "$tok"
      return 0
    fi
  done
  printf 'no (ID=%s; ID_LIKE=%s)\n' "${os_id:-<empty>}" "${os_like:-<empty>}"
  return 1
}

# Return 0 if this looks like an openSUSE-like system (used to gate /etc/kernel/cmdline edits).
is_opensuse_like() {
  opensuse_like_detection_reason >/dev/null
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

kernel_cmdline_persistence_file() {
  echo "/etc/kernel/cmdline"
}
kernel_cmdline_rehydrate_boot_metadata_if_missing() {
  # Best-effort safety net: if /etc/kernel/cmdline lost root metadata,
  # recover it from current/backup BLS entry options before any sync/update.
  local cmdline_file="${1:-}"
  if [[ -z "$cmdline_file" ]]; then
    cmdline_file="$(kernel_cmdline_persistence_file 2>/dev/null || true)"
  fi
  cmdline_file="$(trim "${cmdline_file:-}")"
  [[ -n "$cmdline_file" ]] || return 1
  [[ -f "$cmdline_file" ]] || return 1

  local current_cmdline
  current_cmdline="$(cat "$cmdline_file" 2>/dev/null || true)"
  current_cmdline="$(trim "${current_cmdline:-}")"
  [[ -n "$current_cmdline" ]] || return 1
  if cmdline_get_key_value_token "$current_cmdline" "root" >/dev/null 2>&1; then
    return 0
  fi

  local metadata_opts recovered_cmdline recovered_root_tok
  metadata_opts="$(bls_find_boot_metadata_options 2>/dev/null || true)"
  metadata_opts="$(trim "${metadata_opts:-}")"
  [[ -n "$metadata_opts" ]] || return 1

  recovered_cmdline="$(cmdline_add_boot_metadata_tokens_from_options "$current_cmdline" "$metadata_opts")"
  recovered_cmdline="$(trim "${recovered_cmdline:-}")"
  recovered_root_tok="$(cmdline_get_key_value_token "$recovered_cmdline" "root" 2>/dev/null || true)"
  [[ -n "$recovered_root_tok" ]] || return 1

  if [[ "$recovered_cmdline" == "$current_cmdline" ]]; then
    return 0
  fi

  backup_file "$cmdline_file"
  if (( ! DRY_RUN )); then
    printf '%s\n' "$recovered_cmdline" >"$cmdline_file"
  fi
  note "Rehydrated missing root boot metadata in $cmdline_file from Boot Loader Spec options."
  return 0
}
kernel_cmdline_reconcile_boot_metadata_with_current_mount() {
  # Align persisted root/rootflags metadata with the currently mounted root.
  # This prevents stale snapshot rootflags from surviving across BLS sync runs.
  local cmdline_file="${1:-}"
  if [[ -z "$cmdline_file" ]]; then
    cmdline_file="$(kernel_cmdline_persistence_file 2>/dev/null || true)"
  fi
  cmdline_file="$(trim "${cmdline_file:-}")"
  [[ -n "$cmdline_file" ]] || return 1
  [[ -f "$cmdline_file" ]] || return 1

  local current_cmdline
  current_cmdline="$(cat "$cmdline_file" 2>/dev/null || true)"
  current_cmdline="$(trim "${current_cmdline:-}")"
  [[ -n "$current_cmdline" ]] || return 1

  local mount_root_tok mount_rootflags_tok
  mount_root_tok="$(bls_current_mount_root_token 2>/dev/null || true)"
  mount_rootflags_tok="$(bls_current_mount_rootflags_token 2>/dev/null || true)"
  [[ -n "$mount_root_tok" || -n "$mount_rootflags_tok" ]] || return 1

  local cmdline_root_tok cmdline_rootflags_tok updated_cmdline
  cmdline_root_tok="$(cmdline_get_key_value_token "$current_cmdline" "root" 2>/dev/null || true)"
  cmdline_rootflags_tok="$(cmdline_get_key_value_token "$current_cmdline" "rootflags" 2>/dev/null || true)"
  updated_cmdline="$current_cmdline"

  if [[ -n "$mount_root_tok" ]] && [[ "$cmdline_root_tok" != "$mount_root_tok" ]]; then
    updated_cmdline="$(cmdline_set_key_value_token "$updated_cmdline" "$mount_root_tok")"
  fi
  if [[ -n "$mount_rootflags_tok" ]]; then
    local root_context_matches=1
    if [[ -n "$mount_root_tok" && -n "$cmdline_root_tok" && "$cmdline_root_tok" != "$mount_root_tok" ]]; then
      root_context_matches=0
    fi
    if (( root_context_matches )) && [[ "$cmdline_rootflags_tok" != "$mount_rootflags_tok" ]]; then
      updated_cmdline="$(cmdline_set_key_value_token "$updated_cmdline" "$mount_rootflags_tok")"
    fi
  fi

  updated_cmdline="$(trim "${updated_cmdline:-}")"
  [[ -n "$updated_cmdline" ]] || return 1
  if [[ "$updated_cmdline" == "$current_cmdline" ]]; then
    return 0
  fi

  backup_file "$cmdline_file"
  if (( ! DRY_RUN )); then
    printf '%s\n' "$updated_cmdline" >"$cmdline_file"
  fi
  note "Reconciled root boot metadata in $cmdline_file with the currently mounted root."
  return 0
}

# Extract the first key=value token for a given key from a kernel cmdline
# string. Example:
#   cmdline_get_key_value_token "quiet root=UUID=abcd rw" "root"
#   -> root=UUID=abcd
cmdline_get_key_value_token() {
  local cmdline="$1" key="$2" tok
  local IFS=$' \t\n'
  for tok in $cmdline; do
    case "$tok" in
      "${key}"=*)
        printf '%s\n' "$tok"
        return 0
        ;;
    esac
  done
  return 1
}
cmdline_contains_exact_token() {
  local cmdline="$1" token="$2" tok
  local IFS=$' \t\n'
  [[ -n "$token" ]] || return 1
  for tok in $cmdline; do
    if [[ "$tok" == "$token" ]]; then
      return 0
    fi
  done
  return 1
}
cmdline_remove_key_value_tokens() {
  # Remove all key=value tokens for one key from a cmdline string.
  local cmdline="$1" key="$2" tok out=""
  local IFS=$' \t\n'
  for tok in $cmdline; do
    case "$tok" in
      "${key}"=*) continue ;;
    esac
    out+="${out:+ }$tok"
  done
  trim "$out"
}
cmdline_set_key_value_token() {
  # Replace key=value tokens for this key with the provided token.
  local cmdline="$1" token="$2"
  local key
  key="${token%%=*}"
  local out
  out="$(cmdline_remove_key_value_tokens "$cmdline" "$key")"
  add_param_once "$out" "$token"
}
bls_current_mount_root_token() {
  # Best-effort root= token from current mount metadata.
  # Works in normal boot and inside chroot (where / points at target root).
  have_cmd findmnt || return 1
  local uuid
  uuid="$(findmnt -no UUID / 2>/dev/null || true)"
  uuid="$(trim "${uuid:-}")"
  [[ -n "$uuid" ]] || return 1
  printf 'root=UUID=%s\n' "$uuid"
}
bls_current_mount_rootflags_token() {
  # Best-effort rootflags=subvol=... token from current mount options.
  have_cmd findmnt || return 1
  local opts subvol
  opts="$(findmnt -no OPTIONS / 2>/dev/null || true)"
  opts="$(trim "${opts:-}")"
  [[ -n "$opts" ]] || return 1
  subvol="$(tr ',' '\n' <<<"$opts" | sed -n 's/^subvol=//p' | head -n1)"
  subvol="$(trim "${subvol:-}")"
  [[ -n "$subvol" ]] || return 1
  printf 'rootflags=subvol=%s\n' "$subvol"
}
bls_find_entry_backup_metadata_options() {
  # Return newest backup options for this exact entry path that still contains root=.
  local entry="$1"
  local bak opts
  local best_bak="" best_opts=""
  shopt -s nullglob
  for bak in "${entry}.bak."*; do
    [[ -f "$bak" ]] || continue
    opts="$(bls_entry_options "$bak")"
    opts="$(trim "${opts:-}")"
    [[ -n "$opts" ]] || continue
    if ! cmdline_get_key_value_token "$opts" "root" >/dev/null 2>&1; then
      continue
    fi
    if [[ -z "$best_bak" || "$bak" > "$best_bak" ]]; then
      best_bak="$bak"
      best_opts="$opts"
    fi
  done
  shopt -u nullglob
  [[ -n "$best_opts" ]] || return 1
  printf '%s\n' "$best_opts"
}
bls_find_boot_metadata_options() {
  # Best-effort source for stable boot metadata tokens used by openSUSE BLS:
  # root=, rootflags=, rootfstype=, resume=, systemd.machine_id, ro/rw.
  # Preference order:
  #   1) selected source system entry
  #   2) any current *.conf entry that still contains root=
  #   3) newest backup *.conf.bak.* entry, preferring root/rootflags that
  #      match the currently mounted root subvolume when available
  local dir source opts f
  dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
  [[ -n "$dir" ]] || return 1

  source="$(bls_select_source_system_entry "$dir" 2>/dev/null || true)"
  if [[ -n "$source" && -f "$source" ]]; then
    opts="$(bls_entry_options "$source")"
    opts="$(trim "${opts:-}")"
    if [[ -n "$opts" ]] && cmdline_get_key_value_token "$opts" "root" >/dev/null 2>&1; then
      printf '%s\n' "$opts"
      return 0
    fi
  fi
  shopt -s nullglob
  for f in "$dir"/system-*.conf "$dir"/snapper-*.conf "$dir"/*.conf; do
    [[ -f "$f" ]] || continue
    opts="$(bls_entry_options "$f")"
    opts="$(trim "${opts:-}")"
    [[ -n "$opts" ]] || continue
    if cmdline_get_key_value_token "$opts" "root" >/dev/null 2>&1; then
      printf '%s\n' "$opts"
      shopt -u nullglob
      return 0
    fi
  done
  shopt -u nullglob

  local root_hint_tok rootflags_hint_tok cmdline_file cmdline_opts
  root_hint_tok="$(bls_current_mount_root_token 2>/dev/null || true)"
  rootflags_hint_tok="$(bls_current_mount_rootflags_token 2>/dev/null || true)"
  cmdline_file="$(kernel_cmdline_persistence_file 2>/dev/null || true)"
  cmdline_file="$(trim "${cmdline_file:-}")"
  if [[ -n "$cmdline_file" && -f "$cmdline_file" ]]; then
    cmdline_opts="$(cat "$cmdline_file" 2>/dev/null || true)"
    cmdline_opts="$(trim "${cmdline_opts:-}")"
    if [[ -z "$root_hint_tok" ]]; then
      root_hint_tok="$(cmdline_get_key_value_token "$cmdline_opts" "root" 2>/dev/null || true)"
    fi
    if [[ -z "$rootflags_hint_tok" ]]; then
      rootflags_hint_tok="$(cmdline_get_key_value_token "$cmdline_opts" "rootflags" 2>/dev/null || true)"
    fi
  fi

  local best_bak="" best_opts="" best_score=-1 score

  shopt -s nullglob
  for f in "$dir"/system-*.conf.bak.* "$dir"/snapper-*.conf.bak.* "$dir"/*.conf.bak.*; do
    [[ -f "$f" ]] || continue
    opts="$(bls_entry_options "$f")"
    opts="$(trim "${opts:-}")"
    [[ -n "$opts" ]] || continue
    if ! cmdline_get_key_value_token "$opts" "root" >/dev/null 2>&1; then
      continue
    fi
    score=0
    if [[ -n "$rootflags_hint_tok" ]] && cmdline_contains_exact_token "$opts" "$rootflags_hint_tok"; then
      (( score += 2 ))
    fi
    if [[ -n "$root_hint_tok" ]] && cmdline_contains_exact_token "$opts" "$root_hint_tok"; then
      (( score += 1 ))
    fi
    if (( score > best_score )) || { (( score == best_score )) && [[ -z "$best_bak" || "$f" > "$best_bak" ]]; }; then
      best_score="$score"
      best_bak="$f"
      best_opts="$opts"
    fi
  done
  shopt -u nullglob
  if [[ -n "$best_opts" ]]; then
    printf '%s\n' "$best_opts"
    return 0
  fi
  return 1
}
cmdline_add_boot_metadata_tokens_from_options() {
  # Merge boot-metadata tokens from one options string into another cmdline.
  local cmdline="$1" source_opts="$2"
  local out="$cmdline"
  local tok key
  for key in root rootflags rootfstype resume systemd.machine_id; do
    tok="$(cmdline_get_key_value_token "$source_opts" "$key" 2>/dev/null || true)"
    [[ -n "$tok" ]] && out="$(cmdline_set_key_value_token "$out" "$tok")"
  done
  if grep -Eq '(^|[[:space:]])ro([[:space:]]|$)' <<<"$source_opts"; then
    out="$(add_param_once "$out" "ro")"
  fi
  if grep -Eq '(^|[[:space:]])rw([[:space:]]|$)' <<<"$source_opts"; then
    out="$(add_param_once "$out" "rw")"
  fi
  trim "$out"
}
bls_entry_is_vfio_fallback() {
  local entry="$1" base
  base="$(basename "$entry")"
  if [[ "$base" == fallback-* || "$base" == *-fallback.conf || "$base" == *-novfio.conf ]]; then
    return 0
  fi
  grep -Eq '^# vfio-fallback-entry:[[:space:]]*1([[:space:]]*)?$' "$entry" 2>/dev/null
}
bls_entry_options() {
  local entry="$1"
  grep -m1 -E '^options[[:space:]]+' "$entry" 2>/dev/null | sed -E 's/^options[[:space:]]+//'
}
bls_entry_snapshot_id() {
  # Extract trailing snapshot ID from BLS filename, e.g. *-33.conf -> 33.
  local entry="$1" base
  base="$(basename "$entry")"
  if [[ "$base" =~ -([0-9]+)\.conf$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}
rootflags_snapshot_id_from_token() {
  # Extract snapshot ID from rootflags token when it follows .snapshots/<id>/snapshot.
  local tok="${1:-}" val
  [[ "$tok" == rootflags=* ]] || return 1
  val="${tok#rootflags=}"
  if [[ "$val" =~ \.snapshots/([0-9]+)/snapshot ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}
bls_rootflags_token_for_snapshot_id() {
  local snapshot_id="${1:-}"
  [[ "$snapshot_id" =~ ^[0-9]+$ ]] || return 1
  printf 'rootflags=subvol=@/.snapshots/%s/snapshot\n' "$snapshot_id"
}
bls_rd_driver_pre_remove_vfio_pci() {
  # Remove vfio-pci from one rd.driver.pre= token while preserving other drivers.
  local token="$1"
  local value
  value="${token#rd.driver.pre=}"
  local old_ifs="$IFS"
  IFS=','
  local -a drivers=()
  read -r -a drivers <<<"$value"
  IFS="$old_ifs"

  local -a keep=()
  local driver
  for driver in "${drivers[@]}"; do
    [[ -n "$driver" ]] || continue
    if [[ "$driver" == "vfio-pci" ]]; then
      continue
    fi
    keep+=("$driver")
  done
  if (( ${#keep[@]} == 0 )); then
    return 1
  fi
  local joined
  old_ifs="$IFS"
  IFS=','
  joined="${keep[*]}"
  IFS="$old_ifs"
  printf 'rd.driver.pre=%s\n' "$joined"
}
bls_strip_vfio_forcing_tokens_from_options() {
  # Remove known VFIO-forcing cmdline tokens from one BLS options string.
  local opts="$1"
  local out="" tok
  local IFS=$' \t\n'
  for tok in $opts; do
    case "$tok" in
      vfio-pci.ids=*|pcie_acs_override=*)
        continue
        ;;
      rd.driver.pre=*)
        local rewritten
        rewritten="$(bls_rd_driver_pre_remove_vfio_pci "$tok" 2>/dev/null || true)"
        if [[ -z "$rewritten" ]]; then
          continue
        fi
        tok="$rewritten"
        ;;
    esac
    out+="${out:+ }$tok"
  done
  trim "$out"
}
bls_options_has_forbidden_vfio_tokens() {
  local opts="$1" tok
  local IFS=$' \t\n'
  for tok in $opts; do
    case "$tok" in
      vfio-pci.ids=*|pcie_acs_override=*)
        return 0
        ;;
      rd.driver.pre=*)
        local values
        values=",$(printf '%s' "${tok#rd.driver.pre=}" | tr -s ','),"
        if [[ "$values" == *,vfio-pci,* ]]; then
          return 0
        fi
        ;;
    esac
  done
  return 1
}
bls_fallback_entry_target_path() {
  local source="$1" dir base stem
  dir="$(dirname "$source")"
  base="$(basename "$source")"
  stem="${base%.conf}"
  printf '%s/%s-fallback.conf\n' "$dir" "$stem"
}
bls_select_source_system_entry() {
  # Select a non-fallback system-*.conf source, preferring the currently booted root/rootflags.
  local dir="$1"
  local -a entries=()
  local f
  shopt -s nullglob
  for f in "$dir"/system-*.conf; do
    bls_entry_is_vfio_fallback "$f" && continue
    entries+=("$f")
  done
  shopt -u nullglob
  (( ${#entries[@]} > 0 )) || return 1

  local running_cmdline running_root_tok running_rootflags_tok
  running_cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
  running_root_tok="$(cmdline_get_key_value_token "$running_cmdline" "root" 2>/dev/null || true)"
  running_rootflags_tok="$(cmdline_get_key_value_token "$running_cmdline" "rootflags" 2>/dev/null || true)"

  local entry entry_opts entry_root_tok entry_rootflags_tok
  if [[ -n "$running_root_tok" ]]; then
    for entry in "${entries[@]}"; do
      entry_opts="$(bls_entry_options "$entry")"
      entry_opts="$(trim "${entry_opts:-}")"
      [[ -n "$entry_opts" ]] || continue
      entry_root_tok="$(cmdline_get_key_value_token "$entry_opts" "root" 2>/dev/null || true)"
      [[ "$entry_root_tok" == "$running_root_tok" ]] || continue
      if [[ -n "$running_rootflags_tok" ]]; then
        entry_rootflags_tok="$(cmdline_get_key_value_token "$entry_opts" "rootflags" 2>/dev/null || true)"
        [[ "$entry_rootflags_tok" == "$running_rootflags_tok" ]] || continue
      fi
      printf '%s\n' "$entry"
      return 0
    done
  fi

  printf '%s\n' "${entries[0]}"
}
bls_render_fallback_entry_from_source() {
  # Emit fallback entry content from a source BLS entry.
  local source="$1"
  local line marker_written=0 options_seen=0
  local opts sanitized title
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Normalize marker placement by writing one canonical marker ourselves.
    if [[ "$line" =~ ^#\ vfio-fallback-entry: ]]; then
      continue
    fi

    if [[ "$line" =~ ^title[[:space:]]+ ]]; then
      title="$(sed -E 's/^title[[:space:]]+//' <<<"$line")"
      if [[ "$title" != *"(fallback)"* ]]; then
        line="title ${title} (fallback)"
      fi
    fi

    if [[ "$line" =~ ^options[[:space:]]+ ]]; then
      if (( marker_written == 0 )); then
        printf '# vfio-fallback-entry: 1\n'
        marker_written=1
      fi
      opts="$(sed -E 's/^options[[:space:]]+//' <<<"$line")"
      sanitized="$(bls_strip_vfio_forcing_tokens_from_options "$opts")"
      printf 'options %s\n' "$sanitized"
      options_seen=1
      continue
    fi

    printf '%s\n' "$line"
  done <"$source"

  if (( marker_written == 0 )); then
    printf '# vfio-fallback-entry: 1\n'
  fi
  if (( options_seen == 0 )); then
    printf 'options \n'
  fi
}
create_or_update_bls_fallback_entry() {
  local fail_count=0
  local -a fail_assertions=()

  if ! is_opensuse_like; then
    (( fail_count += 1 ))
    fail_assertions+=("opensuse_like_required")
  fi

  local bl
  bl="$(detect_bootloader 2>/dev/null || true)"
  if [[ "$bl" != "grub2-bls" && "$bl" != "systemd-boot" ]]; then
    (( fail_count += 1 ))
    fail_assertions+=("bls_bootloader_required:detected=${bl:-unknown}")
  fi

  local dir
  dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
  if [[ -z "$dir" ]]; then
    (( fail_count += 1 ))
    fail_assertions+=("bls_entries_dir_present")
  fi

  local source_entry=""
  if [[ -n "$dir" ]]; then
    source_entry="$(bls_select_source_system_entry "$dir" 2>/dev/null || true)"
    if [[ -z "$source_entry" || ! -f "$source_entry" ]]; then
      (( fail_count += 1 ))
      fail_assertions+=("source_system_entry_present")
    fi
  fi

  local target_entry=""
  if [[ -n "$source_entry" ]]; then
    target_entry="$(bls_fallback_entry_target_path "$source_entry")"
    if [[ "$target_entry" == "$source_entry" ]]; then
      (( fail_count += 1 ))
      fail_assertions+=("target_entry_distinct_from_source")
    fi
  fi

  local tmp=""
  if [[ -n "$source_entry" ]]; then
    tmp="$(mktemp)"
    bls_render_fallback_entry_from_source "$source_entry" >"$tmp"

    local candidate_opts
    candidate_opts="$(bls_entry_options "$tmp")"
    candidate_opts="$(trim "${candidate_opts:-}")"
    if ! grep -Eq '^# vfio-fallback-entry:[[:space:]]*1([[:space:]]*)?$' "$tmp" 2>/dev/null; then
      (( fail_count += 1 ))
      fail_assertions+=("fallback_marker_present_in_rendered_entry")
    fi
    if [[ -z "$candidate_opts" ]]; then
      (( fail_count += 1 ))
      fail_assertions+=("fallback_options_line_present")
    elif bls_options_has_forbidden_vfio_tokens "$candidate_opts"; then
      (( fail_count += 1 ))
      fail_assertions+=("fallback_options_forbidden_tokens_absent")
    fi
  fi

  if (( fail_count > 0 )); then
    if [[ -n "$tmp" ]]; then
      rm -f "$tmp" || true
    fi
    say "FAIL SUMMARY (${fail_count})"
    local item
    for item in "${fail_assertions[@]}"; do
      say "  - assertion: $item"
    done
    return 1
  fi

  local target_existed=0 changed=1 wrote=0
  if [[ -f "$target_entry" ]]; then
    target_existed=1
    if have_cmd cmp && cmp -s "$tmp" "$target_entry"; then
      changed=0
    fi
  fi

  if (( changed )); then
    if (( DRY_RUN )); then
      if (( target_existed )); then
        say "DRY RUN: would update fallback BLS entry $(basename "$target_entry") from source $(basename "$source_entry")."
      else
        say "DRY RUN: would create fallback BLS entry $(basename "$target_entry") from source $(basename "$source_entry")."
      fi
    else
      local mode owner group
      if (( target_existed )); then
        backup_file "$target_entry"
        mode="$(stat -c '%a' "$target_entry")"
        owner="$(stat -c '%u' "$target_entry")"
        group="$(stat -c '%g' "$target_entry")"
      else
        mode="$(stat -c '%a' "$source_entry" 2>/dev/null || echo 644)"
        owner="$(stat -c '%u' "$source_entry" 2>/dev/null || id -u)"
        group="$(stat -c '%g' "$source_entry" 2>/dev/null || id -g)"
      fi
      install -o "$owner" -g "$group" -m "$mode" "$tmp" "$target_entry"
      wrote=1
    fi
  fi

  local verify_path verify_opts
  verify_path="$tmp"
  if (( ! DRY_RUN )); then
    verify_path="$target_entry"
  fi
  verify_opts="$(bls_entry_options "$verify_path")"
  verify_opts="$(trim "${verify_opts:-}")"
  if ! bls_entry_is_vfio_fallback "$verify_path"; then
    (( fail_count += 1 ))
    fail_assertions+=("fallback_marker_present_in_written_entry")
  fi
  if [[ -z "$verify_opts" ]]; then
    (( fail_count += 1 ))
    fail_assertions+=("written_fallback_options_line_present")
  elif bls_options_has_forbidden_vfio_tokens "$verify_opts"; then
    (( fail_count += 1 ))
    fail_assertions+=("written_fallback_options_forbidden_tokens_absent")
  fi

  rm -f "$tmp" || true

  if (( fail_count > 0 )); then
    say "FAIL SUMMARY (${fail_count})"
    local item
    for item in "${fail_assertions[@]}"; do
      say "  - assertion: $item"
    done
    return 1
  fi

  if (( ! DRY_RUN )); then
    if (( changed )); then
      if (( target_existed )); then
        say "Updated fallback BLS entry: $(basename "$target_entry")"
      else
        say "Created fallback BLS entry: $(basename "$target_entry")"
      fi
    else
      say "Fallback BLS entry already up to date: $(basename "$target_entry")"
    fi
  fi
  say "Source BLS entry: $(basename "$source_entry")"
  say "PASS SUMMARY (1)"
  say "Fallback entry verification passed."
  if (( ! DRY_RUN )) && (( wrote == 0 )) && (( changed == 0 )); then
    return 0
  fi
  return 0
}
bls_fallback_entry_detect_status() {
  # Read-only status report for openSUSE BLS fallback readiness.
  # Emits key=value lines:
  #   BOOTLOADER, STATUS, REASON, SOURCE_ENTRY, TARGET_ENTRY
  local bootloader status reason source_entry target_entry dir target_opts tmp
  local in_sync

  bootloader="$(detect_bootloader 2>/dev/null || true)"
  status="NOT_APPLICABLE"
  reason=""
  source_entry=""
  target_entry=""
  in_sync=0

  if ! is_opensuse_like; then
    reason="openSUSE-like system not detected"
    printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
    printf 'STATUS=%s\n' "$status"
    printf 'REASON=%s\n' "$reason"
    printf 'SOURCE_ENTRY=\n'
    printf 'TARGET_ENTRY=\n'
    return 0
  fi

  if [[ "$bootloader" != "grub2-bls" && "$bootloader" != "systemd-boot" ]]; then
    reason="Boot Loader Spec fallback applies only to grub2-bls/systemd-boot (detected: ${bootloader:-unknown})"
    printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
    printf 'STATUS=%s\n' "$status"
    printf 'REASON=%s\n' "$reason"
    printf 'SOURCE_ENTRY=\n'
    printf 'TARGET_ENTRY=\n'
    return 0
  fi

  dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
  if [[ -z "$dir" ]]; then
    status="INVALID"
    reason="Boot Loader Spec entries directory not found"
    printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
    printf 'STATUS=%s\n' "$status"
    printf 'REASON=%s\n' "$reason"
    printf 'SOURCE_ENTRY=\n'
    printf 'TARGET_ENTRY=\n'
    return 0
  fi

  source_entry="$(bls_select_source_system_entry "$dir" 2>/dev/null || true)"
  if [[ -z "$source_entry" || ! -f "$source_entry" ]]; then
    status="INVALID"
    reason="Source system BLS entry was not found"
    printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
    printf 'STATUS=%s\n' "$status"
    printf 'REASON=%s\n' "$reason"
    printf 'SOURCE_ENTRY=\n'
    printf 'TARGET_ENTRY=\n'
    return 0
  fi

  target_entry="$(bls_fallback_entry_target_path "$source_entry")"
  if [[ -z "$target_entry" ]]; then
    status="INVALID"
    reason="Could not derive fallback entry path from source"
    printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
    printf 'STATUS=%s\n' "$status"
    printf 'REASON=%s\n' "$reason"
    printf 'SOURCE_ENTRY=%s\n' "$source_entry"
    printf 'TARGET_ENTRY=\n'
    return 0
  fi

  if [[ ! -f "$target_entry" ]]; then
    status="MISSING"
    reason="Fallback entry file is missing"
    printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
    printf 'STATUS=%s\n' "$status"
    printf 'REASON=%s\n' "$reason"
    printf 'SOURCE_ENTRY=%s\n' "$source_entry"
    printf 'TARGET_ENTRY=%s\n' "$target_entry"
    return 0
  fi

  target_opts="$(bls_entry_options "$target_entry")"
  target_opts="$(trim "${target_opts:-}")"
  if ! bls_entry_is_vfio_fallback "$target_entry"; then
    status="INVALID"
    reason="Fallback marker is missing from fallback entry"
    printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
    printf 'STATUS=%s\n' "$status"
    printf 'REASON=%s\n' "$reason"
    printf 'SOURCE_ENTRY=%s\n' "$source_entry"
    printf 'TARGET_ENTRY=%s\n' "$target_entry"
    return 0
  fi
  if [[ -z "$target_opts" ]]; then
    status="INVALID"
    reason="Fallback entry options line is missing"
    printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
    printf 'STATUS=%s\n' "$status"
    printf 'REASON=%s\n' "$reason"
    printf 'SOURCE_ENTRY=%s\n' "$source_entry"
    printf 'TARGET_ENTRY=%s\n' "$target_entry"
    return 0
  fi
  if bls_options_has_forbidden_vfio_tokens "$target_opts"; then
    status="INVALID"
    reason="Fallback entry options still contain VFIO-forcing tokens"
    printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
    printf 'STATUS=%s\n' "$status"
    printf 'REASON=%s\n' "$reason"
    printf 'SOURCE_ENTRY=%s\n' "$source_entry"
    printf 'TARGET_ENTRY=%s\n' "$target_entry"
    return 0
  fi

  tmp="$(mktemp)"
  bls_render_fallback_entry_from_source "$source_entry" >"$tmp"
  if have_cmd cmp; then
    if cmp -s "$tmp" "$target_entry"; then
      in_sync=1
    fi
  elif have_cmd diff; then
    if diff -q "$tmp" "$target_entry" >/dev/null 2>&1; then
      in_sync=1
    fi
  else
    if [[ "$(cat "$tmp" 2>/dev/null || true)" == "$(cat "$target_entry" 2>/dev/null || true)" ]]; then
      in_sync=1
    fi
  fi
  rm -f "$tmp" || true

  if (( in_sync )); then
    status="OK"
    reason="Fallback entry is present and synchronized with source entry"
  else
    status="OUTDATED"
    reason="Fallback entry exists but differs from expected rendered fallback"
  fi

  printf 'BOOTLOADER=%s\n' "${bootloader:-unknown}"
  printf 'STATUS=%s\n' "$status"
  printf 'REASON=%s\n' "$reason"
  printf 'SOURCE_ENTRY=%s\n' "$source_entry"
  printf 'TARGET_ENTRY=%s\n' "$target_entry"
}
maybe_offer_detect_fallback_entry_create() {
  [[ "${MODE:-}" == "detect" ]] || return 0

  local report status reason source_entry target_entry bootloader
  report="$(bls_fallback_entry_detect_status)"
  status=""
  reason=""
  source_entry=""
  target_entry=""
  bootloader=""

  local key value
  while IFS='=' read -r key value; do
    case "$key" in
      BOOTLOADER) bootloader="$value" ;;
      STATUS) status="$value" ;;
      REASON) reason="$value" ;;
      SOURCE_ENTRY) source_entry="$value" ;;
      TARGET_ENTRY) target_entry="$value" ;;
    esac
  done <<<"$report"

  [[ -n "$status" ]] || return 0
  [[ "$status" == "NOT_APPLICABLE" ]] && return 0

  local source_name target_name
  source_name="<unknown>"
  target_name="<unknown>"
  [[ -n "$source_entry" ]] && source_name="$(basename "$source_entry")"
  [[ -n "$target_entry" ]] && target_name="$(basename "$target_entry")"

  say
  if (( ENABLE_COLOR )); then
    say "${C_CYAN}-- Boot Loader Spec fallback entry (openSUSE-specific) --${C_RESET}"
  else
    say "-- Boot Loader Spec fallback entry (openSUSE-specific) --"
  fi
  print_kv "Bootloader (detected)" "${bootloader:-unknown}"
  print_kv "Source entry" "$source_name"
  print_kv "Fallback entry" "$target_name"

  case "$status" in
    OK)
      print_kv "Fallback status" "OK (synchronized)"
      return 0
      ;;
    MISSING)
      print_kv "Fallback status" "MISSING"
      ;;
    OUTDATED)
      print_kv "Fallback status" "OUTDATED"
      ;;
    INVALID)
      print_kv "Fallback status" "INVALID"
      ;;
    *)
      print_kv "Fallback status" "$status"
      ;;
  esac

  [[ -n "$reason" ]] && note "Reason: $reason"
  note "Recommendation: run $SCRIPT_NAME --create-fallback-entry"

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    note "Run as root to create or update the fallback entry."
    return 0
  fi

  if ! prompt_yn "Create/update fallback BLS entry now from detect mode?" N "BLS fallback entry"; then
    return 0
  fi
  if ! confirm_phrase "This will edit Boot Loader Spec entry files now." "CREATE FALLBACK ENTRY"; then
    note "Skipping fallback entry remediation (confirmation phrase not provided)."
    return 0
  fi

  local prev_dry="${DRY_RUN:-0}"
  DRY_RUN=0
  if create_or_update_bls_fallback_entry; then
    say "Fallback entry remediation completed from detect mode."
  else
    note "Fallback entry remediation failed; review FAIL SUMMARY above."
  fi
  DRY_RUN="$prev_dry"
}

# Enforce that every Boot Loader Spec entry options line follows the current
# /etc/kernel/cmdline baseline while preserving per-entry root metadata needed
# for snapshot-aware boots.
sync_bls_entries_from_kernel_cmdline() {
  if ! is_opensuse_like; then
    return 0
  fi

  local bl
  bl="$(detect_bootloader 2>/dev/null || true)"
  if [[ "$bl" != "grub2-bls" && "$bl" != "systemd-boot" ]]; then
    return 0
  fi

  local cmdline_file
  cmdline_file="$(kernel_cmdline_persistence_file 2>/dev/null || true)"
  cmdline_file="$(trim "${cmdline_file:-}")"
  if [[ -z "$cmdline_file" ]]; then
    note "Skipping BLS entry sync: kernel cmdline persistence path is empty."
    return 0
  fi

  if [[ ! -f "$cmdline_file" ]]; then
    note "Skipping BLS entry sync: $cmdline_file is missing."
    return 0
  fi
  kernel_cmdline_rehydrate_boot_metadata_if_missing "$cmdline_file" || true
  kernel_cmdline_reconcile_boot_metadata_with_current_mount "$cmdline_file" || true

  local base_cmdline
  base_cmdline="$(cat "$cmdline_file" 2>/dev/null || true)"
  base_cmdline="$(trim "${base_cmdline:-}")"
  if [[ -z "$base_cmdline" ]]; then
    note "Skipping BLS entry sync: $cmdline_file is empty."
    return 0
  fi
  local fallback_metadata_opts
  local base_file_root_tok base_file_rootflags_tok
  local base_fallback_root_tok base_fallback_rootflags_tok
  local mount_root_tok mount_rootflags_tok
  local proc_root_tok proc_rootflags_tok
  local base_root_source base_rootflags_source
  local running_boot_opts running_root_tok
  fallback_metadata_opts="$(bls_find_boot_metadata_options 2>/dev/null || true)"
  base_file_root_tok="$(cmdline_get_key_value_token "$base_cmdline" "root" 2>/dev/null || true)"
  base_file_rootflags_tok="$(cmdline_get_key_value_token "$base_cmdline" "rootflags" 2>/dev/null || true)"
  base_fallback_root_tok=""
  base_fallback_rootflags_tok=""
  mount_root_tok=""
  mount_rootflags_tok=""
  proc_root_tok=""
  proc_rootflags_tok=""
  base_root_source=""
  base_rootflags_source=""
  running_boot_opts=""
  running_root_tok=""
  if [[ -n "$base_file_root_tok" ]]; then
    base_root_source="kernel_cmdline_file"
  fi
  if [[ -n "$base_file_rootflags_tok" ]]; then
    base_rootflags_source="kernel_cmdline_file"
  fi

  if [[ -n "$fallback_metadata_opts" ]]; then
    base_cmdline="$(cmdline_add_boot_metadata_tokens_from_options "$base_cmdline" "$fallback_metadata_opts")"
    base_fallback_root_tok="$(cmdline_get_key_value_token "$fallback_metadata_opts" "root" 2>/dev/null || true)"
    base_fallback_rootflags_tok="$(cmdline_get_key_value_token "$fallback_metadata_opts" "rootflags" 2>/dev/null || true)"
    if [[ -n "$base_fallback_root_tok" ]]; then
      base_root_source="bls_metadata_options"
    fi
    if [[ -n "$base_fallback_rootflags_tok" ]]; then
      base_rootflags_source="bls_metadata_options"
    fi
  fi
  if ! cmdline_get_key_value_token "$base_cmdline" "root" >/dev/null 2>&1; then
    mount_root_tok="$(bls_current_mount_root_token 2>/dev/null || true)"
    mount_rootflags_tok="$(bls_current_mount_rootflags_token 2>/dev/null || true)"
    if [[ -n "$mount_root_tok" ]]; then
      base_cmdline="$(cmdline_set_key_value_token "$base_cmdline" "$mount_root_tok")"
      base_root_source="current_mount_metadata"
    fi
    if [[ -n "$mount_rootflags_tok" ]]; then
      base_cmdline="$(cmdline_set_key_value_token "$base_cmdline" "$mount_rootflags_tok")"
      base_rootflags_source="current_mount_metadata"
    fi
  fi
  if ! cmdline_get_key_value_token "$base_cmdline" "root" >/dev/null 2>&1; then
    running_boot_opts="$(cat /proc/cmdline 2>/dev/null || true)"
    if [[ -n "$running_boot_opts" ]]; then
      proc_root_tok="$(cmdline_get_key_value_token "$running_boot_opts" "root" 2>/dev/null || true)"
      proc_rootflags_tok="$(cmdline_get_key_value_token "$running_boot_opts" "rootflags" 2>/dev/null || true)"
      base_cmdline="$(cmdline_add_boot_metadata_tokens_from_options "$base_cmdline" "$running_boot_opts")"
      running_root_tok="$(cmdline_get_key_value_token "$base_cmdline" "root" 2>/dev/null || true)"
      if [[ -n "$running_root_tok" ]]; then
        base_root_source="proc_cmdline"
        [[ -n "$proc_rootflags_tok" ]] && base_rootflags_source="proc_cmdline"
        note "Recovered root boot metadata for BLS sync baseline from running /proc/cmdline."
      fi
    fi
  fi
  if ! cmdline_get_key_value_token "$base_cmdline" "root" >/dev/null 2>&1; then
    note "BLS sync baseline has no global root=... metadata after trying $cmdline_file, BLS backups, current mount metadata, and /proc/cmdline."
    note "Continuing with per-entry root preservation; entries without provable root metadata will be skipped for safety."
  fi
  local base_root_tok base_rootflags_tok base_rootfstype_tok base_resume_tok base_machine_id_tok
  base_root_tok="$(cmdline_get_key_value_token "$base_cmdline" "root" 2>/dev/null || true)"
  base_rootflags_tok="$(cmdline_get_key_value_token "$base_cmdline" "rootflags" 2>/dev/null || true)"
  base_rootfstype_tok="$(cmdline_get_key_value_token "$base_cmdline" "rootfstype" 2>/dev/null || true)"
  base_resume_tok="$(cmdline_get_key_value_token "$base_cmdline" "resume" 2>/dev/null || true)"
  base_machine_id_tok="$(cmdline_get_key_value_token "$base_cmdline" "systemd.machine_id" 2>/dev/null || true)"
  if [[ -z "$base_root_source" ]]; then
    [[ -n "$base_root_tok" ]] && base_root_source="unknown"
  fi
  if [[ -z "$base_rootflags_source" ]]; then
    [[ -n "$base_rootflags_tok" ]] && base_rootflags_source="unknown"
  fi
  if (( DEBUG_CMDLINE_TOKENS )); then
    say "DEBUG[BLS baseline-candidate]: kernel_cmdline root=${base_file_root_tok:-<none>} rootflags=${base_file_rootflags_tok:-<none>}"
    say "DEBUG[BLS baseline-candidate]: bls_metadata root=${base_fallback_root_tok:-<none>} rootflags=${base_fallback_rootflags_tok:-<none>}"
    say "DEBUG[BLS baseline-candidate]: current_mount root=${mount_root_tok:-<none>} rootflags=${mount_rootflags_tok:-<none>}"
    say "DEBUG[BLS baseline-candidate]: proc_cmdline root=${proc_root_tok:-<none>} rootflags=${proc_rootflags_tok:-<none>}"
    say "DEBUG[BLS baseline]: root source=${base_root_source:-none} token=${base_root_tok:-<none>}"
    say "DEBUG[BLS baseline]: rootflags source=${base_rootflags_source:-none} token=${base_rootflags_tok:-<none>}"
  fi

  local dir
  dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
  if [[ -z "$dir" ]]; then
    note "Skipping BLS entry sync: loader entries directory was not found."
    return 0
  fi

  local -a entries=()
  local f
  shopt -s nullglob
  for f in "$dir"/*.conf; do
    entries+=("$f")
  done
  shopt -u nullglob

  if (( ${#entries[@]} == 0 )); then
    note "Skipping BLS entry sync: no *.conf entries found under $dir."
    return 0
  fi

  local changed=0 examined=0 snapper_skipped=0 root_examined=0 fallback_skipped=0 root_missing_skipped=0
  local debug_filter_skipped=0
  local current_opts merged_opts root_tok rootflags_tok rootfstype_tok resume_tok machine_id_tok root_source rootflags_source
  local entry_snapshot_id entry_snapshot_rootflags_tok current_rootflags_snapshot_id
  local entry_backup_opts backup_root_tok backup_rootflags_tok backup_rootfstype_tok backup_resume_tok backup_machine_id_tok
  local entry_name
  for f in "${entries[@]}"; do
    entry_name="$(basename "$f")"
    if bls_entry_is_vfio_fallback "$f"; then
      (( fallback_skipped += 1 ))
      continue
    fi
    if [[ "$entry_name" == snapper-* ]]; then
      (( snapper_skipped += 1 ))
      continue
    fi
    if (( DEBUG_CMDLINE_TOKENS )) && [[ -n "${DEBUG_CMDLINE_TOKENS_ENTRY_FILTER:-}" ]]; then
      # shellcheck disable=SC2053
      if [[ "$entry_name" != $DEBUG_CMDLINE_TOKENS_ENTRY_FILTER ]]; then
        (( debug_filter_skipped += 1 ))
        continue
      fi
    fi
    current_opts="$(grep -m1 -E '^options[[:space:]]+' "$f" 2>/dev/null | sed -E 's/^options[[:space:]]+//')"
    current_opts="$(trim "${current_opts:-}")"
    [[ -n "$current_opts" ]] || continue
    (( examined += 1 ))
    (( root_examined += 1 ))

    merged_opts="$base_cmdline"
    root_tok="$(cmdline_get_key_value_token "$current_opts" "root" 2>/dev/null || true)"
    rootflags_tok="$(cmdline_get_key_value_token "$current_opts" "rootflags" 2>/dev/null || true)"
    rootfstype_tok="$(cmdline_get_key_value_token "$current_opts" "rootfstype" 2>/dev/null || true)"
    resume_tok="$(cmdline_get_key_value_token "$current_opts" "resume" 2>/dev/null || true)"
    machine_id_tok="$(cmdline_get_key_value_token "$current_opts" "systemd.machine_id" 2>/dev/null || true)"
    root_source=""
    rootflags_source=""
    [[ -n "$root_tok" ]] && root_source="entry_options"
    [[ -n "$rootflags_tok" ]] && rootflags_source="entry_options"
    entry_backup_opts="$(bls_find_entry_backup_metadata_options "$f" 2>/dev/null || true)"
    backup_root_tok=""
    backup_rootflags_tok=""
    backup_rootfstype_tok=""
    backup_resume_tok=""
    backup_machine_id_tok=""
    if [[ -n "$entry_backup_opts" ]]; then
      backup_root_tok="$(cmdline_get_key_value_token "$entry_backup_opts" "root" 2>/dev/null || true)"
      backup_rootflags_tok="$(cmdline_get_key_value_token "$entry_backup_opts" "rootflags" 2>/dev/null || true)"
      backup_rootfstype_tok="$(cmdline_get_key_value_token "$entry_backup_opts" "rootfstype" 2>/dev/null || true)"
      backup_resume_tok="$(cmdline_get_key_value_token "$entry_backup_opts" "resume" 2>/dev/null || true)"
      backup_machine_id_tok="$(cmdline_get_key_value_token "$entry_backup_opts" "systemd.machine_id" 2>/dev/null || true)"

      if [[ -n "$backup_root_tok" ]]; then
        if [[ -z "$root_tok" ]]; then
          root_tok="$backup_root_tok"
          root_source="entry_backup"
        elif [[ -n "$base_root_tok" && "$root_tok" == "$base_root_tok" && "$backup_root_tok" != "$base_root_tok" ]]; then
          root_tok="$backup_root_tok"
          root_source="entry_backup_preferred_over_baseline"
        fi
      fi
      if [[ -n "$backup_rootflags_tok" ]]; then
        if [[ -z "$rootflags_tok" ]]; then
          rootflags_tok="$backup_rootflags_tok"
          rootflags_source="entry_backup"
        elif [[ -n "$base_rootflags_tok" && "$rootflags_tok" == "$base_rootflags_tok" && "$backup_rootflags_tok" != "$base_rootflags_tok" ]]; then
          rootflags_tok="$backup_rootflags_tok"
          rootflags_source="entry_backup_preferred_over_baseline"
        fi
      fi
      if [[ -n "$backup_rootfstype_tok" ]]; then
        if [[ -z "$rootfstype_tok" ]]; then
          rootfstype_tok="$backup_rootfstype_tok"
        elif [[ -n "$base_rootfstype_tok" && "$rootfstype_tok" == "$base_rootfstype_tok" && "$backup_rootfstype_tok" != "$base_rootfstype_tok" ]]; then
          rootfstype_tok="$backup_rootfstype_tok"
        fi
      fi
      if [[ -n "$backup_resume_tok" ]]; then
        if [[ -z "$resume_tok" ]]; then
          resume_tok="$backup_resume_tok"
        elif [[ -n "$base_resume_tok" && "$resume_tok" == "$base_resume_tok" && "$backup_resume_tok" != "$base_resume_tok" ]]; then
          resume_tok="$backup_resume_tok"
        fi
      fi
      if [[ -n "$backup_machine_id_tok" ]]; then
        if [[ -z "$machine_id_tok" ]]; then
          machine_id_tok="$backup_machine_id_tok"
        elif [[ -n "$base_machine_id_tok" && "$machine_id_tok" == "$base_machine_id_tok" && "$backup_machine_id_tok" != "$base_machine_id_tok" ]]; then
          machine_id_tok="$backup_machine_id_tok"
        fi
      fi
    fi
    if [[ -z "$root_tok" && -n "$fallback_metadata_opts" ]]; then
      root_tok="$(cmdline_get_key_value_token "$fallback_metadata_opts" "root" 2>/dev/null || true)"
      [[ -n "$root_tok" ]] && root_source="bls_metadata_options"
    fi
    if [[ -z "$rootflags_tok" && -n "$fallback_metadata_opts" ]]; then
      rootflags_tok="$(cmdline_get_key_value_token "$fallback_metadata_opts" "rootflags" 2>/dev/null || true)"
      [[ -n "$rootflags_tok" ]] && rootflags_source="bls_metadata_options"
    fi
    if [[ -z "$rootfstype_tok" && -n "$fallback_metadata_opts" ]]; then
      rootfstype_tok="$(cmdline_get_key_value_token "$fallback_metadata_opts" "rootfstype" 2>/dev/null || true)"
    fi
    if [[ -z "$resume_tok" && -n "$fallback_metadata_opts" ]]; then
      resume_tok="$(cmdline_get_key_value_token "$fallback_metadata_opts" "resume" 2>/dev/null || true)"
    fi
    if [[ -z "$machine_id_tok" && -n "$fallback_metadata_opts" ]]; then
      machine_id_tok="$(cmdline_get_key_value_token "$fallback_metadata_opts" "systemd.machine_id" 2>/dev/null || true)"
    fi
    entry_snapshot_id="$(bls_entry_snapshot_id "$f" 2>/dev/null || true)"
    if [[ -n "$entry_snapshot_id" ]]; then
      entry_snapshot_rootflags_tok="$(bls_rootflags_token_for_snapshot_id "$entry_snapshot_id" 2>/dev/null || true)"
      current_rootflags_snapshot_id="$(rootflags_snapshot_id_from_token "${rootflags_tok:-}" 2>/dev/null || true)"
      if [[ -n "$entry_snapshot_rootflags_tok" ]] && [[ "$current_rootflags_snapshot_id" != "$entry_snapshot_id" ]]; then
        rootflags_tok="$entry_snapshot_rootflags_tok"
        rootflags_source="entry_snapshot_filename"
      fi
    fi
    if [[ -z "$root_tok" ]]; then
      if [[ -n "$base_root_tok" ]]; then
        root_tok="$base_root_tok"
        root_source="baseline_cmdline"
      else
        (( root_missing_skipped += 1 ))
        if (( DEBUG_CMDLINE_TOKENS )); then
          say "DEBUG[BLS entry ${entry_name}]: root source=none token=<none> (skipped)"
          say "DEBUG[BLS entry ${entry_name}]: rootflags source=${rootflags_source:-none} token=${rootflags_tok:-<none>}"
        fi
        note "Skipping BLS sync for ${entry_name}: unable to determine root=... metadata for this entry."
        continue
      fi
    fi
    if (( DEBUG_CMDLINE_TOKENS )); then
      local debug_rootflags_tok
      debug_rootflags_tok="${rootflags_tok:-}"
      if [[ -z "$debug_rootflags_tok" && -n "$base_rootflags_tok" ]]; then
        debug_rootflags_tok="$base_rootflags_tok"
        [[ -z "$rootflags_source" ]] && rootflags_source="baseline_cmdline"
      fi
      say "DEBUG[BLS entry ${entry_name}]: root source=${root_source:-none} token=${root_tok:-<none>}"
      say "DEBUG[BLS entry ${entry_name}]: rootflags source=${rootflags_source:-none} token=${debug_rootflags_tok:-<none>}"
    fi

    [[ -n "$root_tok" ]] && merged_opts="$(cmdline_set_key_value_token "$merged_opts" "$root_tok")"
    [[ -n "$rootflags_tok" ]] && merged_opts="$(cmdline_set_key_value_token "$merged_opts" "$rootflags_tok")"
    [[ -n "$rootfstype_tok" ]] && merged_opts="$(cmdline_set_key_value_token "$merged_opts" "$rootfstype_tok")"
    [[ -n "$resume_tok" ]] && merged_opts="$(cmdline_set_key_value_token "$merged_opts" "$resume_tok")"
    [[ -n "$machine_id_tok" ]] && merged_opts="$(cmdline_set_key_value_token "$merged_opts" "$machine_id_tok")"

    if grep -Eq '(^|[[:space:]])ro([[:space:]]|$)' <<<"$current_opts"; then
      merged_opts="$(add_param_once "$merged_opts" "ro")"
    elif [[ -n "$entry_backup_opts" ]] && grep -Eq '(^|[[:space:]])ro([[:space:]]|$)' <<<"$entry_backup_opts"; then
      merged_opts="$(add_param_once "$merged_opts" "ro")"
    elif [[ -n "$fallback_metadata_opts" ]] && grep -Eq '(^|[[:space:]])ro([[:space:]]|$)' <<<"$fallback_metadata_opts"; then
      merged_opts="$(add_param_once "$merged_opts" "ro")"
    fi
    if grep -Eq '(^|[[:space:]])rw([[:space:]]|$)' <<<"$current_opts"; then
      merged_opts="$(add_param_once "$merged_opts" "rw")"
    elif [[ -n "$entry_backup_opts" ]] && grep -Eq '(^|[[:space:]])rw([[:space:]]|$)' <<<"$entry_backup_opts"; then
      merged_opts="$(add_param_once "$merged_opts" "rw")"
    elif [[ -n "$fallback_metadata_opts" ]] && grep -Eq '(^|[[:space:]])rw([[:space:]]|$)' <<<"$fallback_metadata_opts"; then
      merged_opts="$(add_param_once "$merged_opts" "rw")"
    fi

    merged_opts="$(trim "$merged_opts")"
    if [[ "$merged_opts" == "$current_opts" ]]; then
      continue
    fi

    systemd_boot_write_options "$f" "$merged_opts"
    (( changed += 1 ))
  done

  if (( changed == 0 )); then
    if (( root_missing_skipped > 0 )) || (( debug_filter_skipped > 0 )); then
      note "No Boot Loader Spec entries were synchronized from /etc/kernel/cmdline (${examined} root/system entries checked, ${root_missing_skipped} skipped due missing root metadata, ${snapper_skipped} snapper skipped, ${fallback_skipped} fallback skipped, ${debug_filter_skipped} filtered by --entry)."
    else
      note "Boot Loader Spec options are already synchronized with /etc/kernel/cmdline (${examined} root/system entries checked, ${snapper_skipped} snapper skipped, ${fallback_skipped} fallback skipped)."
    fi
    return 0
  fi

  local entry_word="entries"
  if (( changed == 1 )); then
    entry_word="entry"
  fi
  if (( DRY_RUN )); then
    say "DRY RUN: would synchronize ${changed} Boot Loader Spec ${entry_word} from $cmdline_file (${examined} root/system entries checked, ${root_missing_skipped} skipped due missing root metadata, ${snapper_skipped} snapper skipped, ${fallback_skipped} fallback skipped, ${debug_filter_skipped} filtered by --entry)."
  else
    say "Synchronized ${changed} Boot Loader Spec ${entry_word} from $cmdline_file (preserved per-entry root/rootflags/systemd.machine_id metadata; ${examined} root/system entries checked, ${root_missing_skipped} skipped due missing root metadata, ${snapper_skipped} snapper skipped, ${fallback_skipped} fallback skipped, ${debug_filter_skipped} filtered by --entry)."
  fi
  return 0
}
debug_bls_cmdline_tokens() {
  local prev_debug="${DEBUG_CMDLINE_TOKENS:-0}"
  local prev_dry="${DRY_RUN:-0}"
  local rc=0
  local sync_output=""

  DEBUG_CMDLINE_TOKENS=1
  DRY_RUN=1

  if (( JSON_OUTPUT )); then
    if sync_output="$(sync_bls_entries_from_kernel_cmdline)"; then
      rc=0
    else
      rc=$?
    fi
    debug_cmdline_tokens_print_json_lines "$sync_output" "$rc"
  else
    say
    hdr "BLS cmdline token source debug"
    note "Tracing root/rootflags source selection in read-only dry-run mode."
    if [[ -n "${DEBUG_CMDLINE_TOKENS_ENTRY_FILTER:-}" ]]; then
      note "Applying entry filter: ${DEBUG_CMDLINE_TOKENS_ENTRY_FILTER}"
    fi
    sync_bls_entries_from_kernel_cmdline || rc=$?
  fi

  DRY_RUN="$prev_dry"
  DEBUG_CMDLINE_TOKENS="$prev_debug"
  return "$rc"
}
verify_bls_entries_against_kernel_cmdline() {
  local fail_count=0
  local -a fail_assertions=()

  if ! is_opensuse_like; then
    say "FAIL SUMMARY (1)"
    say "  - assertion: opensuse_like_required"
    say "    detail: this verification mode is intended for openSUSE-style BLS systems"
    return 1
  fi

  local bl
  bl="$(detect_bootloader 2>/dev/null || true)"
  if [[ "$bl" != "grub2-bls" && "$bl" != "systemd-boot" ]]; then
    say "FAIL SUMMARY (1)"
    say "  - assertion: bls_bootloader_required"
    say "    detail: detected bootloader '$bl' (expected grub2-bls or systemd-boot)"
    return 1
  fi

  local cmdline_file
  cmdline_file="$(kernel_cmdline_persistence_file 2>/dev/null || true)"
  cmdline_file="$(trim "${cmdline_file:-}")"
  if [[ -z "$cmdline_file" ]]; then
    say "FAIL SUMMARY (1)"
    say "  - assertion: kernel_cmdline_path_nonempty"
    say "    detail: kernel cmdline persistence path is empty"
    return 1
  fi
  if [[ ! -f "$cmdline_file" ]]; then
    say "FAIL SUMMARY (1)"
    say "  - assertion: kernel_cmdline_file_present"
    say "    detail: missing $cmdline_file"
    return 1
  fi

  local base_cmdline
  base_cmdline="$(cat "$cmdline_file" 2>/dev/null || true)"
  base_cmdline="$(trim "${base_cmdline:-}")"
  if [[ -z "$base_cmdline" ]]; then
    say "FAIL SUMMARY (1)"
    say "  - assertion: kernel_cmdline_nonempty"
    say "    detail: $cmdline_file is empty"
    return 1
  fi
  if ! cmdline_get_key_value_token "$base_cmdline" "root" >/dev/null 2>&1; then
    (( fail_count += 1 ))
    fail_assertions+=("kernel_cmdline_root_token_present")
  fi
  local mount_root_tok mount_rootflags_tok base_root_tok base_rootflags_tok
  mount_root_tok="$(bls_current_mount_root_token 2>/dev/null || true)"
  mount_rootflags_tok="$(bls_current_mount_rootflags_token 2>/dev/null || true)"
  base_root_tok="$(cmdline_get_key_value_token "$base_cmdline" "root" 2>/dev/null || true)"
  base_rootflags_tok="$(cmdline_get_key_value_token "$base_cmdline" "rootflags" 2>/dev/null || true)"
  if [[ -n "$mount_root_tok" && "$base_root_tok" != "$mount_root_tok" ]]; then
    (( fail_count += 1 ))
    fail_assertions+=("kernel_cmdline_root_matches_current_mount")
  fi
  if [[ -n "$mount_rootflags_tok" && "$base_rootflags_tok" != "$mount_rootflags_tok" ]]; then
    (( fail_count += 1 ))
    fail_assertions+=("kernel_cmdline_rootflags_matches_current_mount")
  fi

  local expected_base_cmdline
  expected_base_cmdline="$base_cmdline"
  local fallback_metadata_opts
  fallback_metadata_opts="$(bls_find_boot_metadata_options 2>/dev/null || true)"
  if [[ -n "$fallback_metadata_opts" ]]; then
    expected_base_cmdline="$(cmdline_add_boot_metadata_tokens_from_options "$expected_base_cmdline" "$fallback_metadata_opts")"
  fi
  if ! cmdline_get_key_value_token "$expected_base_cmdline" "root" >/dev/null 2>&1; then
    (( fail_count += 1 ))
    fail_assertions+=("kernel_cmdline_effective_root_token_present")
  fi

  local dir
  dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
  if [[ -z "$dir" ]]; then
    say "FAIL SUMMARY (1)"
    say "  - assertion: bls_entries_dir_present"
    say "    detail: loader entries directory was not found"
    return 1
  fi

  local -a entries=()
  local f
  shopt -s nullglob
  for f in "$dir"/*.conf; do
    entries+=("$f")
  done
  shopt -u nullglob
  if (( ${#entries[@]} == 0 )); then
    say "FAIL SUMMARY (1)"
    say "  - assertion: bls_entries_present"
    say "    detail: no *.conf entries found under $dir"
    return 1
  fi

  local examined=0 snapper_skipped=0 root_examined=0 fallback_skipped=0
  local current_opts expected_opts root_tok rootflags_tok rootfstype_tok resume_tok machine_id_tok tok
  local -a missing_tokens=() extra_tokens=()
  for f in "${entries[@]}"; do
    if bls_entry_is_vfio_fallback "$f"; then
      (( fallback_skipped += 1 ))
      continue
    fi
    if [[ "$(basename "$f")" == snapper-* ]]; then
      (( snapper_skipped += 1 ))
      continue
    fi
    current_opts="$(grep -m1 -E '^options[[:space:]]+' "$f" 2>/dev/null | sed -E 's/^options[[:space:]]+//')"
    current_opts="$(trim "${current_opts:-}")"
    if [[ -z "$current_opts" ]]; then
      (( fail_count += 1 ))
      fail_assertions+=("options_line_present:$(basename "$f")")
      continue
    fi
    if ! cmdline_get_key_value_token "$current_opts" "root" >/dev/null 2>&1; then
      (( fail_count += 1 ))
      fail_assertions+=("entry_root_token_present:$(basename "$f")")
    fi

    (( examined += 1 ))
    (( root_examined += 1 ))

    expected_opts="$expected_base_cmdline"
    root_tok="$(cmdline_get_key_value_token "$current_opts" "root" 2>/dev/null || true)"
    rootflags_tok="$(cmdline_get_key_value_token "$current_opts" "rootflags" 2>/dev/null || true)"
    rootfstype_tok="$(cmdline_get_key_value_token "$current_opts" "rootfstype" 2>/dev/null || true)"
    resume_tok="$(cmdline_get_key_value_token "$current_opts" "resume" 2>/dev/null || true)"
    machine_id_tok="$(cmdline_get_key_value_token "$current_opts" "systemd.machine_id" 2>/dev/null || true)"
    [[ -n "$root_tok" ]] && expected_opts="$(cmdline_set_key_value_token "$expected_opts" "$root_tok")"
    [[ -n "$rootflags_tok" ]] && expected_opts="$(cmdline_set_key_value_token "$expected_opts" "$rootflags_tok")"
    [[ -n "$rootfstype_tok" ]] && expected_opts="$(cmdline_set_key_value_token "$expected_opts" "$rootfstype_tok")"
    [[ -n "$resume_tok" ]] && expected_opts="$(cmdline_set_key_value_token "$expected_opts" "$resume_tok")"
    [[ -n "$machine_id_tok" ]] && expected_opts="$(cmdline_set_key_value_token "$expected_opts" "$machine_id_tok")"
    if grep -Eq '(^|[[:space:]])ro([[:space:]]|$)' <<<"$current_opts"; then
      expected_opts="$(add_param_once "$expected_opts" "ro")"
    fi
    if grep -Eq '(^|[[:space:]])rw([[:space:]]|$)' <<<"$current_opts"; then
      expected_opts="$(add_param_once "$expected_opts" "rw")"
    fi
    expected_opts="$(trim "$expected_opts")"

    if [[ "$expected_opts" == "$current_opts" ]]; then
      continue
    fi

    (( fail_count += 1 ))
    fail_assertions+=("options_sync_with_kernel_cmdline:$(basename "$f")")
    missing_tokens=()
    extra_tokens=()
    for tok in $expected_opts; do
      if ! cmdline_contains_exact_token "$current_opts" "$tok"; then
        missing_tokens+=("$tok")
      fi
    done
    for tok in $current_opts; do
      if ! cmdline_contains_exact_token "$expected_opts" "$tok"; then
        extra_tokens+=("$tok")
      fi
    done
    say "DRIFT: $(basename "$f")"
    if (( ${#missing_tokens[@]} > 0 )); then
      say "  missing: ${missing_tokens[*]}"
    fi
    if (( ${#extra_tokens[@]} > 0 )); then
      say "  unexpected: ${extra_tokens[*]}"
    fi
  done

  if (( examined == 0 )); then
    say "FAIL SUMMARY (1)"
    say "  - assertion: nonsnapper_nonfallback_bls_entries_present"
    say "    detail: no non-snapper, non-fallback Boot Loader Spec entries were found under $dir (${snapper_skipped} snapper skipped, ${fallback_skipped} fallback skipped)"
    return 1
  fi

  if (( fail_count > 0 )); then
    say "FAIL SUMMARY (${fail_count})"
    local item
    for item in "${fail_assertions[@]}"; do
      say "  - assertion: $item"
    done
    say "Checked entries: ${examined} root/system (${snapper_skipped} snapper skipped, ${fallback_skipped} fallback skipped)"
    return 1
  fi

  say "PASS SUMMARY (${examined})"
  say "All Boot Loader Spec root/system entries are synchronized with $cmdline_file (${root_examined} root/system, ${snapper_skipped} snapper skipped, ${fallback_skipped} fallback skipped)."
  return 0
}
verify_bls_no_snapper_writes() {
  # Regression guard: ensure sync logic never targets snapper-* entries for writes.
  if ! is_opensuse_like; then
    say "FAIL SUMMARY (1)"
    say "  - assertion: opensuse_like_required"
    say "    detail: this regression mode is intended for openSUSE-style BLS systems"
    return 1
  fi

  local bl
  bl="$(detect_bootloader 2>/dev/null || true)"
  if [[ "$bl" != "grub2-bls" && "$bl" != "systemd-boot" ]]; then
    say "FAIL SUMMARY (1)"
    say "  - assertion: bls_bootloader_required"
    say "    detail: detected bootloader '$bl' (expected grub2-bls or systemd-boot)"
    return 1
  fi

  local dir
  dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
  if [[ -z "$dir" ]]; then
    say "FAIL SUMMARY (1)"
    say "  - assertion: bls_entries_dir_present"
    say "    detail: loader entries directory was not found"
    return 1
  fi

  local -a snapper_entries=()
  local f
  shopt -s nullglob
  for f in "$dir"/snapper-*.conf; do
    [[ -f "$f" ]] || continue
    snapper_entries+=("$f")
  done
  shopt -u nullglob

  VFIO_BLS_SNAPPER_WRITE_ATTEMPTS=0
  VFIO_BLS_SNAPPER_WRITE_ATTEMPT_PATHS=()

  local prev_dry="${DRY_RUN:-0}"
  DRY_RUN=1
  sync_bls_entries_from_kernel_cmdline || true
  DRY_RUN="$prev_dry"

  if (( VFIO_BLS_SNAPPER_WRITE_ATTEMPTS > 0 )); then
    say "FAIL SUMMARY (1)"
    say "  - assertion: no_snapper_bls_write_attempts"
    say "    detail: detected ${VFIO_BLS_SNAPPER_WRITE_ATTEMPTS} attempted write target(s) under snapper-* entries"
    local p
    for p in "${VFIO_BLS_SNAPPER_WRITE_ATTEMPT_PATHS[@]}"; do
      say "    attempted: $(basename "$p")"
    done
    return 1
  fi

  if (( ${#snapper_entries[@]} == 0 )); then
    say "PASS SUMMARY (1)"
    say "No snapper-* BLS entries were found under $dir, and no snapper write attempts were observed."
    return 0
  fi

  say "PASS SUMMARY (1)"
  say "No snapper BLS write attempts detected (${#snapper_entries[@]} snapper entries observed)."
  return 0
}

# On openSUSE systems that use Boot Loader Spec (systemd-boot or grub2-bls),
# kernel parameters are persisted via /etc/kernel/cmdline and propagated to
# loader entries using sdbootutil. This helper wraps that propagation so we
# don't rely on editing individual *.conf files by hand.
opensuse_sdbootutil_update_all_entries() {
  if ! is_opensuse_like; then
    return 0
  fi
  local bl
  bl="$(detect_bootloader 2>/dev/null || true)"
  if [[ "$bl" != "grub2-bls" && "$bl" != "systemd-boot" ]]; then
    return 0
  fi

  local cmdline_file
  cmdline_file="$(kernel_cmdline_persistence_file 2>/dev/null || true)"
  cmdline_file="$(trim "${cmdline_file:-}")"
  if [[ -n "$cmdline_file" && -f "$cmdline_file" ]]; then
    kernel_cmdline_rehydrate_boot_metadata_if_missing "$cmdline_file" || true
  fi

  local sdbootutil_ok=0
  if have_cmd sdbootutil; then
    say "Updating Boot Loader Spec entries via: sdbootutil add-all-kernels && sdbootutil update-all-entries (errors will be ignored by this helper)"
    # Call sdbootutil directly and silence its stdout/stderr to avoid leaking
    # internal sed errors or similar implementation details to the user.
    # We try add-all-kernels first (to ensure all installed kernels have
    # BLS entries) and then update-all-entries to sync options/initrds.
    if sdbootutil add-all-kernels >/dev/null 2>&1 && \
       sdbootutil update-all-entries >/dev/null 2>&1; then
      sdbootutil_ok=1
    else
      note "sdbootutil add-all-kernels/update-all-entries reported an error; falling back to direct BLS option synchronization from /etc/kernel/cmdline."
    fi
  else
    note "sdbootutil is not available; applying direct BLS option synchronization from /etc/kernel/cmdline."
  fi

  sync_bls_entries_from_kernel_cmdline
  # Keep snapper-* entries untouched; only root/system entries are synchronized.

  if (( sdbootutil_ok == 0 )); then
    note "BLS entry option sync completed without a clean sdbootutil run; review entries if your setup relies on sdbootutil-managed boot artifacts."
  fi
  return 0
}

# Safely rewrite the options line for a single systemd-boot entry.
systemd_boot_write_options() {
  local entry="$1" new_opts="$2"
  [[ -f "$entry" ]] || die "systemd-boot entry not found: $entry"
  if [[ "$(basename "$entry")" == snapper-* ]]; then
    (( VFIO_BLS_SNAPPER_WRITE_ATTEMPTS += 1 ))
    VFIO_BLS_SNAPPER_WRITE_ATTEMPT_PATHS+=("$entry")
  fi

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
    local cmdline_root_tok cmdline_rootflags_tok cmdline_rootfstype_tok cmdline_resume_tok cmdline_machine_id_tok
    cmdline_root_tok="$(cmdline_get_key_value_token "$cmdline_content" "root" 2>/dev/null || true)"
    cmdline_rootflags_tok="$(cmdline_get_key_value_token "$cmdline_content" "rootflags" 2>/dev/null || true)"
    cmdline_rootfstype_tok="$(cmdline_get_key_value_token "$cmdline_content" "rootfstype" 2>/dev/null || true)"
    cmdline_resume_tok="$(cmdline_get_key_value_token "$cmdline_content" "resume" 2>/dev/null || true)"
    cmdline_machine_id_tok="$(cmdline_get_key_value_token "$cmdline_content" "systemd.machine_id" 2>/dev/null || true)"
    # Base params: IOMMU and any extras discovered earlier. Framebuffer
    # mitigation (video=efifb:off, etc.) is handled by a dedicated prompt
    # below so users understand why it is needed and can skip it if they
    # know their boot VGA path is already safe.
    local -a params_to_add=("$(cpu_iommu_param)" "iommu=pt")
    if [[ -n "${GRUB_EXTRA_PARAMS:-}" ]]; then
      local -a extra=()
      read -r -a extra <<<"${GRUB_EXTRA_PARAMS}"
      params_to_add+=("${extra[@]}")
    fi
    local new_cmdline="$cmdline_content"
    
    local p
    for p in "${params_to_add[@]}"; do
      new_cmdline="$(add_param_once "$new_cmdline" "$p")"
    done
    new_cmdline="$(append_guest_vfio_ids_with_detect_fallback "$new_cmdline" "/etc/kernel/cmdline (persistence)")"
    local boot_metadata_opts
    boot_metadata_opts="$(bls_find_boot_metadata_options 2>/dev/null || true)"
    if [[ -n "$boot_metadata_opts" ]]; then
      new_cmdline="$(cmdline_add_boot_metadata_tokens_from_options "$new_cmdline" "$boot_metadata_opts")"
    fi
    # Optional: USB/xHCI stability workaround for hosts that can freeze or
    # spam disconnects due to USB runtime PM / PCIe ASPM interactions.
    say
    hdr "USB/xHCI power-management stability (optional)"
    note "If your host shows xHCI hangs, USB disconnect storms, or freezes under USB load, this optional workaround can help."
    note "It adds: usbcore.autosuspend=-1 pcie_aspm=off"
    note "Why optional: it can increase idle power usage and is only needed on affected systems."
    if prompt_yn "Add usbcore.autosuspend=-1 and pcie_aspm=off to /etc/kernel/cmdline? (optional workaround)" N "USB/xHCI stability"; then
      new_cmdline="$(add_param_once "$new_cmdline" "usbcore.autosuspend=-1")"
      new_cmdline="$(add_param_once "$new_cmdline" "pcie_aspm=off")"
    else
      note "Skipping USB/xHCI power workaround parameters."
    fi

    # Optional: boot framebuffer / Boot VGA mitigation. On many systems the
    # EFI/simple framebuffer can "pin" the guest GPU memory and prevent
    # reliable VFIO binding (symptoms include black screens, "Header type 127",
    # or hangs when starting the VM). These parameters tell the kernel not
    # to use those early framebuffers for the console.
    say
    hdr "Boot framebuffer (Boot VGA) mitigation (optional)"
    note "On some setups the EFI/simple framebuffer (efifb/vesafb/sysfb) can lock your guest GPU and cause black screens or hangs when using VFIO."
    note "If you pass your primary/Boot VGA dGPU to a VM, disabling these framebuffers is often recommended."
    note "If your guest GPU is a secondary card and the host only uses an iGPU or a different card for the boot console, you may not need this."
    local fb_default="N"
    if [[ -n "${CTX[guest_gpu]:-}" && "$(pci_boot_vga_flag "${CTX[guest_gpu]}")" == "1" ]]; then
      if is_opensuse_like; then
        fb_default="N"
        note "Detected guest GPU as Boot VGA on this boot, but on openSUSE we default this mitigation to NO for safer first boot behavior."
        note "Enable it only if you confirm early framebuffer locking is causing passthrough failures."
      else
        fb_default="Y"
        note "Detected guest GPU as Boot VGA on this boot; defaulting this mitigation to YES."
      fi
    else
      note "Guest GPU does not appear to be Boot VGA on this boot; defaulting this mitigation to NO."
    fi
    if prompt_yn "Add video=efifb:off video=vesafb:off initcall_blacklist=sysfb_init to /etc/kernel/cmdline?" "$fb_default" "Boot framebuffer mitigation"; then
      new_cmdline="$(add_param_once "$new_cmdline" "video=efifb:off")"
      new_cmdline="$(add_param_once "$new_cmdline" "video=vesafb:off")"
      new_cmdline="$(add_param_once "$new_cmdline" "initcall_blacklist=sysfb_init")"
    else
      note "Keeping existing framebuffer settings. If you later see black screens or "Header type 127" when starting the VM, rerun and enable this option."
    fi

    # Optional: disable SELinux/AppArmor at the kernel level.
    # On openSUSE Tumbleweed with Btrfs rollbacks, enabling SELinux
    # or AppArmor on a rolled-back root can easily cause confusing
    # boot failures (desktop spin+reboot, services denied writes on
    # read-only or mislabelled subvolumes, etc.). This helper is
    # not LSM-policy aware, so the safest default for passthrough
    # debugging is to turn those off via selinux=0 apparmor=0.
    say
    hdr "Kernel security modules (SELinux/AppArmor, optional)"
    note "By default this helper keeps existing SELinux/AppArmor settings unchanged."
    note "Only disable them for troubleshooting if you have confirmed policy denials are causing VFIO boot/login failures."
    if prompt_yn "Disable SELinux and AppArmor in kernel parameters (add selinux=0 apparmor=0 and remove security=selinux/apparmor)?" N "Kernel security modules"; then
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
    if prompt_yn "Disable boot splash / quiet and enable detailed text logs on boot?" N "Boot verbosity (persistence)"; then
      new_cmdline="$(remove_param_all "$new_cmdline" "quiet")"
      new_cmdline="$(remove_param_all "$new_cmdline" "splash=silent")"
      new_cmdline="$(remove_param_all "$new_cmdline" "splash")"
      new_cmdline="$(remove_param_all "$new_cmdline" "rhgb")"
      new_cmdline="$(add_param_once "$new_cmdline" "systemd.show_status=1")"
      new_cmdline="$(add_param_once "$new_cmdline" "loglevel=7")"
      # Stronger Plymouth disable (initramfs + userspace).
      new_cmdline="$(add_param_once "$new_cmdline" "rd.plymouth=0")"
      new_cmdline="$(add_param_once "$new_cmdline" "plymouth.enable=0")"
      disable_plymouth_services
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
    new_cmdline="$(add_custom_kernel_params_interactive "$new_cmdline" "/etc/kernel/cmdline (persistence)")"

    # Preserve current persisted boot metadata unless explicitly unavailable.
    # This keeps root/rootflags stable across additive parameter updates.
    if [[ -n "$cmdline_root_tok" || -n "$cmdline_rootflags_tok" || -n "$cmdline_rootfstype_tok" || -n "$cmdline_resume_tok" || -n "$cmdline_machine_id_tok" ]]; then
      new_cmdline="$(cmdline_add_boot_metadata_tokens_from_options "$new_cmdline" "$cmdline_content")"
    fi
    if ! cmdline_get_key_value_token "$new_cmdline" "root" >/dev/null 2>&1; then
      local mount_root_tok mount_rootflags_tok
      mount_root_tok="$(bls_current_mount_root_token 2>/dev/null || true)"
      mount_rootflags_tok="$(bls_current_mount_rootflags_token 2>/dev/null || true)"
      [[ -n "$mount_root_tok" ]] && new_cmdline="$(cmdline_set_key_value_token "$new_cmdline" "$mount_root_tok")"
      [[ -n "$mount_rootflags_tok" ]] && new_cmdline="$(cmdline_set_key_value_token "$new_cmdline" "$mount_rootflags_tok")"
    fi
    if ! cmdline_get_key_value_token "$new_cmdline" "root" >/dev/null 2>&1; then
      local running_boot_opts running_root_tok
      running_boot_opts="$(cat /proc/cmdline 2>/dev/null || true)"
      if [[ -n "$running_boot_opts" ]]; then
        new_cmdline="$(cmdline_add_boot_metadata_tokens_from_options "$new_cmdline" "$running_boot_opts")"
        running_root_tok="$(cmdline_get_key_value_token "$new_cmdline" "root" 2>/dev/null || true)"
        if [[ -n "$running_root_tok" ]]; then
          note "Recovered root boot metadata for /etc/kernel/cmdline candidate from running /proc/cmdline."
        fi
      fi
    fi
    if ! cmdline_get_key_value_token "$new_cmdline" "root" >/dev/null 2>&1; then
      local recovered_boot_opts recovered_cmdline recovered_root_tok
      recovered_boot_opts="$(bls_find_boot_metadata_options 2>/dev/null || true)"
      if [[ -n "$recovered_boot_opts" ]]; then
        recovered_cmdline="$(cmdline_add_boot_metadata_tokens_from_options "$new_cmdline" "$recovered_boot_opts")"
        recovered_root_tok="$(cmdline_get_key_value_token "$recovered_cmdline" "root" 2>/dev/null || true)"
        if [[ -n "$recovered_root_tok" ]]; then
          say
          hdr "openSUSE BLS safety recovery"
          note "Detected missing root=... token in /etc/kernel/cmdline candidate."
          note "Recovered boot metadata from existing Boot Loader Spec entries."
          note "Recovered root token: $recovered_root_tok"
          if [[ -r /dev/tty && -w /dev/tty ]]; then
            if prompt_yn "Apply recovered boot metadata (root/rootflags/rootfstype/resume/systemd.machine_id) and continue?" Y "openSUSE BLS safety"; then
              new_cmdline="$recovered_cmdline"
              note "Applied recovered boot metadata and continuing with persistence update."
            else
              note "Skipped metadata recovery by user choice."
            fi
          else
            new_cmdline="$recovered_cmdline"
            note "Applied recovered boot metadata automatically (non-interactive context)."
          fi
        fi
      fi
    fi
    if ! cmdline_get_key_value_token "$new_cmdline" "root" >/dev/null 2>&1; then
      note "openSUSE BLS safety: /etc/kernel/cmdline has no explicit root=... token."
      note "Skipping /etc/kernel/cmdline write to avoid unsafe persistence and /dev/gpt-auto-root boot hangs."
      note "VFIO setup will continue, but persistent kernel parameter changes were not applied."
      note "Run this helper from the installed target root (with a valid root=... cmdline) to apply persistent kernel parameters safely."
      return 0
    fi

    if [[ "$(trim "$new_cmdline")" != "$(trim "$cmdline_content")" ]]; then
      if preview_cmdline_change_interactive "$cmdline_content" "$new_cmdline" "/etc/kernel/cmdline (persistence)"; then
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
      fi
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

  local -a params_to_add=("$(cpu_iommu_param)" "iommu=pt")
  if [[ -n "${GRUB_EXTRA_PARAMS:-}" ]]; then
    local -a extra=()
    read -r -a extra <<<"${GRUB_EXTRA_PARAMS}"
    params_to_add+=("${extra[@]}")
  fi
  local new_opts="$current_opts"
  for p in "${params_to_add[@]}"; do
    new_opts="$(add_param_once "$new_opts" "$p")"
  done
  new_opts="$(append_guest_vfio_ids_with_detect_fallback "$new_opts" "systemd-boot entry options")"

  # Optional: USB/xHCI stability workaround for the selected live entry.
  say
  hdr "USB/xHCI power-management stability (optional)"
  note "If your host can freeze or spam USB disconnects because of xHCI/USB power transitions, this optional workaround can help."
  note "It adds: usbcore.autosuspend=-1 pcie_aspm=off"
  note "Trade-off: increased idle power usage."
  if prompt_yn "Add usbcore.autosuspend=-1 and pcie_aspm=off to this boot entry? (optional workaround)" N "USB/xHCI stability (systemd-boot)"; then
    new_opts="$(add_param_once "$new_opts" "usbcore.autosuspend=-1")"
    new_opts="$(add_param_once "$new_opts" "pcie_aspm=off")"
  else
    note "Skipping USB/xHCI power workaround parameters for this entry."
  fi
  
  # If the user chose verbose boot in the persistence step, mirror that
  # here so the CURRENT entry immediately shows logs instead of splash.
  if (( verbose_persist )); then
    new_opts="$(remove_param_all "$new_opts" "quiet")"
    new_opts="$(remove_param_all "$new_opts" "splash=silent")"
    new_opts="$(remove_param_all "$new_opts" "splash")"
    new_opts="$(remove_param_all "$new_opts" "rhgb")"
    new_opts="$(add_param_once "$new_opts" "systemd.show_status=1")"
    new_opts="$(add_param_once "$new_opts" "loglevel=7")"
    new_opts="$(add_param_once "$new_opts" "rd.plymouth=0")"
    new_opts="$(add_param_once "$new_opts" "plymouth.enable=0")"
  fi
  
  say
  hdr "Advanced (optional): ACS override (systemd-boot)"
  if prompt_yn "Enable ACS override (pcie_acs_override=downstream,multifunction) in this entry?" N "Boot options (systemd-boot)"; then
    new_opts="$(add_param_once "$new_opts" "pcie_acs_override=downstream,multifunction")"
  fi
  new_opts="$(add_custom_kernel_params_interactive "$new_opts" "systemd-boot entry")"

  if [[ "$(trim "$new_opts")" == "$(trim "$current_opts")" ]]; then
    say "systemd-boot entry options unchanged (params already present)."
    return 0
  fi
  if ! preview_cmdline_change_interactive "$current_opts" "$new_opts" "systemd-boot entry options"; then
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
  say "Optional stability workaround for USB/xHCI crashes/freezes (only if needed):"
  say "  usbcore.autosuspend=-1 pcie_aspm=off"
  say "Advanced (usually NOT recommended): pcie_acs_override=downstream,multifunction"
  say "  - Only consider this if your IOMMU groups are not isolated."
  say "  - It can reduce PCIe isolation and may cause instability on some systems."
}

grub_add_kernel_params() {
  # Merge standard params with any discovered extras. Framebuffer mitigation
  # (video=efifb:off, etc.) is offered via an explicit prompt below so that
  # users understand why it is being added.
  local -a params_to_add=("$(cpu_iommu_param)" "iommu=pt")
  if [[ -n "${GRUB_EXTRA_PARAMS:-}" ]]; then
    local -a extra=()
    read -r -a extra <<<"${GRUB_EXTRA_PARAMS}"
    params_to_add+=("${extra[@]}")
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
  new="$(append_guest_vfio_ids_with_detect_fallback "$new" "GRUB kernel cmdline")"

  # Optional USB/xHCI power-management workaround.
  say
  hdr "USB/xHCI power-management stability (optional)"
  note "If your host sometimes freezes or logs xHCI/USB disconnect storms, this optional workaround can improve stability."
  note "It adds: usbcore.autosuspend=-1 pcie_aspm=off"
  note "Why optional: it can increase idle power usage and is not needed on all systems."
  if prompt_yn "Add usbcore.autosuspend=-1 and pcie_aspm=off to GRUB kernel parameters? (optional workaround)" N "USB/xHCI stability (GRUB)"; then
    new="$(add_param_once "$new" "usbcore.autosuspend=-1")"
    new="$(add_param_once "$new" "pcie_aspm=off")"
  else
    note "Leaving USB/xHCI power-management parameters unchanged."
  fi

  # Optional: boot framebuffer / Boot VGA mitigation for GRUB systems.
  # This mirrors the openSUSE /etc/kernel/cmdline behavior: we can
  # disable efifb/vesafb/sysfb to avoid early framebuffers pinning the
  # guest GPU.
  say
  hdr "Boot framebuffer (Boot VGA) mitigation (optional)"
  note "On some systems, early EFI/vesa framebuffers can keep the guest GPU busy and interfere with VFIO (black screens, hangs, \"Header type 127\")."
  note "If you are passing your primary dGPU (Boot VGA) to a VM, disabling those framebuffers is usually recommended."
  note "If the host only uses an iGPU or a different card for the console, you may not need this."
  local grub_fb_default="N"
  if [[ -n "${CTX[guest_gpu]:-}" && "$(pci_boot_vga_flag "${CTX[guest_gpu]}")" == "1" ]] && ! is_opensuse_like; then
    grub_fb_default="Y"
  fi
  if prompt_yn "Add video=efifb:off video=vesafb:off initcall_blacklist=sysfb_init to GRUB kernel parameters?" "$grub_fb_default" "Boot framebuffer mitigation"; then
    new="$(add_param_once "$new" "video=efifb:off")"
    new="$(add_param_once "$new" "video=vesafb:off")"
    new="$(add_param_once "$new" "initcall_blacklist=sysfb_init")"
  else
    note "Leaving framebuffer parameters unchanged. If you later hit black screens at VM start, rerun and enable this option."
  fi
 
  # Optional: disable SELinux/AppArmor on GRUB-based systems as
  # well to match the openSUSE BLS path.
  say
  hdr "Kernel security modules (SELinux/AppArmor)"
  note "On systems that use Btrfs rollbacks (like openSUSE), SELinux/AppArmor combined with an older root snapshot can cause boot issues."
  note "This helper focuses on VFIO and does not manage LSM policy, so for stable passthrough testing it is often safest to turn them off."
  if prompt_yn "Disable SELinux and AppArmor in GRUB kernel parameters (selinux=0 apparmor=0)?" N "Kernel security modules"; then
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
  if prompt_yn "Disable boot splash / quiet and enable detailed text logs on boot?" N "Boot verbosity"; then
    new="$(remove_param_all "$new" "quiet")"
    new="$(remove_param_all "$new" "splash=silent")"
    new="$(remove_param_all "$new" "splash")"
    new="$(remove_param_all "$new" "rhgb")"
    new="$(add_param_once "$new" "systemd.show_status=1")"
    new="$(add_param_once "$new" "loglevel=7")"
    # Stronger Plymouth disable (initramfs + userspace).
    new="$(add_param_once "$new" "rd.plymouth=0")"
    new="$(add_param_once "$new" "plymouth.enable=0")"
    disable_plymouth_services
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
  new="$(add_custom_kernel_params_interactive "$new" "GRUB cmdline")"

  # Safety: do not silently rewrite if nothing changed.
  local grub_cmdline_changed=0
  if [[ "$(trim "$new")" == "$(trim "$current")" ]]; then
    say "GRUB cmdline unchanged (params already present)."
  else
    if preview_cmdline_change_interactive "$current" "$new" "GRUB kernel cmdline"; then
      grub_write_cmdline_in_place "$key" "$(trim "$new")"
      grub_cmdline_changed=1
    fi
  fi

  if (( grub_cmdline_changed )); then
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
  else
    note "Skipping GRUB config regeneration because kernel cmdline was not changed."
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

# Fail-safe: do not steal the active Boot VGA GPU during normal host boot
# unless the host GPU is explicitly configured as a different non-Boot-VGA
# adapter. Set VFIO_ALLOW_BOOT_VGA=1 to force binding unconditionally.
if [[ -f "/sys/bus/pci/devices/$GUEST_GPU_BDF/boot_vga" ]]; then
  guest_boot_vga="$(cat "/sys/bus/pci/devices/$GUEST_GPU_BDF/boot_vga" 2>/dev/null || echo 0)"
  boot_vga_policy="${VFIO_BOOT_VGA_POLICY:-STRICT}"
  boot_vga_policy="${boot_vga_policy^^}"
  case "$boot_vga_policy" in
    AUTO|STRICT) ;;
    *) boot_vga_policy="STRICT" ;;
  esac
  if [[ "$guest_boot_vga" == "1" ]] && [[ "${VFIO_ALLOW_BOOT_VGA:-0}" != "1" ]]; then
    allow_boot_vga_bind=0
    allow_boot_vga_reason="none"
    host_assisted_boot_vga_bind=0
    if [[ -n "${HOST_GPU_BDF:-}" ]] && [[ "$HOST_GPU_BDF" != "$GUEST_GPU_BDF" ]] && [[ -f "/sys/bus/pci/devices/$HOST_GPU_BDF/boot_vga" ]]; then
      host_boot_vga="$(cat "/sys/bus/pci/devices/$HOST_GPU_BDF/boot_vga" 2>/dev/null || echo 1)"
      if [[ "$host_boot_vga" == "0" ]]; then
        host_assisted_boot_vga_bind=1
        if [[ "${VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU:-0}" == "1" ]]; then
          allow_boot_vga_bind=1
          allow_boot_vga_reason="explicit_opt_in"
        fi
        if [[ "$boot_vga_policy" == "AUTO" ]]; then
          allow_boot_vga_bind=1
          allow_boot_vga_reason="auto_detect"
        fi
      fi
    fi

    if [[ "$allow_boot_vga_bind" == "1" ]]; then
      say "WARN: $GUEST_GPU_BDF is Boot VGA, and HOST_GPU_BDF=${HOST_GPU_BDF:-} has boot_vga=0."
      if [[ "$allow_boot_vga_reason" == "auto_detect" ]]; then
        say "INFO: VFIO_BOOT_VGA_POLICY=AUTO auto-detected a safe host-assisted topology; proceeding with vfio bind."
        say "INFO: Set VFIO_BOOT_VGA_POLICY=STRICT to require explicit VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1."
      else
        say "WARN: VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1 is set; proceeding with host-assisted vfio bind."
        say "INFO: Set VFIO_ALLOW_BOOT_VGA=1 to force this behavior without host GPU checks."
      fi
    else
      say "WARN: $GUEST_GPU_BDF is Boot VGA; skipping vfio-pci bind to keep host graphics alive."
      if [[ "$host_assisted_boot_vga_bind" == "1" ]]; then
        say "INFO: HOST_GPU_BDF=${HOST_GPU_BDF:-} has boot_vga=0."
        say "INFO: Set VFIO_BOOT_VGA_POLICY=AUTO (recommended) or VFIO_ALLOW_BOOT_VGA_IF_HOST_GPU=1 to allow host-assisted Boot VGA binding."
      else
        say "INFO: Set HOST_GPU_BDF to a different GPU (boot_vga=0) or set VFIO_ALLOW_BOOT_VGA=1 to force binding."
      fi
      exit 0
    fi
  fi
fi

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
ExecStartPost=/bin/sh -c 'if [ -x /usr/local/sbin/vfio-graphics-protocold.sh ]; then /usr/local/sbin/vfio-graphics-protocold.sh --once --prelogin || true; fi'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  run systemctl daemon-reload
  run systemctl enable vfio-bind-selected-gpu.service
}
ensure_graphics_daemon_deployment_safety() {
  # Guardrail for partial/failed deployments:
  # if a unit exists without its daemon script, disable and remove the stale unit.
  local changed=0
  local cond_line="ConditionPathExists=$GRAPHICS_DAEMON_SCRIPT"

  if [[ -f "$GRAPHICS_DAEMON_UNIT" && ! -f "$GRAPHICS_DAEMON_SCRIPT" ]]; then
    note "Detected incomplete graphics daemon deployment (unit present, script missing)."
    if have_cmd systemctl; then
      run systemctl disable --now vfio-graphics-protocold.service 2>/dev/null || true
    fi
    run rm -f "$GRAPHICS_DAEMON_WANTS_LINK" 2>/dev/null || true
    run rm -f "$GRAPHICS_DAEMON_UNIT" 2>/dev/null || true
    changed=1
  fi

  if [[ -f "$GRAPHICS_DAEMON_UNIT" ]] && ! grep -Fqx "$cond_line" "$GRAPHICS_DAEMON_UNIT"; then
    backup_file "$GRAPHICS_DAEMON_UNIT"
    if (( ! DRY_RUN )); then
      local tmp
      tmp="$(mktemp)"
      awk -v cond="$cond_line" '
        {
          print
          if ($0 ~ /^ConditionPathExists=\/etc\/vfio-gpu-passthrough\.conf$/) {
            print cond
          }
        }
      ' "$GRAPHICS_DAEMON_UNIT" >"$tmp"
      install -m 0644 -o root -g root "$tmp" "$GRAPHICS_DAEMON_UNIT"
      rm -f "$tmp" || true
    fi
    changed=1
  fi

  if (( changed )) && have_cmd systemctl; then
    run systemctl daemon-reload 2>/dev/null || true
  fi
}
install_graphics_protocol_daemon() {
  local daemon_interval="${1:-${GRAPHICS_DAEMON_INTERVAL_OVERRIDE:-$GRAPHICS_DAEMON_INTERVAL_DEFAULT}}"
  local desktop_pair watchdog_user watchdog_home watchdog_group watchdog_log
  if [[ ! "$daemon_interval" =~ ^[0-9]+$ ]] || (( 10#$daemon_interval < 1 || 10#$daemon_interval > 3600 )); then
    daemon_interval="$GRAPHICS_DAEMON_INTERVAL_DEFAULT"
  fi
  desktop_pair="$(resolve_desktop_user_home 2>/dev/null || true)"
  watchdog_user="root"
  watchdog_home="/home"
  watchdog_group="root"
  if [[ -n "$desktop_pair" ]]; then
    watchdog_user="${desktop_pair%%$'\t'*}"
    watchdog_home="${desktop_pair#*$'\t'}"
    watchdog_group="$(id -gn "$watchdog_user" 2>/dev/null || true)"
    [[ -n "$watchdog_group" ]] || watchdog_group="$watchdog_user"
  fi
  if [[ -n "$watchdog_home" && -d "$watchdog_home" && "$watchdog_home" != "/home" ]]; then
    watchdog_log="$watchdog_home/.local/state/vfio-graphics-protocol/watchdog.log"
  else
    watchdog_log="/home/vfio-graphics-protocol/watchdog.log"
  fi
  ensure_graphics_daemon_deployment_safety
  if ! have_cmd systemctl; then
    note "systemctl is not available; skipping graphics protocol daemon installation."
    return 0
  fi
  if (( ! DRY_RUN )); then
    mkdir -p "$(dirname "$GRAPHICS_DAEMON_SCRIPT")" "$(dirname "$GRAPHICS_DAEMON_UNIT")"
  fi

  backup_file "$GRAPHICS_DAEMON_SCRIPT"
  backup_file "$GRAPHICS_DAEMON_UNIT"

  write_file_atomic "$GRAPHICS_DAEMON_SCRIPT" 0755 "root:root" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/vfio-gpu-passthrough.conf"
XORG_HOST_GPU_CONF="/etc/X11/xorg.conf.d/20-vfio-host-gpu.conf"
LIGHTDM_HOST_GPU_CONF="/etc/lightdm/lightdm.conf.d/90-vfio-host-gpu.conf"
STATE_FILE="/run/vfio-graphics-protocold.state"
WATCHDOG_LOG="__VFIO_GRAPHICS_WATCHDOG_LOG__"
WATCHDOG_TARGET_USER="__VFIO_GRAPHICS_WATCHDOG_USER__"
WATCHDOG_TARGET_GROUP="__VFIO_GRAPHICS_WATCHDOG_GROUP__"
WATCHDOG_LOG_DIR="$(dirname "$WATCHDOG_LOG")"
DEFAULT_SLEEP_SECS=2
DEFAULT_AUTO_X11_PINNING=0
DEFAULT_WATCHDOG_RETENTION_DAYS=10
DEFAULT_WATCHDOG_MAX_LINES=5000

trim() {
  local s="$*"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s\n' "$s"
}

daemon_sleep_secs() {
  local raw=""
  if [[ -n "${VFIO_GRAPHICS_DAEMON_INTERVAL:-}" ]]; then
    raw="${VFIO_GRAPHICS_DAEMON_INTERVAL}"
  elif [[ -f "$CONF_FILE" ]]; then
    raw="$(awk -F= '/^VFIO_GRAPHICS_DAEMON_INTERVAL=/{v=$2; gsub(/"/,"",v); print v; exit}' "$CONF_FILE" 2>/dev/null || true)"
  fi
  raw="$(trim "$raw")"
  if [[ "$raw" =~ ^[0-9]+$ ]] && (( 10#$raw >= 1 && 10#$raw <= 3600 )); then
    printf '%s\n' "$((10#$raw))"
  else
    printf '%s\n' "$DEFAULT_SLEEP_SECS"
  fi
}

auto_x11_pinning_enabled() {
  local raw=""
  if [[ -n "${VFIO_GRAPHICS_AUTO_X11_PINNING:-}" ]]; then
    raw="${VFIO_GRAPHICS_AUTO_X11_PINNING}"
  elif [[ -f "$CONF_FILE" ]]; then
    raw="$(awk -F= '/^VFIO_GRAPHICS_AUTO_X11_PINNING=/{v=$2; gsub(/"/,"",v); print v; exit}' "$CONF_FILE" 2>/dev/null || true)"
  fi
  raw="$(trim "$raw")"
  raw="${raw,,}"
  case "$raw" in
    1|y|yes|true|on) return 0 ;;
    0|n|no|false|off) return 1 ;;
    *)
      (( DEFAULT_AUTO_X11_PINNING == 1 )) && return 0
      return 1
      ;;
  esac
}
watchdog_retention_days() {
  local raw=""
  if [[ -n "${VFIO_GRAPHICS_WATCHDOG_RETENTION_DAYS:-}" ]]; then
    raw="${VFIO_GRAPHICS_WATCHDOG_RETENTION_DAYS}"
  elif [[ -f "$CONF_FILE" ]]; then
    raw="$(awk -F= '/^VFIO_GRAPHICS_WATCHDOG_RETENTION_DAYS=/{v=$2; gsub(/"/,"",v); print v; exit}' "$CONF_FILE" 2>/dev/null || true)"
  fi
  raw="$(trim "$raw")"
  if [[ "$raw" =~ ^[0-9]+$ ]] && (( 10#$raw >= 1 && 10#$raw <= 365 )); then
    printf '%s\n' "$((10#$raw))"
  else
    printf '%s\n' "$DEFAULT_WATCHDOG_RETENTION_DAYS"
  fi
}
watchdog_max_lines() {
  local raw=""
  if [[ -n "${VFIO_GRAPHICS_WATCHDOG_MAX_LINES:-}" ]]; then
    raw="${VFIO_GRAPHICS_WATCHDOG_MAX_LINES}"
  elif [[ -f "$CONF_FILE" ]]; then
    raw="$(awk -F= '/^VFIO_GRAPHICS_WATCHDOG_MAX_LINES=/{v=$2; gsub(/"/,"",v); print v; exit}' "$CONF_FILE" 2>/dev/null || true)"
  fi
  raw="$(trim "$raw")"
  if [[ "$raw" =~ ^[0-9]+$ ]] && (( 10#$raw >= 200 && 10#$raw <= 500000 )); then
    printf '%s\n' "$((10#$raw))"
  else
    printf '%s\n' "$DEFAULT_WATCHDOG_MAX_LINES"
  fi
}
prune_watchdog_log() {
  [[ -f "$WATCHDOG_LOG" ]] || return 0
  local retention_days max_lines cutoff_epoch line ts ts_epoch line_count
  local tmp
  retention_days="$(watchdog_retention_days)"
  max_lines="$(watchdog_max_lines)"
  cutoff_epoch="$(date -u -d "-${retention_days} days" +%s 2>/dev/null || true)"
  tmp="$(mktemp)"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if [[ -n "$cutoff_epoch" ]]; then
      ts="${line%% *}"
      ts_epoch="$(date -u -d "$ts" +%s 2>/dev/null || true)"
      if [[ -n "$ts_epoch" ]] && (( ts_epoch < cutoff_epoch )); then
        continue
      fi
    fi
    printf '%s\n' "$line" >>"$tmp"
  done < "$WATCHDOG_LOG"
  line_count="$(wc -l < "$tmp" 2>/dev/null || echo 0)"
  if [[ "$line_count" =~ ^[0-9]+$ ]] && (( line_count > max_lines )); then
    tail -n "$max_lines" "$tmp" >"${tmp}.tail" 2>/dev/null || true
    mv -f "${tmp}.tail" "$tmp" 2>/dev/null || true
  fi
  if cmp -s "$tmp" "$WATCHDOG_LOG"; then
    rm -f "$tmp" || true
  else
    mv -f "$tmp" "$WATCHDOG_LOG" 2>/dev/null || true
  fi
}

xorg_busid_from_bdf() {
  local bdf="$1"
  local bus_hex dev_hex func_dec
  if [[ ! "$bdf" =~ ^[[:xdigit:]]{4}:([[:xdigit:]]{2}):([[:xdigit:]]{2})\.([0-7])$ ]]; then
    return 1
  fi
  bus_hex="${BASH_REMATCH[1]}"
  dev_hex="${BASH_REMATCH[2]}"
  func_dec="${BASH_REMATCH[3]}"
  printf 'PCI:%d:%d:%d\n' "$((16#$bus_hex))" "$((16#$dev_hex))" "$func_dec"
}

normalize_display_manager_name() {
  local raw="$1"
  raw="${raw##*/}"
  raw="${raw%.service}"
  raw="${raw,,}"
  case "$raw" in
    lightdm|sddm|lxdm|xdm) echo "$raw"; return 0 ;;
    gdm|gdm3) echo "gdm"; return 0 ;;
  esac
  return 1
}
display_manager_name() {
  local dm_link base dm
  if [[ -L /etc/systemd/system/display-manager.service ]]; then
    dm_link="$(readlink -f /etc/systemd/system/display-manager.service 2>/dev/null || true)"
    base="$(basename "${dm_link:-}")"
    if dm="$(normalize_display_manager_name "$base")"; then
      echo "$dm"
      return 0
    fi
  fi
  # openSUSE often uses a display-manager wrapper unit; resolve the active DM
  # from alternatives as a fallback so protocol policy can classify prelogin mode.
  if [[ -L /usr/lib/X11/displaymanagers/default-displaymanager ]]; then
    dm_link="$(readlink -f /usr/lib/X11/displaymanagers/default-displaymanager 2>/dev/null || true)"
    base="$(basename "${dm_link:-}")"
    if dm="$(normalize_display_manager_name "$base")"; then
      echo "$dm"
      return 0
    fi
  fi
  echo "none"
}
display_manager_prefers_x11_prelogin() {
  # Display managers that typically launch an Xorg greeter before login.
  case "$(display_manager_name)" in
    lightdm|sddm|lxdm|xdm) return 0 ;;
    gdm|none|*) return 1 ;;
  esac
}

display_manager_prefers_wayland_prelogin() {
  # GDM commonly defaults to Wayland greeter when available.
  case "$(display_manager_name)" in
    gdm) return 0 ;;
    *) return 1 ;;
  esac
}

active_user_session_exists() {
  local sid state class
  while read -r sid _rest; do
    [[ -n "${sid:-}" ]] || continue
    state="$(loginctl show-session "$sid" -p State --value 2>/dev/null || true)"
    class="$(loginctl show-session "$sid" -p Class --value 2>/dev/null || true)"
    [[ "$class" == "user" ]] || continue
    [[ "$state" == "active" ]] || continue
    return 0
  done < <(loginctl list-sessions --no-legend 2>/dev/null || true)
  return 1
}

infer_prelogin_protocol_mode() {
  if display_manager_prefers_x11_prelogin; then
    echo "x11"
    return 0
  fi
  if display_manager_prefers_wayland_prelogin; then
    echo "wayland"
    return 0
  fi
  echo "unknown"
}

write_file_if_changed() {
  local dst="$1"
  local mode="$2"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if [[ -f "$dst" ]] && cmp -s "$tmp" "$dst"; then
    rm -f "$tmp" || true
    return 1
  fi
  install -m "$mode" -o root -g root "$tmp" "$dst"
  rm -f "$tmp" || true
  return 0
}

ensure_x11_host_gpu_pinning() {
  local host_gpu_bdf="$1"
  local guest_gpu_bdf="$2"
  local host_busid changed=0 dm

  [[ -n "$host_gpu_bdf" && -n "$guest_gpu_bdf" ]] || return 0
  [[ "$host_gpu_bdf" != "$guest_gpu_bdf" ]] || return 0

  host_busid="$(xorg_busid_from_bdf "$host_gpu_bdf" 2>/dev/null || true)"
  [[ -n "$host_busid" ]] || return 0

  mkdir -p /etc/X11/xorg.conf.d
  if write_file_if_changed "$XORG_HOST_GPU_CONF" 0644 <<EOF_XORG
# Managed by vfio-graphics-protocold (AUTO/X11 policy)
# Host GPU (Xorg): $host_gpu_bdf
# Guest GPU (VFIO): $guest_gpu_bdf
Section "ServerLayout"
    Identifier "Layout0"
    Screen 0 "Screen0"
EndSection
Section "Device"
    Identifier "HostGPU"
    BusID "$host_busid"
    Option "PrimaryGPU" "true"
EndSection
Section "Screen"
    Identifier "Screen0"
    Device "HostGPU"
EndSection
EOF_XORG
  then
    changed=1
  fi

  dm="$(display_manager_name)"
  if [[ "$dm" == "lightdm" ]]; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    if write_file_if_changed "$LIGHTDM_HOST_GPU_CONF" 0644 <<EOF_LIGHTDM
# Managed by vfio-graphics-protocold (AUTO/X11 policy)
[Seat:*]
xserver-command=X -core -isolateDevice $host_busid
EOF_LIGHTDM
    then
      changed=1
    fi
  fi

  return "$changed"
}

remove_x11_host_gpu_pinning() {
  local removed=0
  if [[ -f "$XORG_HOST_GPU_CONF" ]]; then
    rm -f "$XORG_HOST_GPU_CONF"
    removed=1
  fi
  if [[ -f "$LIGHTDM_HOST_GPU_CONF" ]]; then
    rm -f "$LIGHTDM_HOST_GPU_CONF"
    removed=1
  fi
  return "$removed"
}

detect_active_session_type() {
  local sid state class stype
  while read -r sid _rest; do
    [[ -n "${sid:-}" ]] || continue
    state="$(loginctl show-session "$sid" -p State --value 2>/dev/null || true)"
    class="$(loginctl show-session "$sid" -p Class --value 2>/dev/null || true)"
    stype="$(loginctl show-session "$sid" -p Type --value 2>/dev/null || true)"
    [[ "$class" == "user" ]] || continue
    [[ "$state" == "active" ]] || continue
    case "$stype" in
      x11|wayland) echo "$stype"; return 0 ;;
    esac
  done < <(loginctl list-sessions --no-legend 2>/dev/null || true)
  echo "unknown"
}
current_root_subvolume() {
  local cmdline subvol
  cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
  subvol="$(printf '%s\n' "$cmdline" | sed -n 's/.*rootflags=[^ ]*subvol=\([^ ,]*\).*/\1/p')"
  printf '%s\n' "${subvol:-unknown}"
}
watchdog_log_event() {
  local mode="$1" session_type="$2" action="$3"
  local reason="${4:-unspecified}" dm_name="${5:-none}" prelogin_protocol="${6:-unknown}"
  local host_gpu="${7:-unknown}" guest_gpu="${8:-unknown}"
  local ts root_subvol retention_days max_lines
  reason="$(trim "$reason")"
  reason="${reason//[[:space:]]/-}"
  [[ -n "$reason" ]] || reason="unspecified"
  dm_name="$(trim "$dm_name")"
  [[ -n "$dm_name" ]] || dm_name="none"
  prelogin_protocol="$(trim "$prelogin_protocol")"
  [[ -n "$prelogin_protocol" ]] || prelogin_protocol="unknown"
  host_gpu="$(trim "$host_gpu")"
  [[ -n "$host_gpu" ]] || host_gpu="unknown"
  guest_gpu="$(trim "$guest_gpu")"
  [[ -n "$guest_gpu" ]] || guest_gpu="unknown"
  ts="$(date -Is 2>/dev/null || true)"
  [[ -n "$ts" ]] || ts="unknown-time"
  root_subvol="$(current_root_subvolume)"
  retention_days="$(watchdog_retention_days)"
  max_lines="$(watchdog_max_lines)"
  mkdir -p "$WATCHDOG_LOG_DIR" 2>/dev/null || true
  prune_watchdog_log || true
  printf '%s mode=%s session=%s action=%s reason=%s dm=%s prelogin=%s host=%s guest=%s subvol=%s retention_days=%s max_lines=%s\n' \
    "$ts" "$mode" "$session_type" "$action" "$reason" "$dm_name" "$prelogin_protocol" "$host_gpu" "$guest_gpu" "$root_subvol" "$retention_days" "$max_lines" >>"$WATCHDOG_LOG" 2>/dev/null || true
  prune_watchdog_log || true
  if [[ -n "$WATCHDOG_TARGET_USER" && -n "$WATCHDOG_TARGET_GROUP" ]]; then
    chown "$WATCHDOG_TARGET_USER:$WATCHDOG_TARGET_GROUP" "$WATCHDOG_LOG_DIR" "$WATCHDOG_LOG" 2>/dev/null || true
    chmod u+rwX "$WATCHDOG_LOG_DIR" "$WATCHDOG_LOG" 2>/dev/null || true
  fi
}

apply_policy_once() {
  local prelogin="${1:-0}"
  [[ -f "$CONF_FILE" ]] || return 0
  # shellcheck disable=SC1090
  . "$CONF_FILE"

  local mode host guest session_type inferred_prelogin action reason prev dm_name prelogin_protocol state_key
  mode="$(trim "${GRAPHICS_PROTOCOL_MODE:-AUTO}")"
  mode="${mode^^}"
  host="$(trim "${HOST_GPU_BDF:-}")"
  guest="$(trim "${GUEST_GPU_BDF:-}")"
  dm_name="$(display_manager_name)"
  session_type="unknown"
  action="noop"
  reason="noop"
  prelogin_protocol="unknown"

  if [[ "$prelogin" == "1" ]]; then
    inferred_prelogin="$(infer_prelogin_protocol_mode)"
    prelogin_protocol="$inferred_prelogin"
    case "$mode" in
      X11)
        action="x11"
        session_type="prelogin-x11"
        reason="forced-x11-mode"
        ;;
      WAYLAND)
        action="wayland"
        session_type="prelogin-wayland"
        reason="forced-wayland-mode"
        ;;
      AUTO)
        case "$inferred_prelogin" in
          x11)
            action="x11"
            session_type="prelogin-x11"
            reason="auto-prelogin-x11"
            ;;
          wayland)
            action="wayland"
            session_type="prelogin-wayland"
            reason="auto-prelogin-wayland"
            ;;
          *)
            if auto_x11_pinning_enabled; then
              action="x11"
              session_type="prelogin-auto-x11-fallback"
              reason="auto-prelogin-fallback-x11"
            else
              action="noop"
              session_type="prelogin-unknown"
              reason="auto-prelogin-unknown"
            fi
            ;;
        esac
        ;;
      *)
        action="noop"
        session_type="prelogin-unknown"
        reason="invalid-mode"
        ;;
    esac
  else
    prelogin_protocol="$(infer_prelogin_protocol_mode)"
    session_type="$(detect_active_session_type)"
    if [[ "$session_type" == "unknown" ]] && ! active_user_session_exists; then
      inferred_prelogin="$prelogin_protocol"
      case "$inferred_prelogin" in
        x11) session_type="prelogin-x11" ;;
        wayland) session_type="prelogin-wayland" ;;
        *) session_type="unknown" ;;
      esac
    fi

    case "$mode" in
      X11)
        action="x11"
        reason="forced-x11-mode"
        ;;
      WAYLAND)
        action="wayland"
        reason="forced-wayland-mode"
        ;;
      AUTO)
        case "$session_type" in
          x11|prelogin-x11)
            if auto_x11_pinning_enabled || [[ "$session_type" == "prelogin-x11" ]] || display_manager_prefers_x11_prelogin; then
              action="x11"
              if auto_x11_pinning_enabled; then
                reason="auto-x11-pinning-enabled"
              elif [[ "$session_type" == "prelogin-x11" ]]; then
                reason="auto-prelogin-x11-session"
              else
                reason="auto-dm-prefers-x11-prelogin"
              fi
            else
              # Conservative AUTO default for active X11 sessions when pinning override is disabled.
              action="auto-safe-no-x11"
              reason="auto-x11-pinning-disabled"
            fi
            ;;
          wayland|prelogin-wayland)
            action="wayland"
            reason="auto-wayland-session"
            ;;
          prelogin-auto-x11-fallback)
            action="x11"
            reason="auto-prelogin-fallback-x11"
            ;;
          *)
            action="noop"
            reason="auto-unknown-session"
            ;;
        esac
        ;;
      *)
        action="noop"
        reason="invalid-mode"
        ;;
    esac
  fi

  case "$action" in
    x11)
      ensure_x11_host_gpu_pinning "$host" "$guest" || true
      ;;
    wayland)
      remove_x11_host_gpu_pinning || true
      ;;
    auto-safe-no-x11)
      remove_x11_host_gpu_pinning || true
      ;;
    noop)
      ;;
  esac

  state_key="$mode:$session_type:$action:$reason:$dm_name:$prelogin_protocol"
  prev="$(cat "$STATE_FILE" 2>/dev/null || true)"
  if [[ "$prev" != "$state_key" ]]; then
    printf '%s\n' "$state_key" >"$STATE_FILE" 2>/dev/null || true
    printf 'vfio-graphics-protocold: mode=%s session=%s action=%s reason=%s dm=%s prelogin=%s\n' "$mode" "$session_type" "$action" "$reason" "$dm_name" "$prelogin_protocol"
    watchdog_log_event "$mode" "$session_type" "$action" "$reason" "$dm_name" "$prelogin_protocol" "$host" "$guest"
  fi
}

main() {
  local once=0 prelogin=0
  while (( $# > 0 )); do
    case "$1" in
      --once) once=1 ;;
      --prelogin) prelogin=1 ;;
      *) ;;
    esac
    shift
  done

  if (( once )); then
    apply_policy_once "$prelogin"
    exit 0
  fi

  apply_policy_once "$prelogin" || true
  while true; do
    sleep "$(daemon_sleep_secs)"
    apply_policy_once 0 || true
  done
}

main "$@"
EOF

  write_file_atomic "$GRAPHICS_DAEMON_UNIT" 0644 "root:root" <<EOF
[Unit]
Description=VFIO graphics protocol adaptation daemon
ConditionPathExists=$CONF_FILE
ConditionPathExists=$GRAPHICS_DAEMON_SCRIPT
After=local-fs.target systemd-logind.service vfio-bind-selected-gpu.service
Wants=systemd-logind.service vfio-bind-selected-gpu.service
Before=display-manager.service

[Service]
Type=simple
Environment=VFIO_GRAPHICS_DAEMON_INTERVAL=$daemon_interval
ExecStart=$GRAPHICS_DAEMON_SCRIPT --prelogin
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  if (( ! DRY_RUN )); then
    sed -i "s#__VFIO_GRAPHICS_WATCHDOG_LOG__#$watchdog_log#g" "$GRAPHICS_DAEMON_SCRIPT" || true
    sed -i "s#__VFIO_GRAPHICS_WATCHDOG_USER__#$watchdog_user#g" "$GRAPHICS_DAEMON_SCRIPT" || true
    sed -i "s#__VFIO_GRAPHICS_WATCHDOG_GROUP__#$watchdog_group#g" "$GRAPHICS_DAEMON_SCRIPT" || true
  fi

  if (( ! DRY_RUN )); then
    [[ -f "$GRAPHICS_DAEMON_SCRIPT" ]] || die "Graphics daemon deployment failed: missing script at $GRAPHICS_DAEMON_SCRIPT"
    [[ -x "$GRAPHICS_DAEMON_SCRIPT" ]] || die "Graphics daemon deployment failed: script is not executable at $GRAPHICS_DAEMON_SCRIPT"
    [[ -f "$GRAPHICS_DAEMON_UNIT" ]] || die "Graphics daemon deployment failed: missing unit at $GRAPHICS_DAEMON_UNIT"
    grep -Fqx "ConditionPathExists=$GRAPHICS_DAEMON_SCRIPT" "$GRAPHICS_DAEMON_UNIT" || \
      die "Graphics daemon deployment failed: unit missing script condition guard ($GRAPHICS_DAEMON_SCRIPT)"
  fi
  run systemctl daemon-reload
  run systemctl enable vfio-graphics-protocold.service
  say "Installed graphics protocol daemon: $GRAPHICS_DAEMON_SCRIPT"
  say "Installed graphics protocol unit:   $GRAPHICS_DAEMON_UNIT"
  say "Graphics protocol watchdog log:      $watchdog_log"
  say "Graphics daemon polling interval:    ${daemon_interval}s"
  note "Graphics protocol daemon will activate on next boot (not started immediately)."
}
graphics_daemon_interval_from_conf_or_default() {
  local interval="$GRAPHICS_DAEMON_INTERVAL_DEFAULT"
  if readable_file "$CONF_FILE"; then
    local raw
    raw="$(awk -F= '/^VFIO_GRAPHICS_DAEMON_INTERVAL=/{v=$2; gsub(/"/,"",v); print v; exit}' "$CONF_FILE" 2>/dev/null || true)"
    raw="$(trim "${raw:-}")"
    if [[ "$raw" =~ ^[0-9]+$ ]] && (( 10#$raw >= 1 && 10#$raw <= 3600 )); then
      interval="$((10#$raw))"
    fi
  fi
  printf '%s\n' "$interval"
}
graphics_watchdog_retention_days_from_conf_or_default() {
  local retention_days="$GRAPHICS_WATCHDOG_RETENTION_DAYS_DEFAULT"
  if readable_file "$CONF_FILE"; then
    local raw
    raw="$(awk -F= '/^VFIO_GRAPHICS_WATCHDOG_RETENTION_DAYS=/{v=$2; gsub(/"/,"",v); print v; exit}' "$CONF_FILE" 2>/dev/null || true)"
    raw="$(trim "${raw:-}")"
    if [[ "$raw" =~ ^[0-9]+$ ]] && (( 10#$raw >= 1 && 10#$raw <= 365 )); then
      retention_days="$((10#$raw))"
    fi
  fi
  printf '%s\n' "$retention_days"
}
graphics_watchdog_max_lines_from_conf_or_default() {
  local max_lines="$GRAPHICS_WATCHDOG_MAX_LINES_DEFAULT"
  if readable_file "$CONF_FILE"; then
    local raw
    raw="$(awk -F= '/^VFIO_GRAPHICS_WATCHDOG_MAX_LINES=/{v=$2; gsub(/"/,"",v); print v; exit}' "$CONF_FILE" 2>/dev/null || true)"
    raw="$(trim "${raw:-}")"
    if [[ "$raw" =~ ^[0-9]+$ ]] && (( 10#$raw >= 200 && 10#$raw <= 500000 )); then
      max_lines="$((10#$raw))"
    fi
  fi
  printf '%s\n' "$max_lines"
}
install_graphics_protocol_daemon_from_existing_config() {
  readable_file "$CONF_FILE" || die "Missing $CONF_FILE. Run the full installer first, or create the config before reinstalling only the graphics daemon."
  local interval
  interval="$(graphics_daemon_interval_from_conf_or_default)"
  install_graphics_protocol_daemon "$interval"
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
ConditionPathExists=$AUDIO_SCRIPT

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
install_openbox_monitor_script() {
  backup_file "$OPENBOX_MONITOR_SCRIPT"

  write_file_atomic "$OPENBOX_MONITOR_SCRIPT" 0755 "root:root" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

openbox_connected_outputs_from_xrandr_query() {
  awk '$2 == "connected" { print $1 }'
}

openbox_activate_all_connected_monitors() {
  command -v xrandr >/dev/null 2>&1 || return 0
  [[ -n "${DISPLAY:-}" ]] || return 0

  local query
  query="$(xrandr --query 2>/dev/null || true)"
  [[ -n "$query" ]] || return 0

  local -a outputs=()
  mapfile -t outputs < <(printf '%s\n' "$query" | openbox_connected_outputs_from_xrandr_query)
  (( ${#outputs[@]} > 0 )) || return 0

  local output
  for output in "${outputs[@]}"; do
    xrandr --output "$output" --auto >/dev/null 2>&1 || true
  done
}

openbox_activate_all_connected_monitors
EOF
}
install_openbox_autostart_hook() {
  local autostart_file="$OPENBOX_AUTOSTART_FILE"
  local autostart_dir
  autostart_dir="$(dirname "$autostart_file")"
  local marker_begin="# BEGIN VFIO OPENBOX MONITOR AUTO-ACTIVATE"
  local marker_end="# END VFIO OPENBOX MONITOR AUTO-ACTIVATE"

  if [[ "$(openbox_stack_status)" == "NOT_PRESENT" && ! -d "$autostart_dir" ]]; then
    note "Openbox stack not detected and $autostart_dir is missing; skipping Openbox monitor hook."
    return 0
  fi

  if (( ! DRY_RUN )); then
    mkdir -p "$autostart_dir"
  fi

  backup_file "$autostart_file"

  local tmp mode owner group
  tmp="$(mktemp)"
  if [[ -f "$autostart_file" ]]; then
    awk -v begin="$marker_begin" -v end="$marker_end" '
      $0 == begin { skip=1; next }
      $0 == end { skip=0; next }
      !skip { print }
    ' "$autostart_file" >"$tmp"
    mode="$(stat -c '%a' "$autostart_file" 2>/dev/null || echo 644)"
    owner="$(stat -c '%u' "$autostart_file" 2>/dev/null || id -u)"
    group="$(stat -c '%g' "$autostart_file" 2>/dev/null || id -g)"
  else
    : >"$tmp"
    mode=644
    owner=0
    group=0
  fi

  {
    if [[ -s "$tmp" ]]; then
      cat "$tmp"
      printf '\n'
    fi
    cat <<EOF
$marker_begin
if [ -x "$OPENBOX_MONITOR_SCRIPT" ]; then
  "$OPENBOX_MONITOR_SCRIPT" >/dev/null 2>&1 &
fi
$marker_end
EOF
  } >"${tmp}.new"
  mv "${tmp}.new" "$tmp"

  if (( DRY_RUN )); then
    rm -f "$tmp" || true
    return 0
  fi

  install -o "$owner" -g "$group" -m "$mode" "$tmp" "$autostart_file"
  rm -f "$tmp" || true
  note "Openbox monitor hook ensured at: $autostart_file"
}
remove_openbox_autostart_hook() {
  local autostart_file="$OPENBOX_AUTOSTART_FILE"
  local marker_begin="# BEGIN VFIO OPENBOX MONITOR AUTO-ACTIVATE"
  local marker_end="# END VFIO OPENBOX MONITOR AUTO-ACTIVATE"
  [[ -f "$autostart_file" ]] || return 0

  backup_file "$autostart_file"

  local tmp mode owner group
  tmp="$(mktemp)"
  awk -v begin="$marker_begin" -v end="$marker_end" '
    $0 == begin { skip=1; next }
    $0 == end { skip=0; next }
    !skip { print }
  ' "$autostart_file" >"$tmp"
  mode="$(stat -c '%a' "$autostart_file" 2>/dev/null || echo 644)"
  owner="$(stat -c '%u' "$autostart_file" 2>/dev/null || id -u)"
  group="$(stat -c '%g' "$autostart_file" 2>/dev/null || id -g)"

  if (( DRY_RUN )); then
    rm -f "$tmp" || true
    return 0
  fi

  install -o "$owner" -g "$group" -m "$mode" "$tmp" "$autostart_file"
  rm -f "$tmp" || true
}
install_openbox_monitor_activation() {
  install_openbox_monitor_script
  install_openbox_autostart_hook
}

install_udev_isolation() {
  local gpu_bdf="$1"
  local audio_csv="$2"

  local rule_file="$UDEV_ISOLATION_RULE"
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
usb_bt_mitigation_explain() {
  note "This optional feature targets a specific (but nasty) class of stability problems: USB Bluetooth adapters that cause repeated kernel timeouts and USB reset storms."
  note "These storms can make other USB devices randomly glitch/disconnect and can interfere with VFIO/passthrough stability."
  note
  note "Why this exists (problem statement):"
  note "Some USB Bluetooth adapters (or Bluetooth functions inside docks) behave poorly under Linux when driven by the host btusb stack."
  note "The failure pattern often looks like this in kernel logs:"
  note "  - Bluetooth: hci0: command ... tx timeout"
  note "  - Bluetooth: hci0: Resetting usb device"
  note "  - usb X-Y: reset ... USB device"
  note
  note "This is not just log spam: it can be a real reset loop where the USB host controller repeatedly resets that device/path trying to recover."
  note "If this repeats every few seconds, it can destabilize the entire USB topology behind the same controller/hub/dock, causing symptoms like:"
  note "  - USB storage intermittently failing / unmounting"
  note "  - devices stopping working until replug"
  note "  - general USB flakiness during passthrough testing"
}
usb_sysfs_device_is_bluetooth() {
  # Return 0 if the sysfs USB device directory appears to expose Bluetooth
  # interfaces (btusb driver or interface class/subclass e0/01).
  local dev="$1" intf cls sub drv
  shopt -s nullglob
  for intf in "$dev":*; do
    if [[ -L "$intf/driver" ]]; then
      drv="$(basename "$(readlink -f "$intf/driver" 2>/dev/null || true)")"
      if [[ "$drv" == "btusb" ]]; then
        shopt -u nullglob
        return 0
      fi
    fi
    if [[ -f "$intf/bInterfaceClass" && -f "$intf/bInterfaceSubClass" ]]; then
      cls="$(tr -d '\n' <"$intf/bInterfaceClass" | tr 'A-F' 'a-f')"
      sub="$(tr -d '\n' <"$intf/bInterfaceSubClass" | tr 'A-F' 'a-f')"
      if [[ "$cls" == "e0" && "$sub" == "01" ]]; then
        shopt -u nullglob
        return 0
      fi
    fi
  done
  shopt -u nullglob
  return 1
}
usb_sysfs_device_is_ethernet() {
  # Return 0 if the USB device appears to be a network adapter (Ethernet/LAN).
  local dev="$1" intf cls drv text_hint
  shopt -s nullglob
  for intf in "$dev":*; do
    if [[ -L "$intf/driver" ]]; then
      drv="$(basename "$(readlink -f "$intf/driver" 2>/dev/null || true)")"
      case "$drv" in
        r8152|asix|ax88179_178a|cdc_ether|rndis_host|cdc_ncm|cdc_mbim|lan78xx|smsc95xx|qmi_wwan|aqc111)
          shopt -u nullglob
          return 0
          ;;
      esac
    fi
    if [[ -f "$intf/bInterfaceClass" ]]; then
      cls="$(tr -d '\n' <"$intf/bInterfaceClass" | tr 'A-F' 'a-f')"
      if [[ "$cls" == "02" || "$cls" == "0a" ]]; then
        shopt -u nullglob
        return 0
      fi
    fi
  done
  shopt -u nullglob

  text_hint="$(printf '%s %s' "$(cat "$dev/manufacturer" 2>/dev/null || true)" "$(cat "$dev/product" 2>/dev/null || true)" | tr '[:upper:]' '[:lower:]')"
  if grep -Eq '(ethernet|usb ?lan|network adapter|realtek.*lan|gigabit.*lan)' <<<"$text_hint"; then
    return 0
  fi
  return 1
}
usb_sysfs_device_is_printer() {
  # Return 0 if the USB device appears to be a printer.
  local dev="$1" intf cls drv text_hint
  shopt -s nullglob
  for intf in "$dev":*; do
    if [[ -L "$intf/driver" ]]; then
      drv="$(basename "$(readlink -f "$intf/driver" 2>/dev/null || true)")"
      if [[ "$drv" == "usblp" ]]; then
        shopt -u nullglob
        return 0
      fi
    fi
    if [[ -f "$intf/bInterfaceClass" ]]; then
      cls="$(tr -d '\n' <"$intf/bInterfaceClass" | tr 'A-F' 'a-f')"
      if [[ "$cls" == "07" ]]; then
        shopt -u nullglob
        return 0
      fi
    fi
  done
  shopt -u nullglob

  text_hint="$(printf '%s %s' "$(cat "$dev/manufacturer" 2>/dev/null || true)" "$(cat "$dev/product" 2>/dev/null || true)" | tr '[:upper:]' '[:lower:]')"
  if grep -Eq '(printer|print device)' <<<"$text_hint"; then
    return 0
  fi
  return 1
}
usb_sysfs_device_is_storage() {
  # Return 0 if the USB device appears to be storage (mass storage/SSD/HDD).
  local dev="$1" intf cls drv text_hint
  shopt -s nullglob
  for intf in "$dev":*; do
    if [[ -L "$intf/driver" ]]; then
      drv="$(basename "$(readlink -f "$intf/driver" 2>/dev/null || true)")"
      case "$drv" in
        usb-storage|uas)
          shopt -u nullglob
          return 0
          ;;
      esac
    fi
    if [[ -f "$intf/bInterfaceClass" ]]; then
      cls="$(tr -d '\n' <"$intf/bInterfaceClass" | tr 'A-F' 'a-f')"
      if [[ "$cls" == "08" ]]; then
        shopt -u nullglob
        return 0
      fi
    fi
  done
  shopt -u nullglob

  text_hint="$(printf '%s %s' "$(cat "$dev/manufacturer" 2>/dev/null || true)" "$(cat "$dev/product" 2>/dev/null || true)" | tr '[:upper:]' '[:lower:]')"
  if grep -Eq '(portable ssd|ssd|hdd|hard ?drive|mass storage|flash drive|thumb drive|external drive|usb disk|portable disk)' <<<"$text_hint"; then
    return 0
  fi
  return 1
}
ensure_usb_bt_match_conf_present() {
  # Ensure USB Bluetooth match policy config exists with safe defaults.
  local conf="$1"
  [[ -n "$conf" ]] || return 1
  [[ -f "$conf" ]] && return 0

  note "USB Bluetooth match config was missing; recreating defaults at: $conf"
  local conf_dir
  conf_dir="$(dirname "$conf")"
  mkdir -p "$conf_dir" 2>/dev/null || true
  cat >"$conf" <<'EOF'
# Generated by vfio.sh
# Match behavior for /usr/local/sbin/vfio-usb-bluetooth.sh
#
# MATCH_MODE:
#   auto         -> generic Bluetooth detection (btusb or class e0/01),
#                   then apply INCLUDE_IDS (if non-empty) and EXCLUDE_IDS.
#   include_only -> only match INCLUDE_IDS entries.
#
# INCLUDE_IDS / EXCLUDE_IDS entries are comma-separated VID:PID patterns.
# Wildcards are supported per component:
#   *:*          (match all)
#   2357:*       (any product for vendor 2357)
#   *:0604       (any vendor with product 0604)
#   2357:0604    (exact match)
MATCH_MODE="auto"
INCLUDE_IDS=""
EXCLUDE_IDS=""
EOF
  chmod 0644 "$conf" 2>/dev/null || true
  [[ -f "$conf" ]]
}

configure_usb_bt_exclude_ids_interactive() {
  # Build a numbered USB device list and let the user choose VM-eligible IDs.
  # Selection is VID:PID based. Interactive picks mark VM-eligible IDs and the
  # inverse set is written to EXCLUDE_IDS as host-bound IDs.
  USB_BT_EXCLUDE_CHANGED=0
  local conf="$USB_BT_MATCH_CONF"
  if [[ ! -f "$conf" ]]; then
    if ! ensure_usb_bt_match_conf_present "$conf"; then
      note "No USB Bluetooth match config available at $conf; skipping exclusion picker."
      return 0
    fi
  fi
  local match_mode include_ids storage_interlock_required
  match_mode="$(awk -F= '/^MATCH_MODE=/{v=$2; gsub(/"/,"",v); print tolower(v); exit}' "$conf" 2>/dev/null || true)"
  include_ids="$(awk -F= '/^INCLUDE_IDS=/{v=$2; gsub(/"/,"",v); gsub(/[[:space:]]/,"",v); print tolower(v); exit}' "$conf" 2>/dev/null || true)"
  match_mode="${match_mode:-auto}"
  storage_interlock_required=0
  if [[ "$match_mode" == "include_only" || -n "$include_ids" ]]; then
    storage_interlock_required=1
  fi

  local -a ids=()
  local -a labels=()
  local -a index_colors=()
  local -a is_bt_flags=()
  local -a unique_ids_order=()
  local -a storage_ids_order=()
  local -A all_ids_seen=()
  local -A storage_id_to_label=()
  local usb_devices_glob
  local dev name vid pid manufacturer product hint line
  local is_bt is_eth is_prn is_stg
  local bt_hint_plain bt_hint_colored bt_hint_note
  local eth_hint_plain eth_hint_colored eth_hint_note
  local prn_hint_plain prn_hint_colored prn_hint_note
  local stg_hint_plain stg_hint_colored stg_hint_note
  local mode_host_plain mode_host_colored mode_host_note
  local mode_vm_plain mode_vm_colored mode_vm_note
  bt_hint_plain="[hint: Bluetooth detected]"
  bt_hint_colored="[hint: ${C_BOLD}${C_YELLOW}Bluetooth detected${C_RESET}]"
  bt_hint_note="$bt_hint_plain"
  eth_hint_plain="[keep-bound: Ethernet]"
  eth_hint_colored="[keep-bound: ${C_BOLD}${C_GREEN}Ethernet${C_RESET}]"
  eth_hint_note="$eth_hint_plain"
  prn_hint_plain="[keep-bound: Printer]"
  prn_hint_colored="[keep-bound: ${C_BOLD}${C_BLUE}Printer${C_RESET}]"
  prn_hint_note="$prn_hint_plain"
  stg_hint_plain="[danger: Storage]"
  stg_hint_colored="[danger: ${C_BOLD}${C_RED}Storage${C_RESET}]"
  stg_hint_note="$stg_hint_plain"
  mode_host_plain="[HOST-BOUND]"
  mode_host_colored="[${C_BOLD}${C_GREEN}HOST-BOUND${C_RESET}]"
  mode_host_note="$mode_host_plain"
  mode_vm_plain="[VM-ELIGIBLE]"
  mode_vm_colored="[${C_BOLD}${C_YELLOW}VM-ELIGIBLE${C_RESET}]"
  mode_vm_note="$mode_vm_plain"
  if (( ENABLE_COLOR )); then
    bt_hint_note="$bt_hint_colored"
    eth_hint_note="$eth_hint_colored"
    prn_hint_note="$prn_hint_colored"
    stg_hint_note="$stg_hint_colored"
    mode_host_note="$mode_host_colored"
    mode_vm_note="$mode_vm_colored"
  fi

  usb_devices_glob="${VFIO_USB_SYSFS_GLOB:-/sys/bus/usb/devices/*}"
  for dev in $usb_devices_glob; do
    [[ -f "$dev/idVendor" && -f "$dev/idProduct" ]] || continue
    name="$(basename "$dev")"
    # Keep only physical USB device paths and skip interface pseudo-paths.
    [[ "$name" =~ ^[0-9]+-[0-9]+(\.[0-9]+)*$ ]] || continue

    vid="$(tr -d '\n' <"$dev/idVendor" 2>/dev/null | tr 'A-F' 'a-f')"
    pid="$(tr -d '\n' <"$dev/idProduct" 2>/dev/null | tr 'A-F' 'a-f')"
    [[ -n "$vid" && -n "$pid" ]] || continue

    manufacturer="$(cat "$dev/manufacturer" 2>/dev/null || true)"
    product="$(cat "$dev/product" 2>/dev/null || true)"
    hint=""
    is_bt=0
    is_eth=0
    is_prn=0
    is_stg=0
    if usb_sysfs_device_is_bluetooth "$dev"; then
      is_bt=1
      if (( ENABLE_COLOR )); then
        hint+=" $bt_hint_colored"
      else
        hint+=" $bt_hint_plain"
      fi
    fi
    if usb_sysfs_device_is_ethernet "$dev"; then
      is_eth=1
      if (( ENABLE_COLOR )); then
        hint+=" $eth_hint_colored"
      else
        hint+=" $eth_hint_plain"
      fi
    fi
    if usb_sysfs_device_is_printer "$dev"; then
      is_prn=1
      if (( ENABLE_COLOR )); then
        hint+=" $prn_hint_colored"
      else
        hint+=" $prn_hint_plain"
      fi
    fi
    if usb_sysfs_device_is_storage "$dev"; then
      is_stg=1
      if (( ENABLE_COLOR )); then
        hint+=" $stg_hint_colored"
      else
        hint+=" $stg_hint_plain"
      fi
      if [[ -z "${storage_id_to_label[$vid:$pid]:-}" ]]; then
        storage_ids_order+=("$vid:$pid")
        storage_id_to_label["$vid:$pid"]="$(trim "$name $vid:$pid $manufacturer $product")"
      fi
    fi

    line="$name $vid:$pid $manufacturer $product"
    line="$(trim "$line")"
    line+="$hint"
    ids+=("$vid:$pid")
    labels+=("$line")
    is_bt_flags+=("$is_bt")
    if [[ -z "${all_ids_seen[$vid:$pid]:-}" ]]; then
      unique_ids_order+=("$vid:$pid")
      all_ids_seen["$vid:$pid"]=1
    fi
    if (( is_stg )); then
      index_colors+=("${C_BOLD}${C_RED}")
    elif (( is_bt )); then
      index_colors+=("${C_BOLD}${C_YELLOW}")
    elif (( is_eth )); then
      index_colors+=("${C_BOLD}${C_GREEN}")
    elif (( is_prn )); then
      index_colors+=("${C_BOLD}${C_BLUE}")
    else
      index_colors+=("")
    fi
  done

  if (( ${#ids[@]} == 0 )); then
    note "No USB devices discovered for exclusion selection; leaving EXCLUDE_IDS unchanged."
    return 0
  fi
  local show_full_list filtered_view_active bt_entry_count can_toggle_view
  local -a display_indexes=()
  show_full_list=1
  filtered_view_active=0
  can_toggle_view=0
  bt_entry_count=0
  for i in "${!ids[@]}"; do
    if (( ${is_bt_flags[$i]:-0} )); then
      bt_entry_count=$((bt_entry_count + 1))
    fi
  done
  if (( ! storage_interlock_required && bt_entry_count > 0 && bt_entry_count < ${#ids[@]} )); then
    can_toggle_view=1
  fi
  if (( can_toggle_view )); then
    note "Current policy is Bluetooth-only; you can show a Bluetooth-focused list or the full USB list."
    if prompt_yn "Show full USB list (all devices) instead of Bluetooth-focused view?" N "USB picker view"; then
      show_full_list=1
    else
      show_full_list=0
      filtered_view_active=1
    fi
  fi
  for i in "${!ids[@]}"; do
    if (( show_full_list )) || (( ${is_bt_flags[$i]:-0} )); then
      display_indexes+=("$i")
    fi
  done
  if (( ${#display_indexes[@]} == 0 )); then
    show_full_list=1
    filtered_view_active=0
    for i in "${!ids[@]}"; do
      display_indexes+=("$i")
    done
  fi

  say
  hdr "USB Bluetooth mitigation exclusions"
  note "Pick USB devices that should be VM-eligible (this helper may auto-detach them for passthrough)."
  note "Selecting a number means: allow this device ID to be detached for VM passthrough."
  note "If you want a Bluetooth adapter available for VM passthrough, select it here."
  note "If you want a Bluetooth adapter to remain usable on the host, do NOT select it."
  note "Unselected IDs are kept host-bound and saved into EXCLUDE_IDS."
  note "Entries marked '$bt_hint_note' are likely Bluetooth adapters."
  note "Entries marked '$eth_hint_note' or '$prn_hint_note' are usually host devices you should keep host-bound."
  note "Entries marked '$stg_hint_note' are high-risk to detach (can disconnect active host storage)."
  note "When color output is enabled, entry numbers use the strongest matching hint color (Storage > Bluetooth > Ethernet > Printer)."
  note "Multi-select example: type '4 5 6' (or '4,5,6') to mark multiple devices VM-eligible."
  note "Your VM-eligible picks are converted into EXCLUDE_IDS (unselected host-bound IDs) in: $USB_BT_MATCH_CONF"
  if (( can_toggle_view )); then
    note "Type 'full' to show all USB devices, or 'focus' to show Bluetooth-focused entries."
  fi
  local i idx_text display_no render_device_list
  local -A display_num_by_idx=()
  render_device_list=1

  local in out answer interactive_in_fd
  interactive_in_fd=""
  in="${VFIO_INTERACTIVE_IN:-/dev/stdin}"
  out="${VFIO_INTERACTIVE_OUT:-/dev/stderr}"
  if [[ -z "${VFIO_INTERACTIVE_IN:-}" && -z "${VFIO_INTERACTIVE_OUT:-}" && -r /dev/tty && -w /dev/tty ]]; then
    in="/dev/tty"
    out="/dev/tty"
  fi
  if [[ -n "${VFIO_INTERACTIVE_IN:-}" ]]; then
    exec {interactive_in_fd}<"$in"
  fi

  local exclude_csv=""
  local vm_csv=""
  while true; do
    if (( render_device_list )); then
      if (( filtered_view_active )); then
        note "Bluetooth-focused view is active (showing likely detach targets)."
      fi
      display_num_by_idx=()
      display_no=0
      for i in "${display_indexes[@]}"; do
        display_no=$((display_no + 1))
        display_num_by_idx["$i"]="$display_no"
        idx_text="[$display_no]"
        if (( ENABLE_COLOR )) && [[ -n "${index_colors[$i]:-}" ]]; then
          idx_text="${index_colors[$i]}[$display_no]${C_RESET}"
        fi
        say "  ${idx_text} ${labels[$i]}"
      done
      render_device_list=0
    fi
    if (( can_toggle_view )); then
      printf '%s' "Enter numbers to make VM-eligible (comma/space separated, ENTER for none, or type 'full'/'focus'): " >"$out"
    else
      printf '%s' "Enter numbers to make VM-eligible (comma/space separated, ENTER for none): " >"$out"
    fi
    if [[ -n "$interactive_in_fd" ]]; then
      read -r -u "$interactive_in_fd" answer || answer=""
    else
      read -r answer <"$in" || answer=""
    fi
    answer="$(trim "$answer")"
    if (( can_toggle_view )); then
      local answer_lc
      answer_lc="${answer,,}"
      case "$answer_lc" in
        full)
          if (( show_full_list )); then
            note "Full USB list view is already active."
          else
            show_full_list=1
            filtered_view_active=0
            display_indexes=()
            for i in "${!ids[@]}"; do
              display_indexes+=("$i")
            done
            note "Switched to full USB list view."
          fi
          render_device_list=1
          continue
          ;;
        focus|focused|bt|bluetooth)
          if (( ! show_full_list )); then
            note "Bluetooth-focused view is already active."
          else
            show_full_list=0
            filtered_view_active=1
            display_indexes=()
            for i in "${!ids[@]}"; do
              if (( ${is_bt_flags[$i]:-0} )); then
                display_indexes+=("$i")
              fi
            done
            if (( ${#display_indexes[@]} == 0 )); then
              show_full_list=1
              filtered_view_active=0
              for i in "${!ids[@]}"; do
                display_indexes+=("$i")
              done
              note "No Bluetooth-marked entries were found; staying on full USB list view."
            else
              note "Switched to Bluetooth-focused view."
            fi
          fi
          render_device_list=1
          continue
          ;;
      esac
    fi

    exclude_csv=""
    vm_csv=""
    local -A selected_vm_ids=()
    local -a selected_vm_indexes=()
    if [[ -n "$answer" ]]; then
      answer="${answer//,/ }"
      local token disp_idx idx id
      for token in $answer; do
        if [[ ! "$token" =~ ^[0-9]+$ ]]; then
          note "Ignoring invalid token: $token"
          continue
        fi
        if (( token < 1 || token > ${#display_indexes[@]} )); then
          note "Ignoring out-of-range selection: $token"
          continue
        fi
        disp_idx=$((token-1))
        idx="${display_indexes[$disp_idx]}"
        id="${ids[$idx]}"
        if [[ -z "${selected_vm_ids[$id]:-}" ]]; then
          vm_csv+="${vm_csv:+,}$id"
          selected_vm_ids[$id]=1
          selected_vm_indexes+=("$idx")
        fi
      done
    fi

    local uid
    for uid in "${unique_ids_order[@]}"; do
      if [[ -z "${selected_vm_ids[$uid]:-}" ]]; then
        exclude_csv+="${exclude_csv:+,}$uid"
      fi
    done

    local -a selected_storage_ids=()
    local sid
    for sid in "${storage_ids_order[@]}"; do
      if [[ -n "${selected_vm_ids[$sid]:-}" ]]; then
        selected_storage_ids+=("$sid")
      fi
    done

    if (( ${#selected_storage_ids[@]} > 0 )); then
      if (( storage_interlock_required )); then
        say
        if (( ENABLE_COLOR )); then
          say "${C_BOLD}${C_RED}DANGER:${C_RESET} Some storage devices are selected as VM-eligible detach targets."
        else
          say "DANGER: Some storage devices are selected as VM-eligible detach targets."
        fi
        note "Detaching storage-class USB devices can disconnect active host disks and cause data loss."
        note "Storage entries currently selected for VM eligibility:"
        for sid in "${selected_storage_ids[@]}"; do
          note "  - ${storage_id_to_label[$sid]}"
        done

        if prompt_yn "Re-enter numbers now and keep these storage devices host-bound?" Y "Storage safety"; then
          continue
        fi
        if ! confirm_phrase "Proceeding with storage devices marked VM-eligible is risky." "I ACCEPT STORAGE RISK"; then
          note "Risk confirmation not accepted; please choose VM-eligible devices again."
          continue
        fi
      else
        note "Info: some storage devices are selected as VM-eligible."
        note "Current policy is Bluetooth-only (MATCH_MODE=auto with empty INCLUDE_IDS), so non-Bluetooth storage devices are not detach targets."
      fi
    fi

    say
    note "Selection review:"
    if [[ -n "$vm_csv" ]]; then
      note "Selected VM-eligible IDs (detach targets): $vm_csv"
      local selected_idx selected_idx_text selected_idx_num
      note "Selected VM-eligible entries:"
      for selected_idx in "${selected_vm_indexes[@]}"; do
        selected_idx_num="${display_num_by_idx[$selected_idx]:-$((selected_idx+1))}"
        selected_idx_text="[$selected_idx_num]"
        if (( ENABLE_COLOR )) && [[ -n "${index_colors[$selected_idx]:-}" ]]; then
          selected_idx_text="${index_colors[$selected_idx]}[$selected_idx_num]${C_RESET}"
        fi
        note "  - ${selected_idx_text} ${labels[$selected_idx]}"
      done
    else
      note "No entries selected as VM-eligible."
    fi
    if [[ -n "$exclude_csv" ]]; then
      note "Derived EXCLUDE_IDS (kept host-bound): $exclude_csv"
    else
      note "Derived EXCLUDE_IDS (kept host-bound): <empty>"
    fi
    note "Mode summary per listed device:"
    note "  $mode_vm_note = selected here (eligible for automatic detach for VM passthrough)"
    note "  $mode_host_note = not selected (stays on host via EXCLUDE_IDS)"
    if (( ! storage_interlock_required )); then
      note "  Note: in current Bluetooth-only policy, non-Bluetooth devices are not detach targets."
    fi
    local entry_id mode_tag
    for i in "${display_indexes[@]}"; do
      idx_text="[${display_num_by_idx[$i]}]"
      if (( ENABLE_COLOR )) && [[ -n "${index_colors[$i]:-}" ]]; then
        idx_text="${index_colors[$i]}[${display_num_by_idx[$i]}]${C_RESET}"
      fi
      entry_id="${ids[$i]}"
      if [[ -n "${selected_vm_ids[$entry_id]:-}" ]]; then
        mode_tag="$mode_vm_note"
      else
        mode_tag="$mode_host_note"
      fi
      note "  - ${idx_text} ${mode_tag} ${labels[$i]}"
    done

    if prompt_yn "Apply this VM-eligible selection now?" Y "USB exclusion review"; then
      break
    fi
    note "Selection not applied; re-enter numbers to adjust your choices."
    if (( can_toggle_view )); then
      note "Quick view switch: type 'full' for all USB devices or 'focus' for Bluetooth-focused entries."
    fi
  done
  if [[ -n "$interactive_in_fd" ]]; then
    exec {interactive_in_fd}<&-
  fi
  if (( DRY_RUN )); then
    return 0
  fi
  if [[ ! -f "$conf" ]]; then
    if ! ensure_usb_bt_match_conf_present "$conf"; then
      die "Unable to apply EXCLUDE_IDS; match config is missing and could not be recreated: $conf"
    fi
  fi
  local existing_exclude
  existing_exclude="$(awk -F= '/^EXCLUDE_IDS=/{v=$2; gsub(/"/,"",v); gsub(/[[:space:]]/,"",v); print tolower(v); exit}' "$conf" 2>/dev/null || true)"
  existing_exclude="${existing_exclude:-}"
  if [[ "$existing_exclude" == "$exclude_csv" ]]; then
    note "EXCLUDE_IDS unchanged; skipping write."
    USB_BT_EXCLUDE_CHANGED=0
    if [[ -n "$vm_csv" ]]; then
      say "Configured USB Bluetooth VM-eligible IDs: $vm_csv"
    else
      say "Configured USB Bluetooth VM-eligible IDs: <empty>"
    fi
    if [[ -n "$exclude_csv" ]]; then
      say "Configured USB Bluetooth EXCLUDE_IDS (kept host-bound): $exclude_csv"
    else
      say "Configured USB Bluetooth EXCLUDE_IDS (kept host-bound): <empty>"
    fi
    return 0
  fi

  local tmp mode owner group
  tmp="$(mktemp)"
  awk -v exclude="$exclude_csv" '
    BEGIN { done=0 }
    /^EXCLUDE_IDS=/ { print "EXCLUDE_IDS=\"" exclude "\""; done=1; next }
    { print }
    END {
      if (!done) {
        print "EXCLUDE_IDS=\"" exclude "\""
      }
    }
  ' "$conf" >"$tmp"
  mode="$(stat -c '%a' "$conf" 2>/dev/null || echo 644)"
  owner="$(stat -c '%u' "$conf" 2>/dev/null || id -u)"
  group="$(stat -c '%g' "$conf" 2>/dev/null || id -g)"

  install -o "$owner" -g "$group" -m "$mode" "$tmp" "$conf"
  rm -f "$tmp" || true
  USB_BT_EXCLUDE_CHANGED=1

  if [[ -n "$vm_csv" ]]; then
    say "Configured USB Bluetooth VM-eligible IDs: $vm_csv"
  else
    say "Configured USB Bluetooth VM-eligible IDs: <empty>"
  fi
  if [[ -n "$exclude_csv" ]]; then
    say "Configured USB Bluetooth EXCLUDE_IDS (kept host-bound): $exclude_csv"
  else
    say "Configured USB Bluetooth EXCLUDE_IDS (kept host-bound): <empty>"
  fi
}

install_usb_bluetooth_disable() {
  local had_unit had_match_conf should_start_now usb_bt_artifacts_changed
  local existing_match_mode existing_include_ids existing_exclude_ids exclusions_preconfigured
  had_unit=0
  had_match_conf=0
  should_start_now=1
  usb_bt_artifacts_changed=0
  exclusions_preconfigured=0
  if [[ -f "$USB_BT_SYSTEMD_UNIT" ]]; then
    had_unit=1
  fi
  if [[ -f "$USB_BT_MATCH_CONF" ]]; then
    had_match_conf=1
    backup_file "$USB_BT_MATCH_CONF"
  fi
  ensure_usb_bt_match_conf_present "$USB_BT_MATCH_CONF" || die "Unable to create USB Bluetooth match policy config: $USB_BT_MATCH_CONF"
  if [[ "$had_match_conf" -eq 0 ]]; then
    usb_bt_artifacts_changed=1
  fi
  existing_match_mode="$(awk -F= '/^MATCH_MODE=/{v=$2; gsub(/"/,"",v); gsub(/[[:space:]]/,"",v); print tolower(v); exit}' "$USB_BT_MATCH_CONF" 2>/dev/null || true)"
  existing_include_ids="$(awk -F= '/^INCLUDE_IDS=/{v=$2; gsub(/"/,"",v); gsub(/[[:space:]]/,"",v); print tolower(v); exit}' "$USB_BT_MATCH_CONF" 2>/dev/null || true)"
  existing_exclude_ids="$(awk -F= '/^EXCLUDE_IDS=/{v=$2; gsub(/"/,"",v); gsub(/[[:space:]]/,"",v); print tolower(v); exit}' "$USB_BT_MATCH_CONF" 2>/dev/null || true)"
  existing_match_mode="${existing_match_mode:-auto}"
  if [[ "$existing_match_mode" != "auto" || -n "$existing_include_ids" || -n "$existing_exclude_ids" ]]; then
    exclusions_preconfigured=1
  fi

  if write_file_atomic_if_changed "$USB_BT_SCRIPT" 0755 "root:root" 1 <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

MODE="disable"  # disable | enable
if [[ "${1:-}" == "--enable" ]]; then
  MODE="enable"
elif [[ "${1:-}" == "--disable" || -z "${1:-}" ]]; then
  MODE="disable"
else
  echo "Usage: $(basename "$0") [--disable|--enable]" >&2
  exit 2
fi
MATCH_CONF="/etc/vfio-usb-bluetooth-match.conf"
MATCH_MODE="auto"
INCLUDE_IDS=""
EXCLUDE_IDS=""
if [[ -r "$MATCH_CONF" ]]; then
  # shellcheck disable=SC1091
  source "$MATCH_CONF"
fi

MATCH_MODE="${MATCH_MODE,,}"
case "$MATCH_MODE" in
  auto|include_only) ;;
  *) MATCH_MODE="auto" ;;
esac

normalize_id_component() {
  local v="${1,,}"
  v="${v#0x}"
  printf '%s' "$v"
}

match_id_pattern() {
  local pattern="${1,,}" vid="$2" pid="$3"
  local pvid ppid

  [[ "$pattern" == *:* ]] || return 1
  pvid="$(normalize_id_component "${pattern%%:*}")"
  ppid="$(normalize_id_component "${pattern##*:}")"

  [[ -n "$pvid" && -n "$ppid" ]] || return 1
  [[ "$pvid" == "*" || "$pvid" == "$vid" ]] || return 1
  [[ "$ppid" == "*" || "$ppid" == "$pid" ]] || return 1
  return 0
}

id_in_csv() {
  local csv="$1" vid="$2" pid="$3"
  local item
  [[ -n "$csv" ]] || return 1

  local IFS=','
  for item in $csv; do
    item="${item//[[:space:]]/}"
    [[ -n "$item" ]] || continue
    if match_id_pattern "$item" "$vid" "$pid"; then
      return 0
    fi
  done
  return 1
}
# - interface driver bound to btusb (covers vendor-specific interfaces).
usb_device_is_bluetooth() {
  local dev="$1"
  local intf cls sub drv

  shopt -s nullglob
  for intf in "$dev":*; do
    # Driver-based detection (best-effort)
    if [[ -L "$intf/driver" ]]; then
      drv="$(basename "$(readlink -f "$intf/driver" 2>/dev/null || true)")"
      if [[ "$drv" == "btusb" ]]; then
        return 0
      fi
    fi

    # Class-based detection
    if [[ -f "$intf/bInterfaceClass" && -f "$intf/bInterfaceSubClass" ]]; then
      cls="$(tr -d '\n' <"$intf/bInterfaceClass" | tr 'A-F' 'a-f')"
      sub="$(tr -d '\n' <"$intf/bInterfaceSubClass" | tr 'A-F' 'a-f')"
      if [[ "$cls" == "e0" && "$sub" == "01" ]]; then
        return 0
      fi
    fi
  done
  shopt -u nullglob

  return 1
}

device_matches_policy() {
  local dev="$1" vid pid
  vid="$(normalize_id_component "$(cat "$dev/idVendor" 2>/dev/null || echo '')")"
  pid="$(normalize_id_component "$(cat "$dev/idProduct" 2>/dev/null || echo '')")"
  [[ -n "$vid" && -n "$pid" ]] || return 1

  if [[ "$MATCH_MODE" == "include_only" ]]; then
    id_in_csv "$INCLUDE_IDS" "$vid" "$pid" || return 1
  else
    usb_device_is_bluetooth "$dev" || return 1
    if [[ -n "$INCLUDE_IDS" ]] && ! id_in_csv "$INCLUDE_IDS" "$vid" "$pid"; then
      return 1
    fi
  fi

  if id_in_csv "$EXCLUDE_IDS" "$vid" "$pid"; then
    return 1
  fi

  return 0
}
intf_disable() {
  local intf="$1"
  local name drv
  name="$(basename "$intf")"

  # Prevent btusb from binding again.
  if [[ -w "$intf/driver_override" ]]; then
    echo "none" >"$intf/driver_override" 2>/dev/null || true
  fi

  # If currently bound, unbind from btusb.
  if [[ -L "$intf/driver" ]]; then
    drv="$(basename "$(readlink -f "$intf/driver" 2>/dev/null || true)")"
    if [[ "$drv" == "btusb" && -w /sys/bus/usb/drivers/btusb/unbind ]]; then
      echo "$name" >/sys/bus/usb/drivers/btusb/unbind 2>/dev/null || true
    fi
  fi
}

intf_enable() {
  local intf="$1"
  local name
  name="$(basename "$intf")"

  # Allow drivers to bind again.
  if [[ -w "$intf/driver_override" ]]; then
    echo "" >"$intf/driver_override" 2>/dev/null || true
  fi

  # Best-effort rebind.
  if [[ -w /sys/bus/usb/drivers/btusb/bind ]]; then
    echo "$name" >/sys/bus/usb/drivers/btusb/bind 2>/dev/null || true
  fi
}

changed=0
for dev in /sys/bus/usb/devices/*; do
  [[ -f "$dev/idVendor" && -f "$dev/idProduct" ]] || continue
  if device_matches_policy "$dev"; then
    vid="$(normalize_id_component "$(cat "$dev/idVendor" 2>/dev/null || echo '?')")"
    pid="$(normalize_id_component "$(cat "$dev/idProduct" 2>/dev/null || echo '?')")"
    if usb_device_is_bluetooth "$dev"; then
      shopt -s nullglob
      for intf in "$dev":*; do
        [[ -d "$intf" ]] || continue
        if [[ "$MODE" == "disable" ]]; then
          intf_disable "$intf"
        else
          intf_enable "$intf"
        fi
      done
      shopt -u nullglob
      echo "vfio-usb-bluetooth: ${MODE}d $(basename "$dev") (${vid}:${pid}) mode=${MATCH_MODE}"
      changed=1
    fi
  fi
done

if (( ! changed )); then
  echo "vfio-usb-bluetooth: no matching USB Bluetooth devices found"
fi
EOF
  then
    usb_bt_artifacts_changed=1
  fi

  if write_file_atomic_if_changed "$USB_BT_SYSTEMD_UNIT" 0644 "root:root" 1 <<EOF
[Unit]
Description=Detach USB Bluetooth adapters from btusb (VFIO helper)
After=systemd-udevd.service
Wants=systemd-udevd.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=$USB_BT_SCRIPT --disable

[Install]
WantedBy=multi-user.target
EOF
  then
    usb_bt_artifacts_changed=1
  fi

  if write_file_atomic_if_changed "$USB_BT_UDEV_RULE" 0644 "root:root" 1 <<'EOF'
# Generated by vfio.sh
# Trigger the disable service when a USB Bluetooth interface appears.
# - Matches the standard Bluetooth USB interface class/subclass (e0/01)
# - Also matches interfaces that bind to btusb (covers vendor-specific descriptors)

ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", ATTR{bInterfaceClass}=="e0", ATTR{bInterfaceSubClass}=="01", TAG+="systemd", ENV{SYSTEMD_WANTS}+="vfio-disable-usb-bluetooth.service"
ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", DRIVERS=="btusb", TAG+="systemd", ENV{SYSTEMD_WANTS}+="vfio-disable-usb-bluetooth.service"
ACTION=="bind", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", DRIVERS=="btusb", TAG+="systemd", ENV{SYSTEMD_WANTS}+="vfio-disable-usb-bluetooth.service"
EOF
  then
    usb_bt_artifacts_changed=1
  fi

  if (( exclusions_preconfigured )) && [[ "$had_unit" -eq 1 && "$had_match_conf" -eq 1 ]]; then
    note "Detected existing USB Bluetooth mitigation configuration in: $USB_BT_MATCH_CONF"
    if prompt_yn "Existing USB Bluetooth exclusions/policy detected. Reconfigure now?" N "USB Bluetooth exclusions"; then
      configure_usb_bt_exclude_ids_interactive
      if [[ "${USB_BT_EXCLUDE_CHANGED:-0}" == "0" && "$had_unit" -eq 1 && "$usb_bt_artifacts_changed" -eq 0 ]]; then
        should_start_now=0
      fi
    else
      note "Keeping existing USB Bluetooth exclusions/policy without reconfiguration."
      USB_BT_EXCLUDE_CHANGED=0
      if [[ "$had_unit" -eq 1 && "$usb_bt_artifacts_changed" -eq 0 ]]; then
        should_start_now=0
      fi
    fi
  elif prompt_yn "Review USB devices now and choose EXCLUDE_IDS for mitigation?" Y "USB Bluetooth exclusions"; then
    configure_usb_bt_exclude_ids_interactive
    if [[ "${USB_BT_EXCLUDE_CHANGED:-0}" == "0" && "$had_unit" -eq 1 && "$usb_bt_artifacts_changed" -eq 0 ]]; then
      should_start_now=0
    fi
  else
    note "Keeping EXCLUDE_IDS empty (no explicit USB exclusions)."
    if [[ "$had_unit" -eq 1 && "$usb_bt_artifacts_changed" -eq 0 ]]; then
      should_start_now=0
    fi
  fi

  if have_cmd udevadm; then
    run udevadm control --reload-rules
    # Trigger is best-effort; it can be noisy on some systems, so ignore failures.
    run udevadm trigger --subsystem-match=usb 2>/dev/null || true
  fi

  run systemctl daemon-reload
  if (( should_start_now )); then
    run systemctl enable --now vfio-disable-usb-bluetooth.service
  else
    run systemctl enable vfio-disable-usb-bluetooth.service
    note "USB Bluetooth settings unchanged; skipping immediate service run."
  fi

  say "Installed USB Bluetooth disable helper: $USB_BT_SCRIPT"
  say "Installed systemd unit: $USB_BT_SYSTEMD_UNIT"
  say "Installed udev rule: $USB_BT_UDEV_RULE"
  say "Installed match policy config: $USB_BT_MATCH_CONF"
}

# Install a small helper that dumps the current boot's VFIO-related logs to the
# desktop of the primary user. This makes it easy to inspect what happened
# during early boot without having to remember journalctl incantations.
install_bootlog_dumper() {
  local user home user_home user_group
  user_home="$(resolve_desktop_user_home 2>/dev/null || true)"
  if [[ -z "$user_home" ]]; then
    note "Skipping boot log dumper: could not resolve a desktop user home under /home."
    return 0
  fi
  user="${user_home%%$'\t'*}"
  home="${user_home#*$'\t'}"
  user_group="$(id -gn "$user" 2>/dev/null || true)"
  [[ -n "$user_group" ]] || user_group="$user"

  [[ -n "$home" && -d "$home" ]] || {
    note "Skipping boot log dumper: resolved user '$user' has no accessible home directory."
    return 0
  }

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
TARGET_USER="__VFIO_BOOT_USER__"
TARGET_GROUP="__VFIO_BOOT_GROUP__"
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
# Keep the full log tree user-manageable even though this helper runs as root.
# This allows the desktop user to inspect and delete collected boot logs
# without requiring sudo for routine cleanup.
chown -R "$TARGET_USER:$TARGET_GROUP" "$LOG_ROOT" 2>/dev/null || true
chmod -R u+rwX "$LOG_ROOT" 2>/dev/null || true

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

# Normalize ownership/perms after writes so newly created files from this run
# are also user-manageable.
chown -R "$TARGET_USER:$TARGET_GROUP" "$LOG_ROOT" 2>/dev/null || true
chmod -R u+rwX "$LOG_ROOT" 2>/dev/null || true
EOF

  # Service: run once each boot as early as practical while still guaranteeing
  # journald and local filesystems are available, and complete BEFORE
  # multi-user.target is reached.
  write_file_atomic "$unit" 0644 "root:root" <<EOF
[Unit]
Description=VFIO Early Boot Log Dumper (current and previous boot)
Wants=local-fs.target systemd-journald.service
After=local-fs.target systemd-journald.service
Before=multi-user.target
ConditionPathExists=$bin

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
      sed -i "s#__VFIO_BOOT_USER__#$user#g" "$bin" || true
      sed -i "s#__VFIO_BOOT_GROUP__#$user_group#g" "$bin" || true
    fi
  fi
  if (( ! DRY_RUN )); then
    [[ -x "$bin" ]] || die "Boot log dumper deployment failed: script is not executable at $bin"
    [[ -f "$unit" ]] || die "Boot log dumper deployment failed: missing unit at $unit"
  fi

  if have_cmd systemctl; then
    run systemctl daemon-reload
    run systemctl enable vfio-dump-boot-log.service || true
  fi

  note "Boot log dumper installed. It will run once each boot before multi-user.target and drop vfio-boot-*.log files under ${home}/Desktop/vfio-boot-logs/."
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

  # Resizable BAR + Above 4G status for the configured guest GPU (informational only).
  if [[ -n "${GUEST_GPU_BDF:-}" ]]; then
    say
    hdr "GPU BAR layout (guest GPU)"
    local rebar_state above4g_state
    rebar_state="$(rebar_status_for_bdf "$GUEST_GPU_BDF")"
    above4g_state="$(above_4g_decoding_status_for_bdf "$GUEST_GPU_BDF")"
    if (( ENABLE_COLOR )); then
      say "${C_BLUE}INFO${C_RESET}: ReBAR status for $GUEST_GPU_BDF: ${C_BOLD}${rebar_state}${C_RESET}"
      say "${C_BLUE}INFO${C_RESET}: Above 4G Decoding (64-bit BAR) for $GUEST_GPU_BDF: ${C_BOLD}${above4g_state}${C_RESET}"
    else
      say "INFO: ReBAR status for $GUEST_GPU_BDF: ${rebar_state}"
      say "INFO: Above 4G Decoding (64-bit BAR) for $GUEST_GPU_BDF: ${above4g_state}"
    fi
    note "For passthrough, Above 4G Decoding / 64-bit BAR support should typically be ENABLED so large BARs can be mapped into the guest. ReBAR on top is optional and may need to be toggled depending on your platform."
  fi

  # On openSUSE/BLS, also check the CURRENT Boot Loader Spec entry that
  # was used to boot this kernel, so you know whether that exact entry
  # has the expected VFIO/IOMMU flags.
  #
  # IMPORTANT: some users boot non-standard kernels (for example Liquorix)
  # from the same root/subvolume as the distribution kernels. In that
  # case multiple BLS entries can share the same root= and rootflags=
  # values. To avoid falsely reporting the wrong entry, we also require
  # that the BLS file references the *running* kernel version string
  # (uname -r), similar to the logic used in systemd_boot_add_kernel_params().
  if is_opensuse_like && command -v sdbootutil >/dev/null 2>&1; then
    say
    say "-- Current BLS entry (openSUSE) --"
    local running_cmdline bls_dir entry opts running_kernel
    running_cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
    bls_dir="$(systemd_boot_entries_dir 2>/dev/null || true)"
    running_kernel="$(uname -r)"
    if [[ -n "$bls_dir" && -n "$running_cmdline" && -n "$running_kernel" ]]; then
      local running_root running_rootflags
      running_root="$(sed -n 's/.*\<root=\([^ ]*\).*/\1/p' <<<"$running_cmdline")"
      running_rootflags="$(sed -nE 's/.*rootflags="?([^ "]+)"?.*/\1/p' <<<"$running_cmdline")"
      if [[ -n "$running_root" && -n "$running_rootflags" ]]; then
        local f matched=0
        shopt -s nullglob
        for f in "$bls_dir"/*.conf; do
          opts="$(grep -m1 -E '^options[[:space:]]+' "$f" 2>/dev/null | sed -E 's/^options[[:space:]]+//')"
          opts="$(trim "${opts:-}")"
          [[ -n "$opts" ]] || continue
          # Only consider entries whose file content mentions the running
          # kernel version (usually on the linux / initrd lines).
          if ! grep -Fq "$running_kernel" "$f" 2>/dev/null; then
            continue
          fi
          local eroot eflags
          eroot="$(sed -n 's/.*\<root=\([^ ]*\).*/\1/p' <<<"$opts")"
          eflags="$(sed -nE 's/.*rootflags="?([^ "]+)"?.*/\1/p' <<<"$opts")"
          if [[ -n "$eroot" && -n "$eflags" && "$eroot" == "$running_root" && "$eflags" == "$running_rootflags" ]]; then
            matched=1
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
        if (( ! matched )); then
          say "No BLS entry exactly matching the running kernel ($running_kernel) and root/subvolume was found."
          say "This is normal if you booted a custom kernel (for example Liquorix) via a separate entry outside the standard system-* BLS files."
        fi
      fi
    fi
  fi

  # Host-side VM internet sanity for libvirt/virt-manager NAT networking.
  # Informational only; does not affect VFIO PASS/FAIL grading.
  report_vm_network_precheck || true
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
  local bootlog_bin
  bootlog_bin="$(bootlog_bin_path)"

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
    "$SOFTDEP_FILE"
    "$BIND_SCRIPT"
    "$GRAPHICS_DAEMON_SCRIPT"
    "$AUDIO_SCRIPT"
    "$OPENBOX_MONITOR_SCRIPT"
    "$SYSTEMD_UNIT"
    "$GRAPHICS_DAEMON_UNIT"
    "$UDEV_ISOLATION_RULE"
    "$USB_BT_SCRIPT"
    "$USB_BT_SYSTEMD_UNIT"
    "$USB_BT_UDEV_RULE"
    "$USB_BT_MATCH_CONF"
    "$LIGHTDM_FALLBACK_CONF"
    "/etc/systemd/system/vfio-dump-boot-log.service"
    "$bootlog_bin"
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

# Disable/stop VFIO-related services (best-effort)
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now vfio-bind-selected-gpu.service 2>/dev/null || true
  systemctl disable --now vfio-graphics-protocold.service 2>/dev/null || true
  systemctl disable --now vfio-disable-usb-bluetooth.service 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
fi

# Restore or remove managed files
${rr}

# Remove VFIO Openbox autostart marker block if backup is unavailable.
if [ -f '${OPENBOX_AUTOSTART_FILE}.bak.${RUN_TS}' ]; then
  cp -a '${OPENBOX_AUTOSTART_FILE}.bak.${RUN_TS}' '${OPENBOX_AUTOSTART_FILE}'
elif [ -f '${OPENBOX_AUTOSTART_FILE}' ]; then
  _vfio_tmp_autostart="\$(mktemp)"
  awk '
    \$0 == \"# BEGIN VFIO OPENBOX MONITOR AUTO-ACTIVATE\" { skip=1; next }
    \$0 == \"# END VFIO OPENBOX MONITOR AUTO-ACTIVATE\" { skip=0; next }
    !skip { print }
  ' '${OPENBOX_AUTOSTART_FILE}' >"\$_vfio_tmp_autostart" || true
  cat "\$_vfio_tmp_autostart" >'${OPENBOX_AUTOSTART_FILE}' || true
  rm -f "\$_vfio_tmp_autostart" || true
fi

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
# Display protocol helpers (X11/Wayland adaptive mode).
xorg_busid_from_bdf() {
  local bdf="$1"
  local bus_hex dev_hex func_dec
  if [[ ! "$bdf" =~ ^[[:xdigit:]]{4}:([[:xdigit:]]{2}):([[:xdigit:]]{2})\.([0-7])$ ]]; then
    return 1
  fi
  bus_hex="${BASH_REMATCH[1]}"
  dev_hex="${BASH_REMATCH[2]}"
  func_dec="${BASH_REMATCH[3]}"
  printf 'PCI:%d:%d:%d' "$((16#$bus_hex))" "$((16#$dev_hex))" "$func_dec"
}

install_xorg_host_gpu_pinning() {
  local host_gpu_bdf="$1"
  local guest_gpu_bdf="$2"
  local host_busid
  host_busid="$(xorg_busid_from_bdf "$host_gpu_bdf" 2>/dev/null || true)"
  [[ -n "$host_busid" ]] || die "Failed to convert host GPU BDF to Xorg BusID: $host_gpu_bdf"

  backup_file "$XORG_HOST_GPU_CONF"
  if (( ! DRY_RUN )); then
    mkdir -p /etc/X11/xorg.conf.d
  fi
  write_file_atomic "$XORG_HOST_GPU_CONF" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
# Explicit host/guest split for Xorg:
# - Host GPU (Xorg): $host_gpu_bdf
# - Guest GPU (VFIO): $guest_gpu_bdf

Section "ServerLayout"
    Identifier "Layout0"
    Screen 0 "Screen0"
EndSection

Section "Device"
    Identifier "HostGPU"
    BusID "$host_busid"
    Option "PrimaryGPU" "true"
EndSection

Section "Screen"
    Identifier "Screen0"
    Device "HostGPU"
EndSection
EOF
  say "Installed explicit Xorg host-GPU pinning at $XORG_HOST_GPU_CONF"
}

install_lightdm_host_gpu_isolation() {
  local host_gpu_bdf="$1"
  local host_busid
  host_busid="$(xorg_busid_from_bdf "$host_gpu_bdf" 2>/dev/null || true)"
  [[ -n "$host_busid" ]] || die "Failed to convert host GPU BDF to Xorg BusID: $host_gpu_bdf"

  backup_file "$LIGHTDM_HOST_GPU_CONF"
  if (( ! DRY_RUN )); then
    mkdir -p /etc/lightdm/lightdm.conf.d
  fi
  write_file_atomic "$LIGHTDM_HOST_GPU_CONF" 0644 "root:root" <<EOF
# Generated by $SCRIPT_NAME on $(date -Is)
# Keep LightDM/Xorg on host GPU while guest GPU is bound to VFIO.
[Seat:*]
xserver-command=X -core -isolateDevice $host_busid
EOF
  say "Installed LightDM host-GPU isolateDevice override at $LIGHTDM_HOST_GPU_CONF"
}

remove_xorg_host_gpu_pinning() {
  local removed=0
  if [[ -f "$XORG_HOST_GPU_CONF" ]]; then
    backup_file "$XORG_HOST_GPU_CONF"
    run rm -f "$XORG_HOST_GPU_CONF"
    removed=1
  fi
  if [[ -f "$LIGHTDM_HOST_GPU_CONF" ]]; then
    backup_file "$LIGHTDM_HOST_GPU_CONF"
    run rm -f "$LIGHTDM_HOST_GPU_CONF"
    removed=1
  fi
  if (( removed )); then
    note "Removed Xorg/LightDM host-GPU pinning files."
  fi
}

maybe_offer_xorg_explicit_prompt() {
  local host_gpu_bdf="$1"
  local guest_gpu_bdf="$2"
  local selected_mode="${3:-X11}"
  local xorg_status dm
  selected_mode="${selected_mode^^}"
  xorg_status="$(xorg_stack_status)"
  dm="$(detect_display_manager 2>/dev/null || true)"
  [[ -n "$dm" ]] || dm="none"

  if [[ "$selected_mode" != "X11" ]]; then
    note "Skipping explicit Xorg prompt because selected protocol mode is $selected_mode."
    return 0
  fi

  say
  hdr "Xorg explicit prompt (host/guest split)"
  note "Detected Xorg stack status: $(format_tri_state_status "$xorg_status")"
  if [[ "$xorg_status" != "WORKS" ]]; then
    note "Skipping explicit Xorg prompt because Xorg is not fully detected."
    return 0
  fi

  if [[ -z "$host_gpu_bdf" || -z "$guest_gpu_bdf" || "$host_gpu_bdf" == "$guest_gpu_bdf" ]]; then
    note "Skipping explicit Xorg prompt because host/guest GPU mapping is invalid."
    return 0
  fi

  note "Detected Xorg explicitly. You can install host-GPU pinning so Xorg does not select the guest VFIO GPU."
  note "Host GPU: $host_gpu_bdf | Guest GPU: $guest_gpu_bdf"
  if prompt_yn "Detected Xorg explicitly. Install host-GPU Xorg pinning now? (recommended)" Y "Xorg explicit prompt"; then
    install_xorg_host_gpu_pinning "$host_gpu_bdf" "$guest_gpu_bdf"
  else
    note "Skipping explicit Xorg host-GPU pinning."
    return 0
  fi

  if [[ "$dm" == "lightdm" ]]; then
    if prompt_yn "LightDM detected. Install LightDM host-GPU isolateDevice override too?" Y "Xorg explicit prompt"; then
      install_lightdm_host_gpu_isolation "$host_gpu_bdf"
    else
      note "Skipping LightDM isolateDevice override."
    fi
  fi
}
install_prelogin_x11_host_gpu_pinning_failsafe() {
  # Install-time guardrail for black-screen/no-screens failures:
  # when guest GPU is pre-bound to vfio-pci before display-manager startup,
  # X11 greeters can fail unless the host GPU is explicitly pinned.
  #
  # We apply this proactively for:
  # - explicit X11 mode
  # - AUTO mode with X11-prelogin display managers (SDDM/LightDM/LXDM/XDM)
  #
  # This is additive and compatible with the runtime graphics daemon policy.
  local host_gpu_bdf="$1"
  local guest_gpu_bdf="$2"
  local selected_mode="${3:-AUTO}"
  local dm xorg_status should_pin=0

  selected_mode="${selected_mode^^}"
  [[ -n "$host_gpu_bdf" && -n "$guest_gpu_bdf" ]] || return 0
  [[ "$host_gpu_bdf" != "$guest_gpu_bdf" ]] || return 0

  xorg_status="$(xorg_stack_status)"
  if [[ "$xorg_status" != "WORKS" ]]; then
    return 0
  fi

  dm="$(detect_display_manager 2>/dev/null || true)"
  [[ -n "$dm" ]] || dm="none"

  case "$selected_mode" in
    X11)
      should_pin=1
      ;;
    AUTO)
      case "$dm" in
        lightdm|sddm|lxdm|xdm)
          should_pin=1
          ;;
      esac
      ;;
  esac

  (( should_pin == 1 )) || return 0

  say
  hdr "Prelogin X11 host-GPU failsafe"
  note "Installing persistent host-GPU Xorg pinning to prevent no-screens black-screen failures when the guest GPU is pre-bound to vfio-pci."
  note "Display manager: ${dm} | Graphics mode: ${selected_mode}"
  install_xorg_host_gpu_pinning "$host_gpu_bdf" "$guest_gpu_bdf"
  if [[ "$dm" == "lightdm" ]]; then
    install_lightdm_host_gpu_isolation "$host_gpu_bdf"
  fi
}

install_packages_best_effort() {
  local -a pkgs=("$@")
  local use_sudo=0
  (( ${#pkgs[@]} > 0 )) || return 1

  if [[ "${EUID:-$(id -u)}" -ne 0 ]] && have_cmd sudo; then
    use_sudo=1
  fi

  if have_cmd apt-get; then
    if (( use_sudo )); then
      run sudo apt-get -y install "${pkgs[@]}"
    else
      run apt-get -y install "${pkgs[@]}"
    fi
    return $?
  fi
  if have_cmd dnf; then
    if (( use_sudo )); then
      run sudo dnf -y install "${pkgs[@]}"
    else
      run dnf -y install "${pkgs[@]}"
    fi
    return $?
  fi
  if have_cmd zypper; then
    if (( use_sudo )); then
      run sudo zypper --non-interactive in "${pkgs[@]}"
    else
      run zypper --non-interactive in "${pkgs[@]}"
    fi
    return $?
  fi
  if have_cmd pacman; then
    if (( use_sudo )); then
      run sudo pacman --noconfirm -S "${pkgs[@]}"
    else
      run pacman --noconfirm -S "${pkgs[@]}"
    fi
    return $?
  fi

  return 1
}

protocol_runtime_packages_for_mode() {
  local mode="${1:-}"
  mode="${mode^^}"
  [[ "$mode" == "X11" || "$mode" == "WAYLAND" ]] || return 1

  if have_cmd apt-get; then
    if [[ "$mode" == "X11" ]]; then
      printf '%s\n' xserver-xorg xinit x11-xserver-utils
    else
      printf '%s\n' weston wayland-protocols
    fi
    return 0
  fi
  if have_cmd dnf; then
    if [[ "$mode" == "X11" ]]; then
      printf '%s\n' xorg-x11-server-Xorg xorg-x11-xinit
    else
      printf '%s\n' wayland-protocols weston
    fi
    return 0
  fi
  if have_cmd zypper; then
    if [[ "$mode" == "X11" ]]; then
      printf '%s\n' xorg-x11-server xinit
    else
      printf '%s\n' wayland weston
    fi
    return 0
  fi
  if have_cmd pacman; then
    if [[ "$mode" == "X11" ]]; then
      printf '%s\n' xorg-server xorg-xinit
    else
      printf '%s\n' wayland wayland-protocols weston
    fi
    return 0
  fi

  return 1
}

protocol_stack_status_for_mode() {
  local mode="${1:-}"
  mode="${mode^^}"
  if [[ "$mode" == "X11" ]]; then
    xorg_stack_status
  else
    wayland_stack_status
  fi
}

ensure_graphics_protocol_runtime() {
  local mode="${1:-}"
  mode="${mode^^}"
  [[ "$mode" == "X11" || "$mode" == "WAYLAND" ]] || return 1

  local before after
  before="$(protocol_stack_status_for_mode "$mode")"
  if [[ "$before" == "WORKS" ]]; then
    return 0
  fi

  say
  hdr "Graphics protocol runtime ($mode)"
  note "$mode status before install: $(format_tri_state_status "$before")"

  local -a pkgs=()
  mapfile -t pkgs < <(protocol_runtime_packages_for_mode "$mode" || true)
  if (( ${#pkgs[@]} == 0 )); then
    note "No known package mapping for your package manager. Install $mode runtime manually and re-run."
    return 1
  fi

  note "Suggested packages: ${pkgs[*]}"
  if ! prompt_yn "Install missing $mode runtime packages now?" Y "Graphics protocol runtime"; then
    return 1
  fi

  if ! install_packages_best_effort "${pkgs[@]}"; then
    note "Automatic package installation failed. Install the packages manually and re-run."
    return 1
  fi

  after="$(protocol_stack_status_for_mode "$mode")"
  note "$mode status after install: $(format_tri_state_status "$after")"
  [[ "$after" == "WORKS" ]]
}

select_and_prepare_graphics_protocol_mode() {
  local xorg_status wayland_status support detected_mode selected_mode forced_mode
  xorg_status="$(xorg_stack_status)"
  wayland_status="$(wayland_stack_status)"
  support="$(x11_wayland_support_status "$xorg_status" "$wayland_status")"
  detected_mode="$(x11_wayland_supported_mode "$xorg_status" "$wayland_status")"
  forced_mode="${GRAPHICS_PROTOCOL_OVERRIDE:-}"

  say
  hdr "Graphics protocol auto-detection"
  note "X11 (Xorg): $(format_tri_state_status "$xorg_status")"
  note "Wayland: $(format_tri_state_status "$wayland_status")"
  note "Detected mode availability: $detected_mode"

  if [[ -n "$forced_mode" ]]; then
    selected_mode="$forced_mode"
    note "CLI override applied: --graphics-protocol ${forced_mode,,}"
    case "$selected_mode" in
      X11|WAYLAND)
        if ! ensure_graphics_protocol_runtime "$selected_mode"; then
          die "${selected_mode} mode is required by CLI override but not fully ready. Install/repair ${selected_mode} runtime, then re-run."
        fi
        ;;
      AUTO)
        if [[ "$support" != "WORKS" ]]; then
          die "AUTO mode requested but neither X11 nor Wayland is fully working. Install one runtime stack, then re-run."
        fi
        ;;
    esac
  else
    if [[ "$detected_mode" == "BOTH" ]]; then
      selected_mode="AUTO"
      note "Both X11 and Wayland report WORKS; enabling protocol-agnostic AUTO mode."
      note "No graphics-mode selection is required during install."
    elif [[ "$detected_mode" == "X11" ]]; then
      selected_mode="X11"
      note "Only X11 currently reports WORKS; selecting X11 automatically."
      if ! ensure_graphics_protocol_runtime "$selected_mode"; then
        die "X11 mode is required but not fully ready. Install/repair X11 runtime, then re-run."
      fi
    elif [[ "$detected_mode" == "WAYLAND" ]]; then
      selected_mode="WAYLAND"
      note "Only Wayland currently reports WORKS; selecting Wayland automatically."
      if ! ensure_graphics_protocol_runtime "$selected_mode"; then
        die "Wayland mode is required but not fully ready. Install/repair Wayland runtime, then re-run."
      fi
    else
      # PARTIAL/NONE: no interactive protocol chooser. Try to make one stack
      # ready automatically in a deterministic order.
      if ensure_graphics_protocol_runtime "WAYLAND"; then
        selected_mode="WAYLAND"
        note "Auto-selected Wayland after runtime preparation."
      elif ensure_graphics_protocol_runtime "X11"; then
        selected_mode="X11"
        note "Auto-selected X11 after runtime preparation."
      else
        die "Neither X11 nor Wayland is fully working. Install one runtime stack, then re-run."
      fi
    fi
  fi

  CTX[graphics_protocol_mode]="$selected_mode"
  note "Selected graphics protocol mode: $selected_mode"
  note "VFIO passthrough binding remains persistent and protocol-independent."
  note "Switching between Wayland and X11 later will not require rerunning protocol selection."
}

apply_selected_graphics_protocol_mode() {
  local host_gpu_bdf="$1"
  local guest_gpu_bdf="$2"
  local mode="${CTX[graphics_protocol_mode]:-AUTO}"
  mode="${mode^^}"

  say
  hdr "Graphics protocol activation schedule"
  case "$mode" in
    X11)
      note "X11 mode selected."
      ;;
    WAYLAND)
      note "Wayland mode selected."
      # Ensure next-login/session preference aligns with explicit WAYLAND mode.
      # This writes an additive SDDM config only when supported.
      set_plasma_wayland_default_session
      note "Wayland default-session preference has been refreshed for next login when supported by SDDM."
      ;;
    AUTO)
      note "AUTO mode selected (protocol-agnostic)."
      ;;
    *)
      note "No explicit protocol mode selected; keeping protocol behavior unchanged."
      ;;
  esac
  note "Protocol adaptation is deferred to next boot."
  note "No live Wayland/X11 switching is performed during this install run."
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
    # Optional USB Bluetooth disable unit
    run systemctl disable --now vfio-disable-usb-bluetooth.service 2>/dev/null || true
    # Graphics protocol adaptation daemon
    run systemctl disable --now vfio-graphics-protocold.service 2>/dev/null || true

    # If we previously masked plymouth units as part of "disable splash",
    # unmask them on reset so the system can return to distro defaults.
    unmask_plymouth_services

    run systemctl daemon-reload 2>/dev/null || true
  fi

  # Remove managed files, including optional helpers
  local bootlog_unit="/etc/systemd/system/vfio-dump-boot-log.service"
  local bootlog_bin
  bootlog_bin="$(bootlog_bin_path)"

  run rm -f "$SYSTEMD_UNIT" "$BIND_SCRIPT" "$AUDIO_SCRIPT" \
           "$OPENBOX_MONITOR_SCRIPT" \
           "$CONF_FILE" "$MODULES_LOAD" "$BLACKLIST_FILE" \
           "$SOFTDEP_FILE" "$DRACUT_VFIO_CONF" \
           "$UDEV_ISOLATION_RULE" \
           "$USB_BT_SCRIPT" "$USB_BT_SYSTEMD_UNIT" "$USB_BT_UDEV_RULE" "$USB_BT_MATCH_CONF" \
           "$GRAPHICS_DAEMON_SCRIPT" "$GRAPHICS_DAEMON_UNIT" \
           "$LIGHTDM_FALLBACK_CONF" "$XORG_HOST_GPU_CONF" "$LIGHTDM_HOST_GPU_CONF" \
           "$bootlog_unit" "$bootlog_bin" 2>/dev/null || true

  remove_openbox_autostart_hook

  if have_cmd udevadm; then
    run udevadm control --reload-rules 2>/dev/null || true
    run udevadm trigger 2>/dev/null || true
  fi

  # Remove user unit for SUDO_USER (and optionally all /home users)
  if [[ -n "${SUDO_USER:-}" ]]; then
    remove_user_audio_unit "$SUDO_USER"
  fi

  note "Reset mode: removing vfio-set-host-audio.service for all users under /home/*."
  local d u
  for d in /home/*; do
    [[ -d "$d" ]] || continue
    u="$(basename "$d")"
    # Some /home entries may not correspond to real user accounts; that's OK.
    remove_user_audio_unit "$u"
  done

  local grub_changed=0
  local opensuse_cmdline_present=0

  # Detect active bootloader so we do not try to "classic GRUB"-reset on
  # systems that actually use systemd-boot/GRUB2-BLS with /etc/kernel/cmdline.
  local reset_bl
  reset_bl="$(detect_bootloader)"

  # Remove GRUB kernel parameters added by this script (classic GRUB only).
  # On GRUB2-BLS/systemd-boot setups, we instead operate on /etc/kernel/cmdline.
  if [[ "$reset_bl" == "grub" && -f /etc/default/grub ]]; then
    note "Reset mode: removing VFIO-related kernel params from /etc/default/grub."
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
    # Optional USB/xHCI stability workarounds
    new="$(remove_param_all "$new" "usbcore.autosuspend=-1")"
    new="$(remove_param_all "$new" "pcie_aspm=off")"
    # Initramfs / VFIO ordering
    new="$(remove_param_all "$new" "rd.driver.pre=vfio-pci")"
    new="$(remove_param_prefix "$new" "vfio-pci.ids=")"
    # LSM knobs we may have added
    new="$(remove_param_all "$new" "selinux=0")"
    new="$(remove_param_all "$new" "apparmor=0")"
    # Boot verbosity and target overrides
    new="$(remove_param_all "$new" "systemd.show_status=1")"
    new="$(remove_param_all "$new" "loglevel=7")"
    new="$(remove_param_all "$new" "rd.plymouth=0")"
    new="$(remove_param_all "$new" "plymouth.enable=0")"
    new="$(remove_param_all "$new" "splash=silent")"
    new="$(remove_param_all "$new" "splash")"
    new="$(remove_param_all "$new" "rhgb")"
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

  # On openSUSE-like systems using systemd-boot/sdbootutil, also offer to
  # remove VFIO/IOMMU params from /etc/kernel/cmdline so future kernel
  # entries stop inheriting them. This path is also used for GRUB2-BLS.
  if is_opensuse_like && [[ -f /etc/kernel/cmdline ]]; then
    opensuse_cmdline_present=1
    note "Reset mode: removing VFIO-related kernel params from /etc/kernel/cmdline."
    backup_file /etc/kernel/cmdline
    local kcur knew
    kcur="$(cat /etc/kernel/cmdline 2>/dev/null || true)"
    knew="$kcur"
    # Core IOMMU / ACS params
    knew="$(remove_param_all "$knew" "amd_iommu=on")"
    knew="$(remove_param_all "$knew" "intel_iommu=on")"
    knew="$(remove_param_all "$knew" "iommu=pt")"
    knew="$(remove_param_all "$knew" "pcie_acs_override=downstream,multifunction")"
    # Optional USB/xHCI stability workarounds
    knew="$(remove_param_all "$knew" "usbcore.autosuspend=-1")"
    knew="$(remove_param_all "$knew" "pcie_aspm=off")"
    # Initramfs / VFIO ordering
    knew="$(remove_param_all "$knew" "rd.driver.pre=vfio-pci")"
    knew="$(remove_param_prefix "$knew" "vfio-pci.ids=")"
    # LSM knobs we may have added
    knew="$(remove_param_all "$knew" "selinux=0")"
    knew="$(remove_param_all "$knew" "apparmor=0")"
    # Boot verbosity and target overrides
    knew="$(remove_param_all "$knew" "systemd.show_status=1")"
    knew="$(remove_param_all "$knew" "loglevel=7")"
    knew="$(remove_param_all "$knew" "rd.plymouth=0")"
    knew="$(remove_param_all "$knew" "plymouth.enable=0")"
    knew="$(remove_param_all "$knew" "splash=silent")"
    knew="$(remove_param_all "$knew" "splash")"
    knew="$(remove_param_all "$knew" "rhgb")"
    knew="$(remove_param_all "$knew" "systemd.unit=multi-user.target")"
    # Framebuffer / sysfb related tweaks
    knew="$(remove_param_all "$knew" "video=efifb:off")"
    knew="$(remove_param_all "$knew" "video=vesafb:off")"
    knew="$(remove_param_all "$knew" "initcall_blacklist=sysfb_init")"
    if ! cmdline_get_key_value_token "$knew" "root" >/dev/null 2>&1; then
      local reset_recovered_opts reset_recovered_cmdline reset_recovered_root_tok
      reset_recovered_opts="$(bls_find_boot_metadata_options 2>/dev/null || true)"
      if [[ -n "$reset_recovered_opts" ]]; then
        reset_recovered_cmdline="$(cmdline_add_boot_metadata_tokens_from_options "$knew" "$reset_recovered_opts")"
        reset_recovered_root_tok="$(cmdline_get_key_value_token "$reset_recovered_cmdline" "root" 2>/dev/null || true)"
        if [[ -n "$reset_recovered_root_tok" ]]; then
          knew="$reset_recovered_cmdline"
          note "Reset mode safety: restored missing root boot metadata in /etc/kernel/cmdline."
        fi
      fi
    fi

    if ! cmdline_get_key_value_token "$knew" "root" >/dev/null 2>&1; then
      note "Reset mode safety: refusing to write /etc/kernel/cmdline without root=... token."
      note "Leaving existing /etc/kernel/cmdline unchanged."
    elif [[ "$(trim "$knew")" != "$(trim "$kcur")" ]]; then
      if (( ! DRY_RUN )); then
        printf '%s\n' "$knew" >/etc/kernel/cmdline
      fi
    else
      note "No matching VFIO/IOMMU-related params found in /etc/kernel/cmdline; leaving it unchanged."
    fi
  fi

  # Always refresh openSUSE BLS entries during reset (even when /etc/kernel/cmdline
  # did not change) so stale entry options are reconciled immediately.
  if (( opensuse_cmdline_present )); then
    note "Reset mode: refreshing Boot Loader Spec entries on openSUSE."
    opensuse_sdbootutil_update_all_entries
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
      if [[ -n "$out" ]]; then
        run grub-mkconfig -o "$out" || true
      fi
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
      local out
      if [[ -d /boot/grub2 ]]; then
        out=/boot/grub2/grub.cfg
      elif [[ -d /boot/grub ]]; then
        out=/boot/grub/grub.cfg
      else
        out=""
      fi
      if [[ -n "$out" ]]; then
        run grub2-mkconfig -o "$out" || true
      fi
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

  # Early, kernel-wide VFIO risk audit. At this point we do not yet know
  # which GPU will be the guest, so we only run the generic checks (no
  # BDF argument). Later, after GPU selection, we run a targeted audit
  # again for the chosen guest GPU.
  #
  # IMPORTANT: audit_vfio_health returns non-zero for WARN/FAIL, but we
  # treat this as informational here. The hard gate happens later in
  # apply_configuration().
  audit_vfio_health "" || true

  say
  hdr "Environment support"
  note "Init system: systemd (required; other init systems are NOT supported by this helper)."
  note "Boot loader detected: ${CTX[bootloader]}"
  if [[ "${CTX[bootloader]}" == "grub" || "${CTX[bootloader]}" == "systemd-boot" || "${CTX[bootloader]}" == "grub2-bls" ]]; then
    note "Automatic kernel parameter editing is available for ${CTX[bootloader]}."
  else
    note "Automatic kernel parameter editing is ONLY implemented for GRUB and systemd-boot. For ${CTX[bootloader]}, you must apply kernel parameters manually when prompted."
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
  local gpu_bdf gpu_desc vendor_id device_id_unused audio_csv audio_descs
  while IFS=$'\t' read -r gpu_bdf gpu_desc vendor_id device_id_unused audio_csv audio_descs; do
    [[ -n "${gpu_bdf:-}" ]] || continue
    : "${device_id_unused:-}"
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

  # Resizable BAR status for the selected guest GPU. This is informational
  # but we make it explicit because on some platforms ReBAR being enabled
  # or disabled can be the difference between a black screen and a working
  # guest. The behavior is hardware/firmware specific, so we do NOT force
  # any particular state here.
  #
  # IMPORTANT: For GPU passthrough the **mandatory** BIOS setting is usually
  # "Above 4G Decoding" / "64-bit BAR support" being enabled, so that large
  # PCI BARs can be mapped into the guest address space. ReBAR on top of
  # that is optional/experimental: on some machines it must be ON, on
  # others it must be OFF to avoid black screens once the vendor driver
  # loads inside the VM.
  if rebar_enabled_for_bdf "${CTX[guest_gpu]}"; then
    say
    hdr "Resizable BAR (ReBAR) detected for guest GPU"
    note "lspci reports Resizable BAR as ENABLED for the selected guest GPU (${CTX[guest_gpu]})."
    note "Make sure your BIOS has 'Above 4G Decoding' (sometimes called 'Large BAR' or '64-bit BAR') ENABLED for GPU passthrough; that is the requirement for mapping big BARs into the VM."
    note "ReBAR itself is hardware/firmware specific: on some platforms enabling it fixes black screens, on others you must disable it for the VM to stay stable once the AMD/NVIDIA driver loads."
    note "If you later see black screens or no firmware logo in the guest, one of the first things to try is toggling ReBAR for this GPU in BIOS/UEFI (ON vs OFF) and retesting, with Above 4G Decoding kept enabled."
    if ! confirm_phrase "I understand that ReBAR is optional/experimental and I may need to experiment with it if problems appear." "I UNDERSTAND"; then
      die "Aborted at user request while acknowledging ReBAR status for the guest GPU."
    fi
  fi

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
    if amd_reset_issue_signatures_present_for_bdf "${CTX[guest_gpu]}"; then
      if [[ -d /sys/module/vendor_reset ]]; then
        say "OK: 'vendor-reset' module is loaded."
        if ! grep -q "vendor-reset" "$MODULES_LOAD" 2>/dev/null; then
          say "Adding vendor-reset to $MODULES_LOAD so it loads at boot..."
          if (( ! DRY_RUN )); then
            printf '%s\n' "vendor-reset" >>"$MODULES_LOAD"
          fi
        fi
      else
        say "${C_YELLOW}WARN: Reset-failure markers were detected for this AMD GPU, but 'vendor-reset' is not loaded.${C_RESET}"
        note "This indicates a real reset issue path (FLR/D3/timeout) where vendor-reset may help."
        note "Recommended: install the 'vendor-reset' kernel module (see vendor-reset project docs) after this script finishes."
      fi
    else
      say "INFO: No reset-failure markers detected for the selected AMD GPU in recent kernel logs."
      note "vendor-reset is not recommended by default unless reset failures are observed."
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
  local boot_vga_policy_mode="${BOOT_VGA_POLICY_OVERRIDE:-AUTO}"
  boot_vga_policy_mode="${boot_vga_policy_mode^^}"
  case "$boot_vga_policy_mode" in
    AUTO|STRICT) ;;
    *) boot_vga_policy_mode="AUTO" ;;
  esac

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
  say "  Boot-VGA host-assisted policy: ${boot_vga_policy_mode}"
  if [[ -n "${BOOT_VGA_POLICY_OVERRIDE:-}" ]]; then
    note "CLI override applied: --boot-vga-policy ${BOOT_VGA_POLICY_OVERRIDE,,}"
  fi
  if [[ "${XDG_CURRENT_DESKTOP:-}" =~ KDE|Plasma|PLASMA ]]; then
    note "Desktop session: KDE Plasma detected; these settings are tuned for Plasma + Wayland + PipeWire."
  fi
  # Targeted VFIO kernel audit for the selected guest GPU before we write
  # any configuration. If the kernel looks hostile (CTX[kernel_vfio_risk]=1),
  # we warn loudly and require explicit confirmation to continue.
  #
  # IMPORTANT: ignore the function's exit status here so that set -e does
  # not abort before we can show the warning and ask for confirmation.
  say
  audit_vfio_health "$guest_gpu" || true
  if [[ "${CTX[kernel_vfio_risk]:-0}" == "1" ]]; then
    say
    hdr "Kernel appears hostile to VFIO (proceed with caution)"
    note "The checks above indicate that this running kernel is likely affected by a VFIO/simpledrm regression or similar issue."
    note "Recommended: switch to a known-good kernel (for example the distribution's long-term kernel) before relying on this configuration."
    if ! confirm_phrase "Continuing on a hostile kernel can lead to black screens or failed passthrough even with correct settings." "I UNDERSTAND"; then
      die "Aborted due to high-risk kernel for VFIO. Boot a safer kernel (e.g. longterm) and re-run this helper."
    fi
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

  # Display-manager guardrail:
  # - LightDM: enforce AccountsService/fallback check
  # - SDDM/GDM/LXDM/XDM: recognized and treated as supported
  display_manager_dependency_preflight
  # Graphics protocol guardrail:
  # This helper supports only X11(Xorg)/Wayland and requires at least
  # one stack in WORKS state before installation proceeds.
  graphics_protocol_preflight
  select_and_prepare_graphics_protocol_mode
  local graphics_protocol_mode="${CTX[graphics_protocol_mode]:-AUTO}"
  local graphics_daemon_interval="${GRAPHICS_DAEMON_INTERVAL_OVERRIDE:-$GRAPHICS_DAEMON_INTERVAL_DEFAULT}"
  if [[ "$graphics_protocol_mode" == "AUTO" ]]; then
    say "  Graphics protocol: AUTO (X11 + Wayland compatible, no manual mode selection)"
  else
    say "  Graphics protocol: $graphics_protocol_mode (auto-detected)"
  fi
  if [[ -n "${GRAPHICS_PROTOCOL_OVERRIDE:-}" ]]; then
    note "Graphics protocol override in effect: --graphics-protocol ${GRAPHICS_PROTOCOL_OVERRIDE,,}"
  fi
  if (( INSTALL_GRAPHICS_DAEMON == 0 )); then
    note "CLI override applied: --no-graphics-daemon (independent graphics daemon will not be installed)."
  elif [[ -n "${GRAPHICS_DAEMON_INTERVAL_OVERRIDE:-}" ]]; then
    note "CLI override in effect: --graphics-daemon-interval ${graphics_daemon_interval}s"
  fi

  # Self-heal legacy user audio units that were created before the
  # ConditionPathExists guard was introduced.
  auto_repair_legacy_user_audio_unit_guards

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
  local openbox_runtime_status
  openbox_runtime_status="$(openbox_stack_status)"
  if [[ "$openbox_runtime_status" == "WORKS" || -d /etc/xdg/openbox ]]; then
    say
    hdr "Openbox monitor activation"
    note "Openbox integration can auto-detect connected monitors and activate all of them at session startup."
    note "This installs $OPENBOX_MONITOR_SCRIPT and additively updates $OPENBOX_AUTOSTART_FILE."
    if prompt_yn "Install/refresh Openbox auto-activate-all-monitors helper?" Y "Openbox monitor activation"; then
      install_openbox_monitor_activation
    else
      note "Skipping Openbox monitor activation helper."
    fi
  else
    note "Openbox stack not detected; skipping Openbox monitor activation integration."
  fi
  if [[ -n "$guest_audio_csv" ]]; then
    local IFS=',' dev
    for dev in $guest_audio_csv; do
      [[ -n "$dev" ]] || continue
      assert_pci_bdf_exists "$dev"
      assert_not_equal "$dev" "$host_audio_bdfs_csv" "Guest audio BDF equals host audio BDF (refusing)."
    done
  fi

  write_conf "$host_gpu" "$host_audio_bdfs_csv" "$host_audio_node_name" "$guest_gpu" "$guest_audio_csv" "$guest_vendor" "$graphics_protocol_mode" "$boot_vga_policy_mode" "$graphics_daemon_interval"
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
  if (( INSTALL_GRAPHICS_DAEMON )); then
    install_graphics_protocol_daemon "$graphics_daemon_interval"
  else
    note "Skipping graphics protocol daemon installation by user request (--no-graphics-daemon)."
  fi
  install_prelogin_x11_host_gpu_pinning_failsafe "$host_gpu" "$guest_gpu" "$graphics_protocol_mode"

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
  hdr "USB Bluetooth (optional)"
  note "Optional because most systems do NOT need this. Only enable it if you have a USB Bluetooth adapter (dongle/dock) that causes instability."
  usb_bt_mitigation_explain
  note
  note "What this installs: systemd+udev helper that detaches USB Bluetooth adapters from the host btusb driver (unbind + driver_override=none)."
  note "Result: host-side USB Bluetooth is effectively disabled (no reset-spam), but the USB device stays enumerated so it can be passed through to a VM."
  note "Re-enable later: $USB_BT_SCRIPT --enable (or remove everything via --reset)."
  if prompt_yn "Install and enable automatic USB Bluetooth host detach (systemd+udev)?" N "USB Bluetooth"; then
    install_usb_bluetooth_disable
  else
    note "Skipping USB Bluetooth helper."
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
  apply_selected_graphics_protocol_mode "$host_gpu" "$guest_gpu"

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
  # Ensure this helper is marked executable so it can be run as ./vfio.sh
  # even if the user originally invoked it via "sh vfio.sh" or similar.
  # Best-effort only: ignore failures (read-only filesystem, etc.).
  if [[ -f "$0" && ! -x "$0" ]]; then
    chmod +x "$0" 2>/dev/null || true
  fi

  parse_args "$@"

  if [[ "$MODE" == "print-fish-completion" ]]; then
    print_fish_completion
    exit 0
  fi
  if [[ "$MODE" == "print-bash-completion" ]]; then
    print_bash_completion
    exit 0
  fi
  if [[ "$MODE" == "print-zsh-completion" ]]; then
    print_zsh_completion
    exit 0
  fi

  # Core tools used across modes
  need_cmd lspci
  need_cmd sed
  need_cmd awk
  need_cmd grep
  need_cmd install
  need_cmd mktemp
  need_cmd stat

  # modprobe is only required for modes that actually manipulate
  # kernel modules / bindings. Self-test, detect and health-check
  # variants should be able to run in "thin" environments (containers,
  # chroots) where modprobe may be absent.
  if [[ "$MODE" != "verify" && "$MODE" != "self-test" && "$MODE" != "detect" && "$MODE" != "print-effective-config" && "$MODE" != "sync-bls-only" && "$MODE" != "debug-cmdline-tokens" && "$MODE" != "verify-bls-sync" && "$MODE" != "verify-bls-nosnapper" && "$MODE" != "create-fallback-entry" && "$MODE" != "health-check" && "$MODE" != "health-check-prev" && "$MODE" != "health-check-all" && "$MODE" != "usb-health-check" && "$MODE" != "install-bootlog" && "$MODE" != "install-usb-bt-mitigation" ]]; then
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
  if [[ "$MODE" == "verify-bls-sync" ]]; then
    verify_bls_entries_against_kernel_cmdline
    exit $?
  fi
  if [[ "$MODE" == "verify-bls-nosnapper" ]]; then
    verify_bls_no_snapper_writes
    exit $?
  fi

  if [[ "$MODE" == "sync-bls-only" ]]; then
    require_root "$@"
    require_writable_root_or_die
    sync_bls_entries_from_kernel_cmdline
    verify_bls_entries_against_kernel_cmdline
    exit $?
  fi
  if [[ "$MODE" == "debug-cmdline-tokens" ]]; then
    debug_bls_cmdline_tokens
    exit $?
  fi
  if [[ "$MODE" == "create-fallback-entry" ]]; then
    require_root "$@"
    require_writable_root_or_die
    create_or_update_bls_fallback_entry
    exit $?
  fi

  if [[ "$MODE" == "print-effective-config" ]]; then
    print_effective_config
    exit 0
  fi

  if [[ "$MODE" == "self-test" ]]; then
    self_test
    exit $?
  fi

  if [[ "$MODE" == "health-check" ]]; then
    # If a config exists, prefer to audit the configured guest GPU; otherwise
    # fall back to a generic audit.
    local guest_bdf=""
    if readable_file "$CONF_FILE"; then
      # shellcheck disable=SC1090
      . "$CONF_FILE"
      guest_bdf="${GUEST_GPU_BDF:-}"
    fi
    if [[ -n "$guest_bdf" ]]; then
      audit_vfio_health "$guest_bdf"
    else
      audit_vfio_health ""
    fi
    exit $?
  fi

  if [[ "$MODE" == "health-check-prev" ]]; then
    # Same as --health-check but using the PREVIOUS boot's kernel logs
    # (journalctl -k -b -1) when available.
    local guest_bdf=""
    if readable_file "$CONF_FILE"; then
      # shellcheck disable=SC1090
      . "$CONF_FILE"
      guest_bdf="${GUEST_GPU_BDF:-}"
    fi
    VFIO_HEALTH_BOOT_OFFSET=-1
    if [[ -n "$guest_bdf" ]]; then
      audit_vfio_health "$guest_bdf"
    else
      audit_vfio_health ""
    fi
    exit $?
  fi

  if [[ "$MODE" == "health-check-all" ]]; then
    health_check_all
    exit $?
  fi

  if [[ "$MODE" == "usb-health-check" ]]; then
    usb_health_check
    exit $?
  fi

  if [[ "$MODE" == "reset" ]]; then
    require_root "$@"
    require_systemd
    require_writable_root_or_die
    reset_vfio_all
    exit 0
  fi

  if [[ "$MODE" == "disable-bootlog" ]]; then
    require_root "$@"
    require_systemd
    require_writable_root_or_die
    disable_bootlog_dumper
    exit 0
  fi

  if [[ "$MODE" == "install-bootlog" ]]; then
    require_root "$@"
    require_systemd
    require_writable_root_or_die
    install_bootlog_dumper
    exit 0
  fi

  if [[ "$MODE" == "install-graphics-daemon" ]]; then
    require_root "$@"
    require_systemd
    require_writable_root_or_die
    install_graphics_protocol_daemon_from_existing_config
    exit 0
  fi

  if [[ "$MODE" == "install-usb-bt-mitigation" ]]; then
    require_root "$@"
    require_systemd
    require_writable_root_or_die

    say
    hdr "USB Bluetooth reset-spam mitigation (standalone install)"
    usb_bt_mitigation_explain
    say
    note "This will install:"
    note "  - $USB_BT_SCRIPT"
    note "  - $USB_BT_SYSTEMD_UNIT"
    note "  - $USB_BT_UDEV_RULE"
    note "  - $USB_BT_MATCH_CONF"
    if prompt_yn "Install USB Bluetooth host-detach mitigation now?" Y "USB Bluetooth"; then
      install_usb_bluetooth_disable
      say "Done."
    else
      die "Aborted by user"
    fi
    exit 0
  fi

  require_root "$@"
  require_systemd
  require_writable_root_or_die

  detect_system
  user_selection
  apply_configuration
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
