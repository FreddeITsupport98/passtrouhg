# vfio.sh – Safe multi‑GPU VFIO passthrough helper

> **Status:** This script is a highly defensive, feature‑rich VFIO helper that has been hardened for modern Fedora/RHEL/Arch‑style setups, AMD reset quirks, and boot‑VGA framebuffer conflicts. It is designed as a _host configuration wizard_, **not** a VM manager.

This repository contains a single, self‑contained Bash script, `vfio.sh`, that guides you through setting up **GPU passthrough with VFIO** in a way that is:

- **Multi‑vendor aware** – works with AMD, NVIDIA and Intel GPUs
- **IOMMU‑aware** – adds the right kernel parameters for your CPU family
- **BDF‑centric** – binds **only the exact PCI devices you picked** to `vfio-pci`
- **Audio‑aware** – helps you keep host audio working while optionally passing HDMI/DP audio to the VM
- **Bootloader‑aware** – updates GRUB safely, or prints manual instructions for other bootloaders
- **Reversible** – generates a rollback script and has a full `--reset` mode

The script is designed to be **interactive, defensive and reversible**, so that you are much less likely to soft‑brick your desktop or leave your host without graphics/audio.

> **Important:** This script does *not* create or modify VMs. It only prepares your host so that a hypervisor (libvirt/qemu, etc.) can passthrough the selected PCI devices.

---

## High‑level design

### Main goals

At a high level, `vfio.sh` aims to be a **single, auditable entry‑point** for GPU passthrough host configuration. Instead of copy‑pasting pieces from multiple guides (GRUB tweaks, modprobe snippets, systemd units, scripts, audio hacks), this tool assembles them under one orchestrated, interactive flow.

1. **Bind only the devices you explicitly chose** to `vfio-pci`:
   - The script discovers all GPUs and audio devices with `lspci`.
   - You pick a **guest GPU** (for passthrough) and a **host GPU** (for your desktop).
   - For audio, you pick which PCI audio device stays on the host and which (if any) gets passed through.
2. **Prefer PCI BDFs over raw IDs**:
   - Devices like AMD HDMI audio can share the same PCI ID (e.g. `1002:ab28`) on multiple GPUs.
   - Binding by `vendor:device` could accidentally bind **both** cards.
   - The script stores **full BDFs** (e.g. `0000:06:00.1`) in `/etc/vfio-gpu-passthrough.conf`.
3. **Minimize risk**:
   - Refuses to proceed if host GPU and guest GPU are the same.
   - Warns if guest GPU appears in use (DRM node open, etc.) and requires a manual confirmation phrase.
   - Hard‑gates suspicious IOMMU groups and mis‑matched audio slots with explicit confirmations.
4. **Be explicit about persistent changes**:
   - All file paths, systemd units, and kernel parameters are clearly shown before they are written.
   - Backups are created **once per run** and a standalone rollback script is generated.

### Files created / managed

This section describes the core artifacts the script manages. All paths are centralized near the top of `vfio.sh` as simple variables (`CONF_FILE`, `BIND_SCRIPT`, etc.), so you can easily adjust them if you want a different layout.

The script uses the following paths on the host:

- **Configuration**
  - `/etc/vfio-gpu-passthrough.conf` – main configuration file (host/guest BDFs, audio, vendor, PipeWire node name).

- **Core VFIO binding logic**
  - `/usr/local/sbin/vfio-bind-selected-gpu.sh` – run early at boot by systemd; binds only the configured devices to `vfio-pci`.
  - `/etc/systemd/system/vfio-bind-selected-gpu.service` – system service that runs the bind script before the display manager and libvirt/qemu.

- **Modules / blacklists**
  - `/etc/modules-load.d/vfio.conf` – ensures `vfio`, `vfio_pci`, `vfio_iommu_type1`, `vfio_virqfd` are loaded at boot.
  - `/etc/modprobe.d/vfio-optional-blacklist.conf` – optional, only written if you explicitly choose to blacklist vendor drivers.

- **Audio helpers**
  - `/usr/local/bin/vfio-set-host-audio.sh` – optional helper that sets your **desktop default audio sink** (PipeWire/PulseAudio) after login.
  - `~/.config/systemd/user/vfio-set-host-audio.service` – optional user‑level systemd unit to run the audio helper on login.

- **Backups and rollback**
  - `*.bak.<timestamp>` – backups of files the script edits (e.g. `/etc/default/grub.bak.20250101-120000`).
  - `/root/vfio-rollback-<timestamp>.sh` – rollback script that tries to restore backups, regenerate GRUB and rebuild initramfs.

All writes are done via an **atomic helper** (`write_file_atomic`) to avoid leaving partial or truncated files during failures.

---

## Requirements

The script tries to detect as much as possible at runtime, and will **refuse to continue** or fall back to read‑only/reporting modes when critical assumptions are not met.

### Hardware assumptions

- At least **two GPUs** detected by `lspci`:
  - One will be the **host GPU** (desktop display).
  - One will be the **guest GPU** (assigned to the VM).
- IOMMU support in CPU + chipset (VT‑d/AMD‑Vi) and **enabled in BIOS/UEFI**.

### Software assumptions

Mandatory commands:

- `bash`, `lspci`, `modprobe`, `sed`, `awk`, `grep`, `install`, `mktemp`
- `systemd` as PID 1 (`/run/systemd/system` exists, `systemctl` available)

Recommended:

- `wpctl` and PipeWire/WirePlumber (for better audio sink handling). The script will work without these, but some UX features will be skipped.
- `update-grub` or `grub-mkconfig` if you want automatic GRUB updates.
- One of `update-initramfs`, `mkinitcpio` or `dracut` to rebuild initramfs.

### Operating system / bootloader

- Script is designed for **Linux distributions using systemd**.
- Bootloader support:
  - **GRUB** – automatically edits `/etc/default/grub` in place and regenerates `grub.cfg`.
  - **systemd‑boot / rEFInd / others** – the script prints **manual kernel parameter instructions** instead of editing files.

---

## Installation

You can keep `vfio.sh` anywhere (e.g. inside this repository, `/root`, or a custom scripts directory). It is self‑contained and does not require installation beyond being executable.

Copy the script somewhere convenient, mark it executable and run it:

```bash path=null start=null
cd /path/to/passtrouhg
chmod +x vfio.sh
sudo ./vfio.sh
```

On first run it will:

1. Ensure required commands are available.
2. Ensure it is running as root and under systemd.
3. Run a **preflight check** for existing VFIO/passthrough configuration.
4. Launch an **interactive wizard** to select GPUs and audio devices and apply the configuration.

Use `sudo` so that the script can write to `/etc`, `/usr/local`, systemd directories, GRUB configs, and run kernel tools.

---

## Command‑line modes

The script supports several modes controlled by flags. By default, without any flag, it runs the **interactive installer**.

```text
./vfio.sh [--debug] [--dry-run] [--verify] [--detect] [--self-test] [--health-check] [--health-check-previous] [--health-check-all] [--reset] [--disable-bootlog]
```

### Common flags

- `--debug`
  - Enables verbose logging and `set -x` tracing.
  - Helpful if you want to see exactly what commands are executed.

- `--dry-run`
  - Prevents any persistent changes (no files written, no systemctl enable, etc.).
  - Most commands are only printed/logged.
  - Automatically implied by `--verify`, `--detect`, and `--self-test`.

### Operational modes

- `--health-check`
  - Audits the **currently running kernel and boot** for VFIO-friendliness.
  - Checks:
    - Kernel version (flags 6.13+ as high-risk for known VFIO/simpledrm regressions).
    - IOMMU groups and `vfio-pci` module availability.
    - Optional framebuffer locks (simpledrm/sysfb/efifb/vesafb) via `/proc/iomem`.
    - Kernel logs (via `journalctl -k -b` or `dmesg`) for vfio-pci BAR/probe errors.
  - Produces a single summary line and exit code:
    - `HEALTH: PASS` (exit 0) – no obvious VFIO-hostile markers.
    - `HEALTH: WARN` (exit 1) – one or more risk markers but no hard vfio-pci errors.
    - `HEALTH: FAIL` (exit 2) – vfio-pci BAR/probe errors detected in logs.

- `--health-check-previous`
  - Same as `--health-check`, but inspects the **previous boot’s kernel logs** (`journalctl -k -b -1`) when available.
  - Useful when a bad kernel just failed or black-screened and you have since rebooted into a safe kernel.

- `--health-check-all`
  - Runs the VFIO kernel health audit against **all detected GPUs** instead of just the configured guest GPU.
  - For each GPU BDF it prints the same PASS/WARN/FAIL grading as `--health-check`.
  - Exit code reflects the worst result across all GPUs:
    - 0 – all GPUs reported PASS.
    - 1 – at least one GPU reported WARN, none reported FAIL.
    - 2 – at least one GPU reported FAIL (vfio-pci errors in logs for some device).

- `--verify`
  - Does **not** change anything.
  - Reads `CONF_FILE` (`/etc/vfio-gpu-passthrough.conf`) and checks:
    - Whether the configured guest GPU and guest audio devices are currently bound to `vfio-pci`.
    - Whether the host audio device is *not* bound to `vfio-pci`.
    - Presence and enablement of the systemd service and scripts.
    - Basic IOMMU presence and GRUB/BLS kernel parameters.
  - Prints a PASS/FAIL summary with **colorful status markers** when ANSI colors are enabled:
    - Green `✔ OK` for good checks, red `✖ FAIL` for hard failures, yellow `WARN` for soft issues.
    - A final `✔ RESULT: PASS` or `✖ RESULT: FAIL` line, so you can see at a glance whether the current boot is VFIO‑ready.

- `--detect`
  - Scans your system and prints a rich **VFIO / passthrough detection report** including:
    - Kernel version and current `/proc/cmdline`.
    - Health assessment from `vfio_config_health` (`OK`, `WARN`, or `BAD` plus reasons).
    - Whether the script’s own config/service files exist.
    - Modprobe configuration hints under `/etc/modprobe.d`.
    - Detected initramfs framework(s) and whether VFIO is referenced there.
    - Current GPU & audio bindings from `lspci -nnk`.
    - Libvirt hook directory presence.
  - The report is **color‑aware** when ANSI colors are available:
    - Section headers use cyan, good resources and paths use green, and problems or missing pieces show up as yellow/red.
    - GPU and audio BDFs are highlighted in green so you can quickly spot which device is which.

- `--self-test`
  - Runs a small self test suite:
    - Checks `bash -n` (syntax of the script itself).
    - Checks `awk` behavior used by the PipeWire parsing.
    - Verifies `/dev/tty` access (important for menus under `sudo`).
    - Optionally checks `wpctl` connectivity to PipeWire.
    - Counts discovered GPUs.
  - Intended to catch environment regressions early.

- `--reset`
  - **Destructive clean-up** of everything this script manages.
  - Requires confirmation by typing a phrase (`RESET VFIO`).
  - Performs:
    - Disables and stops `vfio-bind-selected-gpu.service` and, if installed, the VFIO boot-log dumper service.
    - Removes its systemd unit, bind script, audio script, config, vfio modules‑load entry, optional blacklist, and optional boot-log helper.
    - Optionally removes user systemd audio units under `/home/*`.
    - Optionally removes VFIO/IOMMU and related debug kernel parameters from:
      - `/etc/default/grub` on classic GRUB systems, with:
        - Automatic `grub.cfg` regeneration.
        - A **GRUB syntax check** (`grub2-script-check`/`grub-script-check` when available) and automatic rollback to the backed‑up `/etc/default/grub` if the new config would cause lexer errors at boot.
      - `/etc/kernel/cmdline` on openSUSE/BLS systems, followed by a quiet `sdbootutil add-all-kernels` + `update-all-entries` to sync BLS entries.
    - Rebuilds initramfs to reflect the cleaned‑up configuration.
  - On openSUSE/Btrfs systems, prints a reminder that each snapshot has its own `/etc/kernel/cmdline`; after rolling back to an older snapshot you should re-run `--reset` from within that snapshot if you want its VFIO parameters removed as well.

- `--disable-bootlog`
  - Helper that disables and removes the optional `vfio-dump-boot-log.service` boot log dumper unit and its helper script.
  - Leaves all VFIO bindings, core config files, and kernel parameters intact.
  - Useful once your setup is stable and you no longer want the boot log dumper to run (existing logs under `~/Desktop/vfio-boot-logs/` are not deleted).

---

## Additional environment-specific behavior

### openSUSE, Btrfs snapshots and Boot Loader Spec (BLS)

On openSUSE systems that use **Btrfs snapshots** and **Boot Loader Spec (BLS)** entries, the script has extra logic to avoid the common pitfalls you ran into while experimenting with VFIO snapshots:

- Detects when the system is "openSUSE-like" via `ID` / `ID_LIKE` from `/etc/os-release`.
- Treats `/etc/kernel/cmdline` as the **single source of truth** for kernel parameters on BLS systems.
- Uses `sdbootutil` (when present) to regenerate BLS entries after changing `/etc/kernel/cmdline`, instead of trying to edit individual `*.conf` files itself.
- Automatically adds **framebuffer-disabling parameters** when needed to avoid boot-VGA framebuffer traps:
  - `video=efifb:off`
  - `video=vesafb:off`
  - `initcall_blacklist=sysfb_init`
- Offers to temporarily force the system to boot into `multi-user.target` (text mode) so that you can debug VFIO issues without the display manager immediately crashing and causing a reboot loop.

The net effect is that the script behaves like a **BLS-aware helper** on openSUSE:

- You keep using the normal distribution tools (`dracut`, `sdbootutil`),
- But the script ensures that VFIO-related parameters (`iommu=pt`, `rd.driver.pre=vfio-pci`, etc.) are consistently present in both `/etc/kernel/cmdline` and the generated entries.

### SELinux / AppArmor and snapshot rollbacks

On systems that support filesystem rollbacks (particularly openSUSE with Btrfs), enabling SELinux or AppArmor on an older root snapshot can cause subtle and confusing failures (services denied writes, desktop entering a spin-and-reboot loop, etc.).

The script does **not** attempt to manage LSM policy, but for safer VFIO testing it offers to:

- Remove `security=selinux` / `security=apparmor` and their `=1` forms from the kernel command line.
- Add `selinux=0 apparmor=0` so that the kernel boots with both disabled while you experiment with passthrough.

This is always presented as an **explicit prompt**; you can decline if you actively rely on SELinux/AppArmor and know how to manage their policies across snapshots.

On reset, the script can also remove these LSM-related parameters again from both classic GRUB cmdlines and `/etc/kernel/cmdline` (on openSUSE/BLS) so that rollbacks don’t permanently lock you into a “VFIO debug” LSM configuration.

### Dracut and early VFIO binding (`rd.driver.pre=vfio-pci`)

On **dracut-based** systems (including openSUSE Tumbleweed and many Fedora/RHEL style installs), the GPU driver may be pulled into the initramfs very early. If the host driver (`amdgpu`, `nvidia`, `i915`) loads before `vfio-pci`, passthrough can fail even if your GRUB/BLS parameters otherwise look correct.

To address this the script:

- Detects whether the `vfio-pci` module actually exists for the running kernel (via `modinfo`).
- When it does, offers to add **`rd.driver.pre=vfio-pci`** to:
  - `/etc/kernel/cmdline` on openSUSE BLS systems, and/or
  - The GRUB kernel command line.
- Treats this as **strongly recommended** on openSUSE + dracut, because it has a direct impact on whether the guest GPU is claimed by VFIO inside the initramfs.

If `vfio-pci` is missing for the current kernel, the script deliberately **does not** add `rd.driver.pre=vfio-pci` (to avoid early-boot modprobe failures).

On openSUSE BLS systems, after changing `/etc/kernel/cmdline` the script automatically runs:

- `sdbootutil add-all-kernels`
- `sdbootutil update-all-entries`

These are invoked quietly (errors are caught and turned into informational notes) so that Boot Loader Spec entries stay in sync with the updated kernel parameters without spamming low-level `sed` errors from `sdbootutil`.

### Boot log dumper for VFIO debugging

The script can install a small helper + systemd service that automatically dumps detailed **boot logs for VFIO-related debugging** to your desktop after each boot:

- A helper script is placed under the invoking user’s home (e.g. `~/.local/bin/vfio-dump-boot-log.sh`).
- A system service (`vfio-dump-boot-log.service`) runs once at boot and writes snapshot-aware logs into:
  - `~/Desktop/vfio-boot-logs/<year>/<month>/<day>/vfio-boot-<kernel>-{current,previous}.log`
- The log capture is **Btrfs snapshot aware**:
  - It parses the `rootflags=subvol=...` from `/proc/cmdline`.
  - It encodes the snapshot or subvolume name into the path so you can tell which snapshot a log came from.

This makes it much easier to see what happened on a failing VFIO snapshot **without** needing to dig around with `journalctl -b -1` or similar commands.

The boot log dumper is **off by default**:

- The installer explains that this helper is mainly useful while you are actively debugging VFIO failures.
- On a stable setup it can generate many log files over time.
- The prompt default is **No**; you must explicitly opt in if you want per-boot log files on your desktop.

### udev isolation rules for the guest GPU

To further reduce the chance that the host desktop environment (GDM, SDDM, etc.) grabs the guest GPU, the script can install **udev rules** that remove the guest GPU (and optionally its HDMI audio functions) from the systemd "master seat":

- Creates `/etc/udev/rules.d/99-vfio-isolation.rules` with rules like:
  - `TAG-="seat" TAG-="master-of-seat"` for the guest GPU BDF.
  - The same for any selected HDMI/DP audio PCI functions.
- Reloads udev rules and triggers them so that the change applies immediately.

The result is that the guest GPU is much less likely to be automatically associated with the host seat, making it easier to keep the card "headless" on the host and dedicated to the VM.

### TUI (whiptail) support vs plain-text mode

The script supports two presentation styles for its wizard:

- A **text-based UI (TUI)** using `whiptail` when available:
  - Yes/no dialogs for confirmations (`prompt_yn`).
  - Scrollable menus for GPU and audio device selection (`select_from_list`).
  - Clear titles on critical prompts like boot options, security modules, and initramfs behavior.
- A robust **plain-text fallback** when `whiptail` is not installed or when `--no-tui` is passed:
  - All prompts are printed to `/dev/tty` or `/dev/stderr` instead of stdout, so scripts that consume stdout remain stable.
  - Menus are rendered as numbered lists; you type the index.

You can force plain-text mode even when `whiptail` is present by using:

```bash path=null start=null
./vfio.sh --no-tui
```

This is useful when running over SSH or inside environments where TUI dialogs are undesirable.

In both TUI and plain-text modes the script clearly highlights **dangerous operations** (like uninstalling the default kernel on openSUSE) with bold/red warnings when ANSI colors are enabled, and with explicit "DANGER" text when colors are not available.

### Long-term kernel recommendation for some AMD setups

On some AMD Navi setups (for example, GPUs with PCI IDs similar to `1002:73bf`), very recent default kernels have been observed to let `amdgpu` claim the guest GPU even when:

- `vfio-pci.ids=vvvv:dddd` is present on the kernel command line, **and**
- `rd.driver.pre=vfio-pci` is used on dracut-based systems.

In contrast, the **distribution long-term kernel** (for example the `kernel-longterm` package on openSUSE) often has a more conservative driver stack and may reliably allow `vfio-pci` to own the card at boot.

The script encapsulates this as an **optional helper**, not a forced behavior:

- It checks whether:
  - The system is openSUSE-like.
  - The guest GPU vendor is AMD (`1002`).
  - The guest GPU is **not** currently bound to `vfio-pci`.
  - The `kernel-longterm` package is not yet installed.
- If all of those are true, it prints a detailed explanation and offers to run:
  - `zypper --non-interactive in kernel-longterm`
- If the guest GPU is currently on `amdgpu`, the default answer is **YES**, and the prompt explains why installing the long-term kernel is recommended.
- If the GPU is on some other driver (or unbound), the default is **NO**, and the script simply points out the command to use later if you run into binding problems.

Importantly:

- The script **does not remove** your existing kernel by default.
- After installation, you can choose either the default kernel or the long-term kernel from your boot menu.
- All other VFIO logic (IOMMU params, initramfs updates, binding service) works the same; the long-term kernel is just another, often more stable, option.

### Advanced (openSUSE only): removing the default kernel when kernel-longterm is installed

For power users on openSUSE who are confident they only want to run the distribution’s **long-term kernel**, the script offers an **advanced, opt-in** step:

- This prompt only appears if:
  - The system is detected as openSUSE-like, and
  - The `kernel-longterm` package is installed.
- You are shown a **red DANGER warning** (when ANSI colors are enabled) explaining that:
  - Removing the default kernel means you will **no longer have a fallback kernel** if `kernel-longterm` ever fails to boot.
- The prompt is:
  - "Uninstall the default kernel package (e.g. kernel-default) and keep only kernel-longterm?"
  - **Default answer:** `No` (strongly recommended for most users).
- If you explicitly answer **Yes**, the script will:
  - Attempt to remove the common default kernel packages via:
    - `zypper --non-interactive rm kernel-default kernel-default-base kernel-default-extra`
  - Then refresh Boot Loader Spec entries using `sdbootutil add-all-kernels` and `sdbootutil update-all-entries` so that boot entries match the new kernel set.

If any of the packages are not installed, `zypper` simply ignores them. If the removal fails, the script prints a note and leaves package management up to you.

---

## Interactive wizard (default mode)

The default mode (`./vfio.sh` with no arguments) walks you through a **stateful wizard**. It always:

1. Assesses existing VFIO‑related state.
2. Guides you through GPU + audio selection.
3. Writes configuration and helper scripts.
4. Optionally edits kernel parameters and initramfs.
5. Emits a rollback script.

Below is a step‑by‑step view corresponding closely to the internal functions.

When run without `--verify`, `--detect`, `--self-test` or `--reset`, the script enters an interactive **four‑step wizard** after the preflight checks.

### Step 0 – Preflight existing config gate

Before the main wizard, the script looks for any **existing VFIO / passthrough state**:

- `CONF_FILE`, `SYSTEMD_UNIT`, `MODULES_LOAD`, `BLACKLIST_FILE` exist.
- GRUB cmdline contains `amd_iommu=on`, `intel_iommu=on`, `iommu=pt`, or `pcie_acs_override=downstream,multifunction`.
- `lspci -nnk` shows any device **currently using `vfio-pci`**.

If anything is detected, it:

1. Prints a detection report.
2. Evaluates `vfio_config_health`:
   - `OK` – configuration looks consistent.
   - `WARN` – some oddities or left‑overs.
   - `BAD` – clearly broken or dangerous combinations (missing config, conflicting BDFs, host audio on VFIO, etc.).
3. Offers to run `--reset` **first**, especially if status is `BAD`.
4. If you choose not to reset, it requires an explicit phrase confirmation when status is `BAD`.

This prevents stacking multiple half‑working VFIO setups on top of each other.

### Step 1 – Select guest and host GPUs

The script discovers all VGA / 3D / Display controllers via `lspci -Dnn` and for each GPU collects:

- BDF (`0000:BB:DD.F`)
- Full textual description
- Vendor/device IDs (`vvvv:dddd`)
- PCI slot (e.g. `0000:06:00`)
- Associated **audio functions in the same slot**, if any

You are presented with a menu that shows for each GPU:

- GPU BDF and slot
- Shortened, readable model name
- Vendor (colorized per vendor if ANSI colors are enabled)
- Audio BDFs detected in the same slot

You then:

1. Pick the **guest GPU** – this is the card that will be bound to `vfio-pci`.
2. Pick the **host GPU** – the card that stays on a normal graphics driver.
   - If only two GPUs are found, the non‑guest card becomes the host GPU automatically.

The script enforces:

- Host GPU and guest GPU **must be different**.
- All chosen BDFs must exist in `/sys/bus/pci/devices`.

### Step 2 – Optional guest HDMI/DP audio passthrough

For the chosen guest GPU, any audio functions in the **same PCI slot** are treated as candidate **HDMI/DP audio devices**.

The wizard also checks whether **Resizable BAR (ReBAR)** appears enabled for the selected guest GPU (via `lspci -vv`):

- This is reported as **informational**, not as an error.
- Some platforms require ReBAR **enabled** for stable passthrough, others work best with it **disabled**.
- The script makes you acknowledge that ReBAR is a hardware/firmware-specific factor you may need to experiment with if you hit black screens or missing OVMF logos.

You are shown which audio PCI functions are tied to the guest GPU and asked:

- Whether to also passthrough those audio functions.

If you say **yes**, their BDFs are added to `GUEST_AUDIO_BDFS_CSV`. If not, the guest will only get the GPU PCI function.

Before proceeding, there are two important safety checks:

1. **GPU in use preflight** – if the guest GPU is currently a DRM card (e.g. powering your desktop) and that device node appears to be opened by a process, the script warns that binding it can crash your desktop and requires you to type a confirmation phrase (`I UNDERSTAND`).
2. **IOMMU group gate** – the script inspects the IOMMU group of the guest GPU and lists all members. If there are devices in the same group **other than** the guest GPU and the selected guest audio devices, you are warned that passthrough may be unsafe unless you passthrough all of them or rely on ACS separation. Again, you must type a confirmation phrase to proceed.

### Step 3 – Select host audio device

This is crucial for keeping your host desktop audio working reliably.

The script discovers all PCI audio devices via `lspci` and displays for each:

- BDF and PCI slot
- Short audio type (HDMI/DP, HD Audio, generic Audio)
- Vendor & device IDs
- Shortened lspci description
- A **[RECOMMENDED for host GPU]** tag if the audio device shares the same slot as the host GPU

You pick the PCI audio device that should be your primary **host audio** device.

Safeguards:

- Host audio BDF must not equal the guest GPU BDF.
- If the host audio is not in the same slot as the host GPU, the script warns you; this is often a sign of misconfiguration and might indicate you chose the wrong audio device.

### Step 4 – Optional PipeWire default sink selection

If `wpctl` is available, the script can store a stable **PipeWire node name** for your host’s default audio sink.

- It tries to detect PipeWire sinks whose PCI tags match the selected host audio BDF.
- It shows these as **recommended** sinks.
- It then shows all other sinks.
- You pick which sink should be the **default audio output** after login.

The chosen sink’s `node.name` is stored in `HOST_AUDIO_NODE_NAME` inside `CONF_FILE`. The optional user‑systemd service uses this to force the default sink on each login.

---

## Applying changes

Internally, the installer is structured as a clear **"plan then apply"** sequence:

1. Discover devices and validate assumptions.
2. Let the user choose host vs guest roles.
3. Confirm the selections and explain consequences.
4. **Only then** touch `/etc`, systemd units, GRUB, or initramfs.

After your guest/host GPU and audio choices are made, the script prints a summary:

- Host GPU BDF
- Guest GPU BDF and vendor
- Host audio PCI BDF (first entry in CSV)
- Guest audio PCI BDFs
- Host default sink node name (if set)

You must explicitly confirm before anything is written.

When you confirm, the following actions are performed:

1. **Sanity checks**
   - Re‑validate that all BDFs still exist.
   - Ensure no guest audio BDF equals the host audio BDF.

3. **Write configuration**
   - `/etc/vfio-gpu-passthrough.conf` is written with:
     - `HOST_GPU_BDF` – PCI BDF of the GPU that will stay on the host.
     - `HOST_AUDIO_BDFS_CSV` – comma‑separated PCI BDFs for host‑side audio (usually one).
     - `HOST_AUDIO_NODE_NAME` – optional PipeWire `node.name` corresponding to the host output sink.
     - `GUEST_GPU_BDF` – PCI BDF of the GPU to passthrough.
     - `GUEST_AUDIO_BDFS_CSV` – comma‑separated PCI BDFs for HDMI/DP audio functions you chose for the guest.
     - `GUEST_GPU_VENDOR_ID` – raw vendor ID (e.g. `1002` for AMD, `10de` for NVIDIA, `8086` for Intel), used for vendor‑specific logic (blacklist suggestions, softdeps, AMD reset hints).

4. **Install VFIO modules‑load and (optionally) Dracut config**
   - `/etc/modules-load.d/vfio.conf` ensures core VFIO modules are requested at early boot:
     - `vfio`
     - `vfio_pci`
     - `vfio_iommu_type1`
     - `vfio_virqfd`
   - If `/etc/dracut.conf.d` exists, the script also writes `/etc/dracut.conf.d/10-vfio.conf`:
     - Adds `force_drivers+=" vfio vfio_pci vfio_iommu_type1 vfio_virqfd "` so Dracut **includes and loads** VFIO early inside the initramfs.
     - This is especially important on Fedora/RHEL/CentOS/SUSE/Arch‑style Dracut setups, where `/etc/modules-load.d` alone is often not enough.

5. **(Optional) Module soft‑dependency for vendor drivers**
   - The script can add an optional **softdep** in `/etc/modprobe.d/vfio-softdep.conf` for the guest GPU vendor:
     - For NVIDIA: `softdep nvidia pre: vfio-pci`
     - For AMD: `softdep amdgpu pre: vfio-pci`
     - For Intel: `softdep i915 pre: vfio-pci`
   - This nudges the kernel to load `vfio-pci` **before** the vendor GPU driver, reducing races where the vendor driver grabs the card before VFIO can.
   - You are prompted before this is done and can skip it if you have a non‑standard driver stack.

3. **Install VFIO modules‑load**
   - `/etc/modules-load.d/vfio.conf` ensures VFIO modules are present early.

6. **Install & enable bind script and systemd unit**
   - `/usr/local/sbin/vfio-bind-selected-gpu.sh` – a focused helper that:
     - Reads `/etc/vfio-gpu-passthrough.conf`.
     - For each configured guest BDF (GPU + optional audio):
       - Unbinds from the current driver (if any).
       - Writes `vfio-pci` into `driver_override`.
       - Binds the device to `vfio-pci`.
     - Ensures host audio devices have `driver_override` cleared so that they stay or return to their regular drivers.
   - `/etc/systemd/system/vfio-bind-selected-gpu.service` – a **oneshot** service that:
     - Runs after `systemd-modules-load.service`.
     - Runs **before** `display-manager.service`, `libvirtd.service`, `virtqemud.service`, and `multi-user.target`.
     - Is `WantedBy=multi-user.target` and left `RemainAfterExit=yes`.

7. **(Optional) GRUB / kernel parameter updates**
   - You are asked whether to enable IOMMU in GRUB.
   - If yes and GRUB is detected:
     - The script finds `GRUB_CMDLINE_LINUX_DEFAULT` or `GRUB_CMDLINE_LINUX` in `/etc/default/grub`.
     - It adds **once**:
       - `intel_iommu=on` or `amd_iommu=on` (based on CPU vendor).
       - `iommu=pt`.
     - It offers to add `pcie_acs_override=downstream,multifunction` (advanced, usually **not** recommended).
     - It regenerates `grub.cfg` using `update-grub` or `grub-mkconfig`.
   - If GRUB is not used, it prints manual instructions for adding the kernel parameters to your bootloader configuration.

8. **(Optional) Driver blacklisting**
   - You are given a vendor‑specific list of candidate modules to blacklist (e.g. `nouveau`, `nvidia*` for NVIDIA; `amdgpu`/`radeon` for AMD; `i915` for Intel).
   - You can pick none or multiple by number; recommended defaults are conservative (e.g. AMD defaults to blacklisting only `radeon`).
   - If you choose some, `/etc/modprobe.d/vfio-optional-blacklist.conf` is written accordingly and you are advised to rebuild the initramfs.

9. **(Optional) Initramfs update**
   - You are asked whether to rebuild initramfs (recommended).
   - If yes, the script tries `update-initramfs`, `mkinitcpio` or `dracut` in that order.

10. **Rollback script**
   - A rollback script `/root/vfio-rollback-<timestamp>.sh` is generated.
   - This script attempts to restore backups or remove managed files and rebuild boot config and initramfs.

11. **(Optional) User audio unit**
   - You are offered to install a per‑user systemd unit that calls `/usr/local/bin/vfio-set-host-audio.sh` after login.
   - This helper uses `HOST_AUDIO_NODE_NAME` (or, as fallback, BDF‑derived PCI tags) to set the default PipeWire sink, or uses PulseAudio `pactl` when available.

12. **Final instructions**
    - Reboot is required for the VFIO bindings and new kernel params to take full effect.
    - After reboot, you should verify with `lspci -nnk` that:
      - Guest GPU and guest audio functions are using `vfio-pci`.
      - Host audio is *not* using `vfio-pci`.
      - Your VM manager can see and passthrough the guest devices.

---

## Verification and troubleshooting

### Verifying configuration: `--verify`

After reboot, you can run:

```bash path=null start=null
sudo ./vfio.sh --verify
```

This will:

- Show which BDFs are configured for guest and host.
- Confirm guest GPU and audio BDFs are bound to `vfio-pci`.
- Confirm host audio BDF is **not** bound to `vfio-pci`.
- Check for presence and state of the bind script and systemd unit.
- Provide hints for IOMMU and GRUB cmdline.

If it prints `RESULT: PASS`, your VFIO binding base is correct; remaining problems will usually live in VM configuration.

### Detecting issues: `--detect`

If something feels off, run:

```bash path=null start=null
sudo ./vfio.sh --detect
```

Use this when you want to audit:

- Whether there are leftover VFIO or blacklist configs from previous experiments.
- How current kernel cmdline and bootloader look.
- Where VFIO shows up in initramfs and modprobe configs.
- What drivers are currently bound to which GPU/audio devices.
- The **Resizable BAR status** of the configured guest GPU (shown as INFO, based on `lspci -vv` output; the script does not force ReBAR on or off and only reports what the kernel advertises).

### Resetting everything: `--reset`

To undo the script’s changes:

```bash path=null start=null
sudo ./vfio.sh --reset
```

You will be asked to type `RESET VFIO` to confirm. After reset and reboot, your system should behave as though VFIO passthrough had never been configured by this script.

---

## Safety model

The script explicitly treats **safety and recoverability** as first‑class features. Several mechanisms work together to keep your host bootable and debuggable:

The script implements several layers of protection:

- **Atomic writes** via `mktemp` + `install` + rename for all managed files.
- **Backups** for every edited file (notably `/etc/default/grub`, modules‑load, modprobe snippets, systemd units).
- **No new GRUB cmdline key** is created; only the existing `GRUB_CMDLINE_LINUX(_DEFAULT)` is ever modified, and only after a successful backup.
- **Token‑wise addition/removal of kernel params**, avoiding accidental substring corruption.
- **IOMMU group inspection** with an explicit "I UNDERSTAND" gate when groups contain extra devices.
- **GPU‑in‑use detection** that checks both:
  - DRM card usage (via `/dev/dri/card*` and optional `lsof`).
  - Boot VGA framebuffer traps (efifb/simplefb/vesafb via `/proc/iomem`).
- **Optional automatic framebuffer fixes** by queuing `video=...:off` parameters for GRUB.
- **Audio‑in‑use inspection** for HDMI audio: maps the guest GPU’s HDMI audio PCI function to ALSA card(s), then uses `fuser` to detect if `/dev/snd/pcmC*D*` is in active use before binding.
- **Driver sanity** – host audio must not be on `vfio-pci`; guest devices must be.
- **Explicit confirmation phrases** for destructive or high‑risk actions (unsafe groups, in‑use devices, resets).
- **`--dry-run` everywhere** – any operational mode (verify/detect/self‑test/reset) can be run without writing.

Nevertheless, GPU passthrough **always carries risk**. Make sure you have:

- A way to get back into your system if graphical boot fails (SSH, text console, backup kernel entry).
- Backups of important data.

---

## Known limitations

Despite all these protections, **VFIO passthrough remains an advanced configuration**. Some limitations are intentional design choices to keep the script focused and safe.

- Requires **at least two GPUs**; single‑GPU passthrough scenarios are explicitly not supported by this helper.
- Assumes a `systemd` environment.
- Automatic bootloader editing is implemented only for GRUB; other bootloaders must be configured manually.
- `wpctl` and a running PipeWire session are needed at runtime for the best audio experience.
-
### Kernel compatibility note (6.13 and newer)
+
+The script is designed to be conservative around **kernel regressions** that affect VFIO binding, especially on AMD GPUs:
+
+- On some systems, kernels in the **6.13+ family** (or other very new default kernels) may still allow `amdgpu` to claim the guest GPU even when all recommended VFIO parameters are present.
+- In contrast, the distribution’s **long-term kernel** (for example `kernel-longterm` on openSUSE) has been observed to bind the same GPU cleanly to `vfio-pci` with identical settings.
+- Because this can change from release to release, the helper does **not** try to guess future kernel behavior; instead, it:
+  - Detects that the guest GPU is not on `vfio-pci`.
+  - Suggests using the long-term kernel as a known‑good baseline.
+
If your distribution updates to a newer kernel (such as 6.13 or later) and VFIO binding breaks again, you may need to:

- Boot the long-term / older kernel that is known to work.
- Re-run `./vfio.sh --detect` to see how the new kernel is binding devices.
- Wait for future script updates tuned for that kernel series once its behavior is better understood.

The intent is to keep the script tracking real-world kernel behavior over time, rather than pretending all new kernels will always behave the same.

On openSUSE with Btrfs snapshots, remember that **each snapshot has its own `/etc/kernel/cmdline`**:

- When you run `./vfio.sh --reset`, only the **currently booted** snapshot’s kernel parameters are cleaned.
- If you later roll back to an older snapshot, that snapshot may still contain older VFIO/IOMMU parameters.
- After a rollback, you should run:

```bash path=null start=null
sudo ./vfio.sh --reset
```

inside the rolled-back snapshot if you also want its kernel parameters cleaned up.
+
+---
+
+## FAQ

### Can I use this with libvirt/virt‑manager?

Yes. This script only prepares the host bindings. In your VM definition, you still need to add PCI devices corresponding to `GUEST_GPU_BDF` and any `GUEST_AUDIO_BDFS_CSV` entries.

### What if I already have a custom VFIO setup?

Run the script with `--detect` first and read the health report. If it reports `BAD` or if you want to start clean, run `--reset` and reboot before using the wizard.

### Does this script install or manage QEMU/libvirt?

No. It only configures VFIO, GRUB/kernel parameters, systemd unit(s), and (optionally) audio defaults.

### How do I quickly check which driver my GPU is using?

```bash path=null start=null
lspci -nnk -s 0000:01:00.0
```

Check the `Kernel driver in use:` line. If it says `vfio-pci`, the device is owned by VFIO.

---

## Contributing / customizing

The script is written as a single Bash file with clear separation into sections:

- Helpers (logging, prompts, atomic writes, parsing)
- Discovery (GPU/audio / PipeWire sinks)
- Configuration file writers
- GRUB/kernel param helpers
- VFIO bind script & systemd installers
- Audio helpers
- Reset / health / detection logic
- The main interactive wizard

If you adapt it for your environment, consider keeping the same safety properties:

- Always bind by **BDF**, not by plain IDs.
- Always keep a clear separation between **host** and **guest** device sets.
- Always provide a **rollback path**.

---

## License

(Choose and state a license here if you publish this repository publicly.)
