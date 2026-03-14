# Changelog
## Unreleased
- Hardened `is_opensuse_like()` distro detection in `vfio.sh` by parsing `/etc/os-release` key/value pairs directly.
- openSUSE-specific code paths now trigger only when `ID` starts with `opensuse` or an `ID_LIKE` token starts with `opensuse`, reducing accidental matches on non-openSUSE systems.
- Added optional USB/xHCI stability kernel-parameter prompts in `vfio.sh` for:
  - GRUB path (`grub_add_kernel_params`)
  - openSUSE `/etc/kernel/cmdline` persistence path (`systemd_boot_add_kernel_params`)
  - non-openSUSE systemd-boot current entry updates
- New optional parameters:
  - `usbcore.autosuspend=-1`
  - `pcie_aspm=off`
- Added inline wizard explanations about why the workaround is optional (stability benefit vs idle power tradeoff).
- Updated reset cleanup paths to remove the optional parameters from both `/etc/default/grub` and `/etc/kernel/cmdline`.
- Added a new read-only mode `--usb-health-check` in `vfio.sh`:
  - Scans current and previous boot kernel logs for USB/xHCI crash signatures.
  - Grades results as PASS/WARN/FAIL with exit codes 0/1/2.
  - Prints matching log excerpts and recommends optional mitigation parameters (`usbcore.autosuspend=-1 pcie_aspm=off`) when instability markers are detected.
