#!/usr/bin/env bash
# Remove the PXAT PT2887-CI libfprint TOD driver.
# Must be run as root:  sudo ./uninstall.sh
#
# IMPORTANT: this does NOT delete fingerprints stored inside the chip, and it
# does NOT touch /var/lib/fprint. Those host-side records simply become
# unusable while the driver is absent; re-installing makes them work again.
set -euo pipefail

DRV="libpxat_pt2887ci.so"
UDEV_RULE="60-pxat-pt2887ci.rules"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run with sudo." >&2
  exit 1
fi

TOD_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1 2>/dev/null || true)"
[ -n "$TOD_DIR" ] || TOD_DIR="/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1"

if [ -f "$TOD_DIR/$DRV" ]; then
  rm -f "$TOD_DIR/$DRV"
  echo "Removed $TOD_DIR/$DRV"
else
  echo "Driver not installed at $TOD_DIR (nothing to do)."
fi

if [ -f "/etc/udev/rules.d/$UDEV_RULE" ]; then
  rm -f "/etc/udev/rules.d/$UDEV_RULE"
  udevadm control --reload-rules || true
  echo "Removed udev rule."
fi

systemctl try-restart fprintd.service >/dev/null 2>&1 || pkill -x fprintd >/dev/null 2>&1 || true
echo "Done. Any .bak.* driver files in $TOD_DIR were left untouched on purpose."
