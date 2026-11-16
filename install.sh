#!/usr/bin/env bash
# Install the PXAT PT2887-CI libfprint TOD driver.
# Must be run as root:  sudo ./install.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DRV="libpxat_pt2887ci.so"
UDEV_RULE="60-pxat-pt2887ci.rules"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run with sudo (the install touches /usr and /etc)." >&2
  exit 1
fi

echo "== PXAT PT2887-CI driver installer =="

# ---- 1. sanity checks -------------------------------------------------------
if ! lsusb -d 2f0a:1055 >/dev/null 2>&1; then
  echo "WARNING: USB 2f0a:1055 not visible right now; continuing anyway." >&2
fi

if ! ldconfig -p | grep -q 'libfprint-2-tod.so.1'; then
  echo "ERROR: Ubuntu's TOD-enabled libfprint is missing." >&2
  echo "       sudo apt install libfprint-2-tod1 fprintd libpam-fprintd" >&2
  exit 1
fi

# Resolve the TOD driver directory from pkg-config when available.
TOD_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1 2>/dev/null || true)"
[ -n "$TOD_DIR" ] || TOD_DIR="/usr/lib/$(uname -m)-linux-gnu/libfprint-2/tod-1"
[ -d "$TOD_DIR" ] || TOD_DIR="/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1"
if [ ! -d "$TOD_DIR" ]; then
  echo "Creating TOD driver directory: $TOD_DIR"
  install -d -m 0755 "$TOD_DIR"
fi
echo "TOD driver dir: $TOD_DIR"

# ---- 2. driver binary -------------------------------------------------------
SRC="$HERE/dist/$DRV"
if [ ! -f "$SRC" ]; then
  echo "Prebuilt driver not found; building from source..."
  (cd "$HERE" && make all)
  SRC="$HERE/dist/$DRV"
fi
if [ ! -f "$SRC" ]; then
  echo "ERROR: cannot produce $DRV" >&2
  exit 1
fi

if [ -e "$TOD_DIR/$DRV" ]; then
  cp -a "$TOD_DIR/$DRV" "$TOD_DIR/$DRV.bak.$(date +%Y%m%d%H%M%S)"
  echo "Backed up the existing driver."
fi
install -m 0644 -o root -g root "$SRC" "$TOD_DIR/$DRV"
echo "Installed: $TOD_DIR/$DRV"

# ---- 3. udev rule -----------------------------------------------------------
install -m 0644 -o root -g root "$HERE/udev/$UDEV_RULE" "/etc/udev/rules.d/$UDEV_RULE"
udevadm control --reload-rules || true
udevadm trigger --subsystem-match=usb --attr-match=idVendor=2f0a || true
echo "Installed udev rule (uaccess for the active session user)."

# ---- 4. make fprintd reload -------------------------------------------------
# fprintd is D-Bus activated; killing it forces a reload of the TOD drivers.
if systemctl try-restart fprintd.service >/dev/null 2>&1; then
  echo "Restarted fprintd."
else
  pkill -x fprintd >/dev/null 2>&1 || true
  echo "Stopped fprintd (it will be D-Bus activated again on next use)."
fi

# ---- 5. verify --------------------------------------------------------------
echo
echo "== Verify =="
echo "  1) Protocol check (read-only, does not touch stored prints):"
echo "       sudo $HERE/dist/pxat_probe selftest"
echo "  2) Device detection through the driver:"
echo "       fprintd-list \"\$USER\""
echo "       gdbus call --system --dest net.reactived.Fprint --object-path /net/reactived/Fprint/Manager --method net.reactived.Fprint.Manager.GetDevices"
echo "  3) Enroll / verify:"
echo "       fprintd-enroll \"\$USER\""
echo "       fprintd-verify \"\$USER\""
echo
echo "  Logs:  journalctl -u fprintd -f   (or:  sudo LIBFPRINT_DEBUG=1 ... )"
echo
echo "NOTE: enrollment writes templates into the chip's flash. Slot range"
echo "      defaults to 10..19; override with PXAT_SLOT_MIN / PXAT_SLOT_MAX"
echo "      in fprintd's environment if your module differs."
echo "NOTE: keep your password available; fingerprint is a convenience method."
