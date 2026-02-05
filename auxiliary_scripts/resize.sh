#!/bin/bash
set -euo pipefail

DISK="/dev/sda"
PART_NUM="3"
PART="${DISK}${PART_NUM}"

# Ensure tools exist
command -v growpart >/dev/null 2>&1 || {
  echo "Missing 'growpart' (package usually: cloud-guest-utils). Install it first."
  exit 1
}

echo "Growing partition ${PART} on ${DISK}..."
sudo growpart "${DISK}" "${PART_NUM}"

echo "Refreshing kernel partition table..."
sudo partprobe "${DISK}" || true
sudo udevadm settle || true

echo "Resizing PV, LV, and filesystem..."
sudo pvresize "${PART}"
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv

echo "Done."
