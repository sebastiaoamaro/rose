#!/bin/bash
set -euo pipefail
set -x

PART="/dev/sda3"
LV="/dev/ubuntu-vg/ubuntu-lv"

# Basic checks
if [[ ! -b "$PART" ]]; then
  echo "Error: partition block device not found: $PART" >&2
  exit 1
fi

if [[ ! -e "$LV" ]]; then
  echo "Error: logical volume not found: $LV" >&2
  echo "Hint: run 'sudo lvs' to find the correct LV path." >&2
  exit 1
fi

echo "Before:"
sudo pvs || true
sudo vgs || true
sudo lvs || true
df -h / || true

echo "Resizing LVM PV on ${PART}..."
sudo pvresize "$PART"

echo "Extending LV ${LV} to use all free space in the VG..."
sudo lvextend -l +100%FREE "$LV"

echo "Resizing filesystem on ${LV}..."
sudo resize2fs "$LV"

echo "After:"
sudo pvs || true
sudo vgs || true
sudo lvs || true
df -h / || true

echo "Done."
