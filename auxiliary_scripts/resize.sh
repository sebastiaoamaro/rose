#!/bin/bash
set -euo pipefail
set -x

PART="/dev/sda3"
DISK="/dev/sda"
PARTNUM="3"
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

for cmd in sgdisk growpart; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: required command not found: $cmd" >&2
    exit 1
  fi
done

echo "Before:"
sudo pvs || true
sudo vgs || true
sudo lvs || true
df -h / || true

# Growing the underlying virtual disk (e.g. vagrant-disksize) only resizes the disk
# image itself - it doesn't touch the guest's GPT table or partition sizes, so without
# these two steps pvresize below finds no extra space to work with and the whole
# chain silently caps out at whatever the partition's original size was.
echo "Repairing GPT table on ${DISK} to use the full (possibly grown) disk..."
sudo sgdisk -e "$DISK"

echo "Growing partition ${PARTNUM} on ${DISK} into any free space..."
sudo growpart "$DISK" "$PARTNUM"

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
