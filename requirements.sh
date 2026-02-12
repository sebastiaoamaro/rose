#!/bin/bash
set -euo pipefail

SUITABLE=0

need() {
  SUITABLE=1
  echo "Missing minimum required $1 ($2)"
}

# --- CPU check (>= 16) ---
CPU_COUNT="$(nproc)"
if [[ "$CPU_COUNT" -lt 16 ]]; then
  need "number of CPUs" "16"
fi

# --- RAM check (>= 32 GiB) ---
MEM_TOTAL_KIB="$(awk '/MemTotal/ {print $2}' /proc/meminfo)" # KiB
MEM_REQ_KIB=$((32 * 1024 * 1024))                           # 32 GiB in KiB
if [[ "$MEM_TOTAL_KIB" -lt "$MEM_REQ_KIB" ]]; then
  need "RAM" "32G"
fi

# --- Storage check (>= 100 GiB free in current filesystem) ---
STORAGE_AVAIL_KIB="$(df -Pk . | tail -1 | awk '{print $4}')" # KiB available
STORAGE_REQ_KIB=$((100 * 1024 * 1024))                       # 100 GiB in KiB
if [[ "$STORAGE_AVAIL_KIB" -lt "$STORAGE_REQ_KIB" ]]; then
  need "storage space" "180G"
fi

if [[ "$SUITABLE" -eq 1 ]]; then
  echo "Your machine is not suitable for this evaluation."
  exit 1
fi

# --- Ensure python3 is installed ---
if ! command -v python3 >/dev/null 2>&1; then
  echo "Installing python3 (requires sudo)"
  sudo apt update
  sudo apt install -y python3
fi

# --- Install Vagrant (HashiCorp apt repo) ---
if ! command -v vagrant >/dev/null 2>&1; then
  echo "Installing Vagrant (requires sudo)"
  sudo apt update
  sudo apt install -y wget gpg lsb-release ca-certificates

  wget -O - https://apt.releases.hashicorp.com/gpg \
    | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
    | sudo tee /etc/apt/sources.list.d/hashicorp.list >/dev/null

  sudo apt update
  sudo apt install -y vagrant
fi

# --- Install VirtualBox ---
if ! command -v VBoxManage >/dev/null 2>&1; then
  echo "Installing VirtualBox (requires sudo)"
  sudo apt update
  sudo apt install -y virtualbox
fi

echo "All requirements satisfied."
