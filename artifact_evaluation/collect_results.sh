#!/usr/bin/env bash
set -euo pipefail

# Collect files from /shared inside each VM (test1..test3) to ~/shared/<machine>/ on the host.
#
# Default behavior:
#   - Copies (rsync) from VM -> host without deletions on host
#
# Requirements:
#   - run from the directory that contains the Vagrant environment (same dir as Vagrantfile)
#   - VMs must be running and SSH-reachable via `vagrant ssh`
#
# Usage:
#   ./collect_results.sh              # collect from test1..test3
#   ./collect_results.sh test2        # collect only test2
#
# Notes:
#   - Uses `vagrant ssh-config` to discover host/port/key.
#   - Uses rsync with --ignore-existing to avoid overwriting host files.
#   - Does not use --delete (so nothing is deleted on host side).

machines=("$@")
if [[ ${#machines[@]} -eq 0 ]]; then
  machines=("test1" "test2" "test3")
fi

host_base_dir="${HOME}/shared"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }
}

require_cmd vagrant
require_cmd rsync
require_cmd awk
require_cmd mkdir

vagrant_ssh_value() {
  local machine="$1"
  local key="$2"
  # Prints value for a key from `vagrant ssh-config`, e.g., "HostName", "Port", "User", "IdentityFile"
  vagrant ssh-config "$machine" 2>/dev/null | awk -v k="$key" '$1 == k {print $2; exit}'
}

collect_one() {
  local machine="$1"

  local host port user identity_file
  host="$(vagrant_ssh_value "$machine" "HostName" || true)"
  port="$(vagrant_ssh_value "$machine" "Port" || true)"
  user="$(vagrant_ssh_value "$machine" "User" || true)"
  identity_file="$(vagrant_ssh_value "$machine" "IdentityFile" || true)"

  if [[ -z "${host}" || -z "${port}" || -z "${user}" || -z "${identity_file}" ]]; then
    echo "[${machine}] Skipping (machine not created/up or ssh-config unavailable)" >&2
    return 0
  fi

  local dest_dir="${host_base_dir}/${machine}"
  mkdir -p "${dest_dir}"

  echo "[${machine}] Collecting from ${user}@${host}:${port}:/shared/ -> ${dest_dir}/"

  # Pull from VM to host. No deletions, don’t overwrite existing host files.
  rsync -azv \
    --ignore-existing \
    --partial \
    --chmod=Du+rwx,Dgo+rx,Fu+rw,Fgo+r \
    -e "ssh -p ${port} -i ${identity_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
    "${user}@${host}:/shared/" \
    "${dest_dir}/"

  echo "[${machine}] Done"
}

for m in "${machines[@]}"; do
  collect_one "${m}"
done
