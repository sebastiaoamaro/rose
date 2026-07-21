#!/bin/bash

usage() {
    cat <<EOF
Usage: $(basename "$0") <machine_name> <vagrant_vm_name> <file_name> <destination>

Copy a file from a remote machine's shared Vagrant folder via rsync.

Arguments:
  machine_name      Remote host (ssh'd into as sebasamaro@<machine_name>)
  vagrant_vm_name   Name of the Vagrant VM whose shared folder to read from
  file_name         File to fetch, relative to ~/shared/<vagrant_vm_name>/
  destination       Local destination path passed to rsync

Options:
  -h, --help        Show this help message and exit

Example:
  $(basename "$0") build-host test1 results.txt ./results.txt
EOF
}

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 0
fi

if [ "$#" -ne 4 ]; then
    usage
    exit 1
fi

machine_name=$1
vagrant_vm_name=$2
file_name=$3
destination=$4
rsync -avz --progress sebasamaro@$machine_name:./shared/$vagrant_vm_name/$file_name $destination
