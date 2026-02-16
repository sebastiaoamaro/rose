#!/bin/bash
set -xe
mkdir -p ~/shared/
./scripts/setup_anduril_vm.sh
./scripts/setup_docker_vm.sh
./scripts/setup_lxc_vm.sh
