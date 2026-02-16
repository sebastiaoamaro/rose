#!/bin/bash
set -xe
mkdir ~/shared/
cd scripts/ && ./setup_anduril_vm.sh
cd scripts/ && ./setup_docker_vm.sh
cd scripts/ && ./setup_lxc_vm.sh
