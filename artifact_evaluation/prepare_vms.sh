#!/bin/bash
mkdir ~/shared/
cd scripts/ && ./setup_anduril_vm.sh
cd artifact_evaluation/scripts/ && ./setup_docker_vm.sh
cd artifact_evaluation/scripts/ && ./setup_lxc_vm.sh
