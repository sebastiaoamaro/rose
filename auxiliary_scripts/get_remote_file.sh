#!/bin/bash
machine_name=$1
vagrant_vm_name=$2
file_name=$3
destination=$4
rsync -avz --progress sebasamaro@$machine_name:./shared/$vagrant_vm_name/$file_name $destination
