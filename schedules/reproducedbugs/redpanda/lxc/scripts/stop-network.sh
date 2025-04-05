#!/bin/bash

# Stop and disable the systemd service
systemctl stop lxd-dns-lxdbr0
systemctl disable lxd-dns-lxdbr0

# cleanup everything regarding lxd-dns-lxdbr0.service
rm -f /etc/systemd/system/lxd-dns-lxdbr0.service
systemctl daemon-reload

# remove all network related to lxd
lxc profile device remove default eth0
lxc network delete lxdbr0
