#!/bin/bash

# Build the network
echo 1048576 > /proc/sys/fs/aio-max-nr
echo "Building the network"

echo "Configuring the network"
# Get the IPv4 address of lxdbr0
address=$(lxc network get lxdbr0 ipv4.address | cut -d'/' -f1)

# Create the systemd service file with the captured address
cat <<EOF > /etc/systemd/system/lxd-dns-lxdbr0.service
[Unit]
Description=LXD per-link DNS configuration for lxdbr0
BindsTo=sys-subsystem-net-devices-lxdbr0.device
After=sys-subsystem-net-devices-lxdbr0.device

[Service]
Type=oneshot
ExecStart=/usr/bin/resolvectl dns lxdbr0 $address
ExecStart=/usr/bin/resolvectl domain lxdbr0 ~lxd
ExecStopPost=/usr/bin/resolvectl revert lxdbr0
RemainAfterExit=yes

[Install]
WantedBy=sys-subsystem-net-devices-lxdbr0.device
EOF

# Reload systemd to recognize the new service
systemctl daemon-reload

# Enable and start the new service
systemctl enable --now lxd-dns-lxdbr0
systemctl --no-pager status lxd-dns-lxdbr0
resolvectl status lxdbr0


##REBOOT THE MACHINE AFTER THIS
