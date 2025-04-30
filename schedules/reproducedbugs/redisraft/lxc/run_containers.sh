#!/bin/bash

export TERM=xterm

n=5

# Launch LXD Containers (5 nodes)
for i in $(seq 1 $n); do lxc launch ubuntu:22.04 n${i}; done

echo "Started 5 LXD containers"

# Install Required Packages
for i in $(seq 1 $n); do
	lxc exec n${i} -n -- sh -c "apt-get -qy update && apt-get -qy install curl gnupg2 openssh-server sudo && apt-get upgrade -qy"
	echo "Installed packages on n${i}"
done

echo "Installed required packages"

# Setup SSH Access
for i in $(seq 1 $n); do
	echo "Creating SSH directory for n${i}"
	lxc exec n${i} -n -- sh -c "mkdir -p /root/.ssh && chmod 700 /root/.ssh/"
	echo "Copying SSH keys to n${i}"
	lxc file push /root/.ssh/id_rsa.pub n${i}/root/.ssh/authorized_keys --uid 0 --gid 0 --mode 644
	echo "Setting up SSH access for n${i}"
	lxc exec n${i} -n -- bash -c 'echo -e "root\nroot\n" | passwd root'
	echo "Permitting root login for n${i}"
	lxc exec n${i} -n -- sed -i 's,^#\?PermitRootLogin .*,PermitRootLogin yes,g' /etc/ssh/sshd_config
	echo "Restarting SSHD for n${i}"
	lxc exec n${i} -n -- systemctl restart sshd
done

echo "SSH access setup"

# Add Nodes to Known Hosts
rm /root/.ssh/known_hosts
for i in $(seq 1 $n); do ssh-keyscan -t rsa n${i}.lxd >>/root/.ssh/known_hosts; done

echo "Added nodes to known hosts"

# Create ~/nodes with has th DB hostnames one per line
# echo -e 'n1\nn2\nn3\nn4\nn5' > ~/nodes
rm /root/nodes
for i in $(seq 1 $n); do echo -e "n${i}.lxd" >>/root/nodes; done

echo "Created /root/nodes"

#./get-lxcs-info.sh info.txt

# Push the configuration file to each container and run redpanda
