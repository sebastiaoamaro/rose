#!/bin/bash

export TERM=xterm

n=5

# Launch LXD Containers (5 nodes)
for i in $(seq 1 $n); do lxc launch ubuntu:22.04 n${i}; done

echo "Started 5 LXD containers"

# Install Required Packages
for i in $(seq 1 $n); do
	lxc exec n${i} -n -- sh -c "apt-get -qy update && apt-get -qy install curl gnupg2 openssh-server sudo"
	echo "Installed packages on n${i}"
done

echo "Installed required packages"

# Setup SSH Access
for i in $(seq 1 $n); do
	echo "Creating SSH directory for n${i}"
	lxc exec n${i} -n -- sh -c "mkdir -p /root/.ssh && chmod 700 /root/.ssh/"
	echo "Copying SSH keys to n${i}"
	lxc file push ~/.ssh/id_rsa.pub n${i}/root/.ssh/authorized_keys --uid 0 --gid 0 --mode 644
	echo "Setting up SSH access for n${i}"
	lxc exec n${i} -n -- bash -c 'echo -e "root\nroot\n" | passwd root'
	echo "Permitting root login for n${i}"
	lxc exec n${i} -n -- sed -i 's,^#\?PermitRootLogin .*,PermitRootLogin yes,g' /etc/ssh/sshd_config
	echo "Restarting SSHD for n${i}"
	lxc exec n${i} -n -- systemctl restart sshd
done

echo "SSH access setup"

# Add Nodes to Known Hosts
for i in $(seq 1 $n); do ssh-keyscan -t rsa n${i} >>~/.ssh/known_hosts; done

echo "Added nodes to known hosts"

# Clean up ~/node if it exists
if [ -f ~/nodes ]; then
	rm ~/nodes
fi

# Create ~/nodes with has th DB hostnames one per line
# echo -e 'n1\nn2\nn3\nn4\nn5' > ~/nodes
for i in $(seq 1 $n); do echo -e "n${i}" >>~/nodes; done

echo "Created ~/nodes"

./get-lxcs-info.sh info.txt

# Push the configuration file to each container and run redpanda
for i in $(seq 1 $n); do
    lxc exec n${i} -n -- mkdir /etc/redpanda
	lxc file push redpanda.yaml n${i}/etc/redpanda/redpanda.yaml -q
	lxc file push rpk n${i}/ -q
	lxc file push --recursive ../binaries n${i}/opt/ -q
	lxc file push start_redpanda.sh n${i}/start_redpanda.sh -q
	lxc file push rpk_setup.sh n${i}/rpk_setup.sh -q
	echo "Files to n${i}"
#    lxc exec n${i} -n -- bash -c 'rm -rf /var/lib/redpanda/data/*'
done

# lein run test --nodes-file ~/nodes --username root
