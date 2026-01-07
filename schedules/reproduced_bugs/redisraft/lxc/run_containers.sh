#!/bin/bash

export TERM=xterm

n=5
version=$1
# Launch LXD Containers (5 nodes)
for i in $(seq 1 $n); do lxc launch ubuntu:18.04 n${i}; done

echo "Started 5 LXD containers"

# Install Required Packages
for i in $(seq 1 $n); do
	lxc exec n${i} -n -- sh -c "apt-get -qy update && apt-get -qy install curl gnupg2 openssh-server sudo && apt-get upgrade -qy"
	echo "Installed packages on n${i}"
	lxc config set n${i} security.privileged true
	lxc config set n${i} security.nesting true
done

echo "Installed required packages"

# Setup SSH Access
for i in $(seq 1 $n); do
	echo "Creating SSH directory for n${i}"
	lxc exec n${i} -n -- sh -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh/"
	echo "Copying SSH keys to n${i}"
	lxc file push /home/vagrant/.ssh/id_rsa.pub n${i}/root/.ssh/authorized_keys --uid 0 --gid 0 --mode 644
	echo "Setting up SSH access for n${i}"
	lxc exec n${i} -n -- bash -c 'echo -e "root\nroot\n" | passwd root'
	echo "Permitting root login for n${i}"
	lxc exec n${i} -n -- sed -i 's,^#\?PermitRootLogin .*,PermitRootLogin yes,g' /etc/ssh/sshd_config
	echo "Restarting SSHD for n${i}"
	lxc exec n${i} -n -- systemctl restart sshd
done

for i in $(seq 1 $n); do
    lxc exec n${i} -n -- mkdir /opt/redis/
	lxc file push /vagrant/schedules/reproduced_bugs/redisraft/setup/redis_binaries/redis-cli18.04 n${i}/opt/redis/redis-cli -q
	lxc file push /vagrant/schedules/reproduced_bugs/redisraft/setup/redis_binaries/redis-server18.04 n${i}/opt/redis/redis-server -q
	lxc file push /vagrant/schedules/reproduced_bugs/redisraft/setup/redisraft_binaries/18.04redisraft$version.so n${i}/opt/redis/redisraft.so -q
	lxc file push /vagrant/schedules/reproduced_bugs/redisraft/lxc/start_redis_node.sh n${i}/opt/redis/start_redis_node.sh -q
	lxc exec n${i} -n -- chmod "+x" /opt/redis/start_redis_node.sh
	echo "Files to n${i}"
done

echo "SSH access setup"

# Add Nodes to Known Hosts
rm /home/vagrant/.ssh/known_hosts
rm /root/.ssh/known_hosts
for i in $(seq 1 $n); do ssh-keyscan -t rsa n${i}.lxd >>/home/vagrant/.ssh/known_hosts; done
for i in $(seq 1 $n); do ssh-keyscan -t rsa n${i}.lxd >>/root/.ssh/known_hosts; done

echo "Added nodes to known hosts"

# Create ~/nodes with has th DB hostnames one per line
# echo -e 'n1\nn2\nn3\nn4\nn5' > ~/nodes
rm /home/vagrant/nodes
for i in $(seq 1 $n); do echo -e "n${i}.lxd" >>/home/vagrant/nodes; done

rm /home/vagrant/.ssh/config
touch /home/vagrant/.ssh/config
for i in $(seq 1 $n); do echo -e "Host n${i}.lxd\n  user root\n ForwardAgent no\n    IdentityFile /home/vagrant/.ssh/id_rsa" >>/home/vagrant/.ssh/config; done

rm /root/.ssh/config
touch /root/.ssh/config
for i in $(seq 1 $n); do echo -e "Host n${i}.lxd\n  user root\n ForwardAgent no\n    IdentityFile /home/vagrant/.ssh/id_rsa" >>/root/.ssh/config; done

lxc config device set n1 eth0 ipv4.address 10.245.147.145
lxc config device set n2 eth0 ipv4.address 10.245.147.242
lxc config device set n3 eth0 ipv4.address 10.245.147.92
lxc config device set n4 eth0 ipv4.address 10.245.147.132
lxc config device set n5 eth0 ipv4.address 10.245.147.74

./restart_containers.sh

#./get-lxcs-info.sh info.txt

# Push the configuration file to each container and run redpanda
