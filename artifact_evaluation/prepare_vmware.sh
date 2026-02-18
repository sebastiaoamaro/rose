#!/bin/bash
vagrant plugin install vagrant-vmware-desktop
wget "https://releases.hashicorp.com/vagrant-vmware-utility/1.0.24/vagrant-vmware-utility_1.0.24-1_amd64.deb"
sudo apt update
sudo apt install -y libaio1t64
sudo apt -y install ./vagrant-vmware-utility_*.deb
sudo systemctl enable --now vagrant-vmware-utility
sudo systemctl status vagrant-vmware-utility --no-pager
