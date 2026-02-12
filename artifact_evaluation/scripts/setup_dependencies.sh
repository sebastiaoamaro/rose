#!/bin/bash
mkdir /vagrant/rw/Anduril/
cd /vagrant/auxiliary_scripts/
./install.sh
cd /vagrant/
pip3 install -e . --break-system-packages
