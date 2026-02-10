#!/bin/bash
cd /vagrant/rw/Anduril/
./install.sh
cd /vagrant/auxiliary_scripts/
./change_java 8
./build_anduril_systems.sh
