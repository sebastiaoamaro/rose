#!/bin/bash
cd /vagrant/auxiliary_scripts/ && ./change_java.sh 8
./build_anduril_systems.sh
cd /vagrant/auxiliary_scripts/ && ./change_java.sh 8
