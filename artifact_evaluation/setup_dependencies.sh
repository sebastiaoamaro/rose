#!/bin/bash
cd /vagrant/auxiliary_scripts/
sudo ./install.sh
cd /vagrant/artifact_evaluation/tracing_overhead/throughput/
./install_deps.sh
cd /vagrant/
pip3 install -e . --break-system-packages
