#!/bin/bash
sudo install ubuntu-mainline-kernel.sh /usr/local/bin/
sudo env DEBIAN_FRONTEND=noninteractive \
  NEEDRESTART_MODE=a \
  ubuntu-mainline-kernel.sh -i 6.11.0
