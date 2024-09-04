#!/bin/bash
#Disables Hyper Threading
echo off | sudo tee /sys/devices/system/cpu/smt/control

#Disable Turbo Boost
echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo