#!/bin/bash
logs=$(timeout 1 sudo bpftool prog tracelog)
echo "$logs" > /tmp/bpf_logs.txt
