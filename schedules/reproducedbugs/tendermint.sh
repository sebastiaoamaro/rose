#!/bin/bash
rm strace.txt
exec  -a "$0" /home/sebastiaoamaro/phd/tendermint/build/tendermint node --proxy_app=kvstore
#strace --pid "$0"