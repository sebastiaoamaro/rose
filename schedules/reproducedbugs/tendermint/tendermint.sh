#!/usr/bin/env bash
/vagrant/schedules/reproducedbugs/tendermint/setup/tendermint init
exec -a "$0" /vagrant/schedules/reproducedbugs/tendermint/setup/tendermint node --proxy_app=kvstore > /tmp/output.log 2>&1
