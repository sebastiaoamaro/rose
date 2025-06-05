#!/usr/bin/env bash
/vagrant/schedules/reproduced_bugs/tendermint/setup/tendermint init
exec -a "$0" /vagrant/schedules/reproduced_bugs/tendermint/setup/tendermint node --proxy_app=kvstore > /tmp/output.log 2>&1
