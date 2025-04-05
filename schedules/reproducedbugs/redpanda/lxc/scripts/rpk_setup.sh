#!/bin/bash
# systemctl stop redpanda
# systemctl stop wasm_engine
# systemctl disable redpanda
# systemctl disable wasm_engine

./rpk config set redpanda.default_topic_replications "3"
./rpk config set redpanda.id_allocator_replication "3"
./rpk config set redpanda.enable_idempotence "true"
#./rpk config set redpanda.retries "1000"
#./rpk config set redpanda.auto_offset_reset "earliest"
#./rpk config set redpanda.auto_create_topics_enabled false

#rpk config set redpanda.advertised_kafka_api '[{"address": "redpanda0", "port": 9092, "name":"internal"},{"address": "redpanda0", "port": 9092, "name":"external"}]'
