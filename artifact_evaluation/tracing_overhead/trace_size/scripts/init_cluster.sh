#!/bin/bash
sleep 1
redis-cli --cluster create $(cat /vagrant/artifact_evaluation/tracing_overhead/throughput/configs/ips3.txt) --cluster-yes
HOST="172.38.0.11"
PORT="6379"
# 3. Loop until cluster is reported as 'ok'
while true; do
  OUTPUT=$(redis-cli -h "$HOST" -p "$PORT" cluster info 2>/dev/null)

  if echo "$OUTPUT" | grep -q "cluster_state:ok"; then
    echo "✅ Cluster is ready."
    break
  else
    echo "⏳ Cluster not ready yet..."
    sleep 2
  fi
done
