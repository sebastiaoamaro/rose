#!/bin/bash
./rpksetup.sh
a=3
pid=0
if [ "$#" -eq "$a" ];
    then
        sleep 1
        echo "STARTED WITH SEED"
        exec -a "$0" /opt/redpanda/bin/rpk redpanda start --node-id $3 --seeds $2:33145 --kafka-addr internal://0.0.0.0:9092 --advertise-kafka-addr internal://$1:9092 --rpc-addr 0.0.0.0:33145 --advertise-rpc-addr $1:33145
        pid=$!
else
    exec -a "$0" /opt/redpanda/bin/rpk redpanda start --node-id $2 --kafka-addr internal://0.0.0.0:9092 --advertise-kafka-addr internal://$1:9092 --rpc-addr 0.0.0.0:33145 --advertise-rpc-addr $1:33145
    pid=$!
fi

wait $pid

#!/bin/bash
# ./rpksetup.sh
# a=3
# if [ "$#" -eq "$a" ];
#     then
#         echo "STARTED WITH SEED"
#         exec -a "$0" /opt/redpanda/bin/rpk redpanda start --node-id $3 --seeds $2:33145 --kafka-addr internal://0.0.0.0:9092 --advertise-kafka-addr internal://$1:9092 --rpc-addr 0.0.0.0:33145 --advertise-rpc-addr $1:33145
# else
#     exec -a "$0" /opt/redpanda/bin/rpk redpanda start --node-id $2 --kafka-addr internal://0.0.0.0:9092 --advertise-kafka-addr internal://$1:9092 --rpc-addr 0.0.0.0:33145 --advertise-rpc-addr $1:33145
# fi
