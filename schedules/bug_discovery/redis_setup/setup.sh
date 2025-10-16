# run this for loop to create each redis container configuration file
for port in $(seq 1 $1); do

portnumber=$(($port+10))

#echo $portnumber

  mkdir -p /redis/node-${port}/conf
  touch /redis/node-${port}/conf/redis.conf
  cat << EOF >/redis/node-${port}/conf/redis.conf
port 6379
bind 0.0.0.0
protected-mode no
cluster-enabled yes
cluster-config-file nodes.conf
cluster-node-timeout 50000000
cluster-announce-ip 172.38.0.${portnumber}
cluster-announce-port 6379
cluster-announce-bus-port 16379
loglevel notice
appendonly yes
appendfsync always
save 1 1
EOF
done
