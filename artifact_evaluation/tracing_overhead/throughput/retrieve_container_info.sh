#!/bin/bash
rm $1
for container in $(sudo docker ps -q); do
    container_name=$(sudo docker inspect --format='{{.Name}}' $container | sed 's/^\/\(.*\)/\1/')
    iflink=`sudo docker exec -it $container bash -c 'cat /sys/class/net/eth0/iflink'`
    iflink=`echo $iflink|tr -d '\r'`
    veth=`grep -l $iflink /sys/class/net/veth*/ifindex`
    veth=`echo $veth|sed -e 's;^.*net/\(.*\)/ifindex$;\1;'`
    pid=$(sudo docker inspect -f '{{.State.Pid}}' $container)
    echo $container_name,$pid,$veth >> $1
done
