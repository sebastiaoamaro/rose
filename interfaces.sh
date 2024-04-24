#!/bin/bash

# for container in $(docker ps -q); do
#     iflink=`docker exec -it $container bash -c 'cat /sys/class/net/eth0/iflink'`
#     iflink=`echo $iflink|tr -d '\r'`
#     veth=`grep -l $iflink /sys/class/net/veth*/ifindex`
#     veth=`echo $veth|sed -e 's;^.*net/\(.*\)/ifindex$;\1;'`
#     echo $container:$veth
# done

# # Get the list of running containers
# containers=$(docker ps --format '{{.ID}}')

# # Loop through each container
# for container_id in $containers; do
#     # Get container name
#     container_name=$(docker inspect -f '{{.Name}}' $container_id | cut -d'/' -f2)

#     # Get container PID
#     container_pid=$(docker inspect -f '{{.State.Pid}}' $container_id)

#     # Get network device
#     iflink=`docker exec -it $container_id bash -c 'cat /sys/class/net/eth0/iflink'`
#     iflink=`echo $iflink|tr -d '\r'`
#     veth=`grep -l $iflink /sys/class/net/veth*/ifindex`
#     veth=`echo $veth|sed -e 's;^.*net/\(.*\)/ifindex$;\1;'`

#     # Print container name, PID, and network device
#     echo "Container Name: $container_name"
#     echo "PID: $container_pid"
#     echo "Network Device: $veth"
#     echo "------------------------------------"
# done

#!/bin/bash

echo "nodes:"

# Get the list of running containers
containers=$(docker ps --format '{{.ID}}')

# Loop through each container
for container_id in $containers; do
    # Get container name
    container_name=$(docker inspect -f '{{.Name}}' $container_id | cut -d'/' -f2)

    # Get container PID
    container_pid=$(docker inspect -f '{{.State.Pid}}' $container_id)

    # Get container IP address
    container_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $container_id)

    # Get network device
    iflink=`docker exec -it $container_id bash -c 'cat /sys/class/net/eth0/iflink'`
    iflink=`echo $iflink|tr -d '\r'`
    veth=`grep -l $iflink /sys/class/net/veth*/ifindex`
    veth=`echo $veth|sed -e 's;^.*net/\(.*\)/ifindex$;\1;'`

    # Print container info in YAML format
    echo "  $container_name:"
    echo "    pid: $container_pid"
    echo "    ip: $container_ip"
    echo "    veth: $veth"
done