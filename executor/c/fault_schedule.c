#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include "fault_schedule.h"

int get_node_count()   { return 0; }
int get_fault_count()  { return 0; }
int get_maximum_time() { return 0; }

tracer *build_tracer()
{
    return calloc(1, sizeof(tracer));
}

execution_plan *build_execution_plan()
{
    return calloc(1, sizeof(execution_plan));
}

node *build_nodes()
{
    return calloc(1, sizeof(node));
}

fault *build_faults_extra()
{
    return calloc(1, sizeof(fault));
}
