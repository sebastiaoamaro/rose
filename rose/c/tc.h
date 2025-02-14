#ifndef __TC_H
#define __TC_H

struct bpf_tc_hook* get_tc_hook(int pos);
struct bpf_tc_opts* get_tc_opts(int pos);
void init_tc(int count);
char** get_device_names(int);
int delete_tc_hook(struct tc_bpf **tc_ebpf_progs,int,int);
struct pair{
	__be32 src_addr;
	__be32 dst_addr;
};

#endif /* __TC_H */