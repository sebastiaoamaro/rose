#ifndef __TC_H
#define __TC_H

struct tc_bpf* traffic_control(int index,int positio);
struct bpf_tc_hook* get_tc_hook(int pos);
struct bpf_tc_opts* get_tc_opts(int pos);
void init_tc(int count);
struct pair{
	__be32 src_addr;
	__be32 dst_addr;
};

#endif /* __TC_H */