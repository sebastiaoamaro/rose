#ifndef __USDTJAVA_H
#define __USDTJAVA_H

struct javagc_bpf* usdtjava(int pid,int faultcount,int timemode);

struct data_t {
    __u32 cpu;
    __u32 pid;
    __u64 ts;
};


#endif /* ____USDTJAVA_H_H */