/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __FAULTINJECT_H
#define __FAULTINJECT_H

#define MAX_INT 4294967296

struct event_faultinject {
	int injected;
};

struct faultinject_bpf* fault_inject(int faults,int timemode);

#endif /* __FAULTINJECT_H */
