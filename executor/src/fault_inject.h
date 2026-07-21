/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __FAULT_INJECT_H
#define __FAULT_INJECT_H

#define MAX_INT 4294967296

struct fault_inject_bpf* fault_inject(int faults,int mode);

#endif /* __FAULT_INJECT_H */
