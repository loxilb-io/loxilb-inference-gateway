// SPDX-License-Identifier: Apache-2.0

#ifndef LLB_DATAPATH_DETACH_LINUX_H
#define LLB_DATAPATH_DETACH_LINUX_H

#include <linux/types.h>

struct llb_link_programs {
    __u32 skb;
    __u32 drv;
    __u32 ingress;
    __u32 egress;
};

struct llb_link_programs llb_link_programs(int ifindex, int egress);
int llb_shutdown_detach(int ifindex, struct llb_link_programs progs, int *detached);

#endif
