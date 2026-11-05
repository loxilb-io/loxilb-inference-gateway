// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <linux/if_link.h>
#include <string.h>
#include <unistd.h>
#include <bpf.h>
#include <libbpf.h>
#include "datapath_detach_linux.h"

static __u32
xdp_id(int ifindex, int mode)
{
    __u32 id = 0;
    return bpf_xdp_query_id(ifindex, mode, &id) ? 0 : id;
}

static int
query_tc_id(const struct bpf_tc_hook *hook, __u32 *id)
{
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .handle = 1,
        .priority = 1,
    };
    int rc = bpf_tc_query(hook, &opts);
    *id = rc ? 0 : opts.prog_id;
    return rc;
}

static __u32
tc_id(const struct bpf_tc_hook *hook)
{
    __u32 id;
    query_tc_id(hook, &id);
    return id;
}

static __u32
named_program(__u32 id, const char *name)
{
    if (!id)
        return 0;
    int fd = bpf_prog_get_fd_by_id(id);
    if (fd < 0)
        return 0;
    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);
    int rc = bpf_obj_get_info_by_fd(fd, &info, &len);
    close(fd);
    return !rc && !strncmp(info.name, name, strlen(name)) ? id : 0;
}

struct llb_link_programs
llb_link_programs(int ifindex, int egress)
{
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    struct llb_link_programs progs = {
        .skb = named_program(xdp_id(ifindex, XDP_FLAGS_SKB_MODE), "xdp_packet_func"),
        .drv = named_program(xdp_id(ifindex, XDP_FLAGS_DRV_MODE), "xdp_packet_func"),
        .ingress = named_program(tc_id(&hook), "tc_packet_func"),
    };
    if (egress) {
        hook.attach_point = BPF_TC_EGRESS;
        progs.egress = named_program(tc_id(&hook), "tc_packet_func");
    }
    return progs;
}

static int
detach_xdp(int ifindex, int mode, __u32 expected, int *detached)
{
    if (!expected)
        return 0;
    __u32 id = 0;
    int rc = bpf_xdp_query_id(ifindex, mode, &id);
    if (rc)
        return rc == -ENODEV ? 0 : rc;
    if (id != expected)
        return 0;
    int fd = bpf_prog_get_fd_by_id(expected);
    if (fd < 0)
        return -errno;

    struct bpf_xdp_attach_opts opts = {
        .sz = sizeof(opts),
        .old_prog_fd = fd,
    };
    rc = bpf_xdp_detach(ifindex, mode, &opts);
    close(fd);
    if (!rc)
        ++*detached;
    return rc;
}

static int
detach_tc(int ifindex, enum bpf_tc_attach_point point, __u32 expected,
          int *detached)
{
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = point,
    };
    if (!expected)
        return 0;
    __u32 id;
    int rc = query_tc_id(&hook, &id);
    /* RTM_GETTFILTER can return EINVAL when the clsact qdisc is absent. */
    if (rc)
        return rc == -ENODEV || rc == -ENOENT || rc == -EINVAL ? 0 : rc;
    if (id != expected)
        return 0;

    /* Leave the clsact hook and every other filter in place. */
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .handle = 1,
        .priority = 1,
    };
    rc = bpf_tc_detach(&hook, &opts);
    if (!rc)
        ++*detached;
    return rc;
}

int
llb_shutdown_detach(int ifindex, struct llb_link_programs progs, int *detached)
{
    int skb = detach_xdp(ifindex, XDP_FLAGS_SKB_MODE, progs.skb, detached);
    int drv = detach_xdp(ifindex, XDP_FLAGS_DRV_MODE, progs.drv, detached);
    int in = detach_tc(ifindex, BPF_TC_INGRESS, progs.ingress, detached);
    int out = detach_tc(ifindex, BPF_TC_EGRESS, progs.egress, detached);
    if (skb)
        return skb;
    if (drv)
        return drv;
    return in ? in : out;
}
