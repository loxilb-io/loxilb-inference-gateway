// minsockmap.bpf.c - the smallest BPF program that reproduces sockmap redirect on
// its own, with no loxilb involved.
//
// The defect is that the accelerated path sends one TCP segment twice, and byte
// accounting already placed the copy *below* bpf_sk_redirect_hash. One question is
// left: does the kernel's sockmap send path do this for anyone, or does loxilb's
// particular usage provoke it?
//
// So everything is stripped except the semantics of loxilb's datapath: the parser
// returns skb->len as-is, and the verdict looks its own 4-tuple up in a sockhash to
// redirect to the peer socket.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET_ 2

/* Same layout and encoding as loxilb's llb_sockmap_key: the net-order port lives in
 * the upper 16 bits. */
struct key4 {
  __be32 dip;
  __be32 sip;
  __be32 dport;
  __be32 sport;
};

struct {
  __uint(type,        BPF_MAP_TYPE_SOCKHASH);
  __uint(max_entries, 16384);
  __type(key,         struct key4);
  __type(value,       int);
} sockh SEC(".maps");

/* Same as loxilb's llb_sock_parser: one skb is one message. */
SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *skb)
{
  return skb->len;
}

/* Same key computation and redirect as loxilb's non-HAVE_SOCKOPS verdict. */
SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
  struct key4 k = {
    .dip   = skb->remote_ip4,
    .sip   = skb->local_ip4,
    .dport = skb->remote_port,               /* net-order, upper 16 bits */
    .sport = bpf_htonl(skb->local_port),     /* host-order low 16 -> net-order high 16 */
  };

  if (skb->family != AF_INET_) {
    return SK_PASS;
  }
  return bpf_sk_redirect_hash(skb, &sockh, &k, 0);
}

char _license[] SEC("license") = "GPL";
