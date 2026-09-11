# Minimal sockmap reproducer

Tool for deciding whether the segment duplication on the accelerated path comes from
**loxilb or from the kernel**. It uses no loxilb code at all.

Only the sockmap part of loxilb's datapath is kept:
- `sk_skb/stream_parser` returns `skb->len` as-is (same as loxilb's `llb_sock_parser`)
- `sk_skb/stream_verdict` looks its own 4-tuple up in a sockhash and hands the skb to
  the peer socket with `bpf_sk_redirect_hash(skb, &sockh, &key, 0)`
- userspace only accepts, connects, and inserts the two sockets into the sockhash
  under each other's key. **It never relays bytes** - the kernel does all of it.

Userspace does read the first request and forward it, because bytes that reached the
receive queue before registration cannot be picked up by the psock. loxilb handles
its first request the same way.

## Usage

```bash
make

# with the testbed up (config.sh) and loxilb stopped:
sudo docker exec llb1 pkill -x loxilb
( cd minrepro && sudo ip netns exec llb1 ./minsockmap 2150 31.31.31.1 9150 ) &

# backend and load come from the harness one directory up
sudo ip netns exec l3ep1 node ../sse_server.js s1 9150 4000 0 &
sudo ip netns exec l3h1  node ../sse_raw_probe.js 10.10.10.254 2150 32 60000 2000 2 400
```

## Results (kernel 6.11.0-29-generic, 2026-08-20)

| concurrency | streams | anomalous |
|---|---|---|
| 1 | 60 | 1 (1.7 %) |
| 4 | 60 | 15 (25 %) |
| 32 | 60 | 54 (90 %) |

Over 400 streams: 350 anomalous (332 backward rewinds, 8 losses), delta min=-58
p50=-26 max=+1.

**It reproduces without loxilb.** The defect is in the kernel's sockmap send path -
specifically `sk_psock_backlog()` resuming a partial send from offset 0 instead of
from the already-sent offset. Fixed upstream by commit `3b4f14b7`
("bpf, sockmap: fix duplicated data transmission"), present in 6.12.34+, 6.15.y and
6.16+, absent from the 6.11 series.
