#define _GNU_SOURCE
// minsockmap.c - a minimal sockmap TCP relay with no loxilb.
//
//   sudo ip netns exec <ns> ./minsockmap <listen_port> <backend_ip> <backend_port>
//
// It does exactly three things:
//   1) accept a client connection and connect to the backend
//   2) put both sockets into a sockhash under each other's 4-tuple key (the same
//      model as loxilb's non-HAVE_SOCKOPS path)
//   3) from then on the kernel relays every byte - userspace never reads or writes
//
// No HTTP parsing, no buffering, no backend selection. Only the sockmap redirect
// part of loxilb's datapath is left, so reproducing the segment duplication here
// narrows the defect to the kernel path.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <netinet/tcp.h>
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct key4 { __be32 dip, sip, dport, sport; };

static int map_fd = -1;

/* Builds the same key in userspace that the verdict computes. The net-order 16-bit
 * port is shifted into the upper half, matching the verdict's remote_port and
 * htonl(local_port). */
static int mkkey(int fd, struct key4 *k)
{
  struct sockaddr_in loc, rem;
  socklen_t l = sizeof(loc);

  if (getsockname(fd, (struct sockaddr *)&loc, &l) < 0) return -1;
  l = sizeof(rem);
  if (getpeername(fd, (struct sockaddr *)&rem, &l) < 0) return -1;
  k->dip   = rem.sin_addr.s_addr;
  k->sip   = loc.sin_addr.s_addr;
  k->dport = ((__u32)rem.sin_port) << 16;
  k->sport = ((__u32)loc.sin_port) << 16;
  return 0;
}

struct pair { int a, b; struct key4 ka, kb; };

/* Request bytes the client sent before registration are already sitting in the
 * socket receive queue, where the psock cannot pick them up. loxilb has the same
 * shape: userspace reads the first request and forwards it to the backend (peer
 * registration happens at that point), and the kernel relays from the response
 * onward. This mirrors that order.
 * Returns the number of bytes read, or -1 on failure. */
static int read_request(int fd, char *buf, int cap)
{
  int got = 0;
  for (;;) {
    int r = recv(fd, buf + got, cap - got, 0);
    if (r <= 0) return got > 0 ? got : -1;
    got += r;
    buf[got < cap ? got : cap - 1] = 0;
    char *he = memmem(buf, got, "\r\n\r\n", 4);
    if (he) {
      int hlen = (int)(he - buf) + 4;
      int clen = 0;
      char *cl = memmem(buf, hlen, "Content-Length:", 15);
      if (cl) clen = atoi(cl + 15);
      if (got >= hlen + clen) return got;
    }
    if (got >= cap) return got;
  }
}

int main(int argc, char **argv)
{
  if (argc < 4) { fprintf(stderr, "usage: %s <lport> <bip> <bport>\n", argv[0]); return 1; }
  int lport = atoi(argv[1]);
  const char *bip = argv[2];
  int bport = atoi(argv[3]);

  struct rlimit rl = { 1 << 20, 1 << 20 };
  setrlimit(RLIMIT_NOFILE, &rl);
  setrlimit(RLIMIT_MEMLOCK, &rl);

  struct bpf_object *obj = bpf_object__open_file("minsockmap.bpf.o", NULL);
  if (!obj) { fprintf(stderr, "open_file failed\n"); return 1; }
  if (bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); return 1; }

  struct bpf_map *m = bpf_object__find_map_by_name(obj, "sockh");
  struct bpf_program *pp = bpf_object__find_program_by_name(obj, "parser");
  struct bpf_program *pv = bpf_object__find_program_by_name(obj, "verdict");
  if (!m || !pp || !pv) { fprintf(stderr, "missing map/prog\n"); return 1; }
  map_fd = bpf_map__fd(m);

  if (bpf_prog_attach(bpf_program__fd(pp), map_fd, BPF_SK_SKB_STREAM_PARSER, 0)) {
    fprintf(stderr, "attach parser: %s\n", strerror(errno)); return 1;
  }
  if (bpf_prog_attach(bpf_program__fd(pv), map_fd, BPF_SK_SKB_STREAM_VERDICT, 0)) {
    fprintf(stderr, "attach verdict: %s\n", strerror(errno)); return 1;
  }

  int lfd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in la = { .sin_family = AF_INET, .sin_port = htons(lport),
                            .sin_addr.s_addr = INADDR_ANY };
  if (bind(lfd, (struct sockaddr *)&la, sizeof(la)) < 0) { perror("bind"); return 1; }
  listen(lfd, 1024);
  printf("minsockmap: listening :%d -> %s:%d (kernel relay only)\n", lport, bip, bport);
  fflush(stdout);

  int ep = epoll_create1(0);
  struct epoll_event ev = { .events = EPOLLIN, .data.fd = lfd };
  epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev);

  struct sockaddr_in ba = { .sin_family = AF_INET, .sin_port = htons(bport) };
  inet_pton(AF_INET, bip, &ba.sin_addr);

  struct pair **byfd = calloc(1 << 20, sizeof(void *));
  struct epoll_event evs[64];

  for (;;) {
    int n = epoll_wait(ep, evs, 64, -1);
    for (int i = 0; i < n; i++) {
      int fd = evs[i].data.fd;
      if (fd == lfd) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0) continue;
        int b = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(b, (struct sockaddr *)&ba, sizeof(ba)) < 0) { close(c); close(b); continue; }
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(b, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        /* 1) userspace reads the request, so nothing is stranded in the queue */
        char req[16384];
        int rlen = read_request(c, req, sizeof(req));
        if (rlen <= 0) { close(c); close(b); continue; }

        struct pair *p = calloc(1, sizeof(*p));
        p->a = c; p->b = b;
        if (mkkey(c, &p->ka) || mkkey(b, &p->kb)) { close(c); close(b); free(p); continue; }
        /* Insert so that looking up one socket's own tuple yields its peer. */
        if (bpf_map_update_elem(map_fd, &p->ka, &b, BPF_ANY) ||
            bpf_map_update_elem(map_fd, &p->kb, &c, BPF_ANY)) {
          fprintf(stderr, "sockhash update: %s\n", strerror(errno));
          close(c); close(b); free(p); continue;
        }
        /* 2) forward the request only after registration, so the response is
         * relayed by the kernel from its very first byte */
        if (write(b, req, rlen) != rlen) {
          bpf_map_delete_elem(map_fd, &p->ka);
          bpf_map_delete_elem(map_fd, &p->kb);
          close(c); close(b); free(p); continue;
        }
        byfd[c] = p; byfd[b] = p;
        struct epoll_event e2 = { .events = EPOLLRDHUP | EPOLLHUP | EPOLLERR, .data.fd = c };
        epoll_ctl(ep, EPOLL_CTL_ADD, c, &e2);
        e2.data.fd = b;
        epoll_ctl(ep, EPOLL_CTL_ADD, b, &e2);
        continue;
      }
      /* Tear the pair down when either side hangs up. Never touches byte relay. */
      struct pair *p = byfd[fd];
      if (!p) { epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL); close(fd); continue; }
      bpf_map_delete_elem(map_fd, &p->ka);
      bpf_map_delete_elem(map_fd, &p->kb);
      epoll_ctl(ep, EPOLL_CTL_DEL, p->a, NULL);
      epoll_ctl(ep, EPOLL_CTL_DEL, p->b, NULL);
      byfd[p->a] = NULL; byfd[p->b] = NULL;
      close(p->a); close(p->b);
      free(p);
    }
  }
  return 0;
}
