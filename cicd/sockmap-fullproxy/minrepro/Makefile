# Minimal program that reproduces sockmap redirect on its own, without loxilb.
#
#   make
#   sudo ip netns exec <ns> ./minsockmap <lport> <backend_ip> <backend_port>
#
# libbpf is linked statically from the copy built in this repo, so the result does
# not depend on whichever version the host distribution ships.
REPO ?= ../../..
LIBBPF_A   ?= $(REPO)/loxilb-ebpf/libbpf/src/libbpf.a
LIBBPF_INC ?= $(REPO)/loxilb-ebpf/libbpf/src/build/usr/include

all: minsockmap.bpf.o minsockmap

minsockmap.bpf.o: minsockmap.bpf.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

minsockmap: minsockmap.c
	gcc -O2 -Wall -I$(LIBBPF_INC) -o $@ $< $(LIBBPF_A) -lelf -lz

clean:
	rm -f minsockmap minsockmap.bpf.o
