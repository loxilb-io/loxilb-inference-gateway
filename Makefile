.DEFAULT_GOAL := build
bin=loxilb
DPU_CPUS ?= 8
dock?=loxilb
IMAGE?=ghcr.io/loxilb-io/loxilb-inference-gateway
TAG?=latest
ARM64_TAG?=$(TAG)-arm64
BRANCH_NAME:=$(shell git rev-parse --is-inside-work-tree >/dev/null 2>&1 && git branch --show-current || echo nogit)

loxilbid=$(shell docker ps -f name=$(dock) | grep -w $(dock) | cut  -d " "  -f 1 | grep -iv  "CONTAINER")

# Check if L4 trace is enabled (from environment or make args)
ifdef HAVE_L4_TRACE
GO_BUILD_TAGS := -tags l4trace
else
GO_BUILD_TAGS :=
endif

# Check if PII detection is enabled (from environment or make args)
ifdef HAVE_PII_DETECTION
export HAVE_PII_DETECTION
# Add piidetection build tag
ifdef GO_BUILD_TAGS
GO_BUILD_TAGS := $(GO_BUILD_TAGS),piidetection
else
GO_BUILD_TAGS := -tags piidetection
endif
endif

# Check if DOCA DPU offload is enabled (from environment or make args)
ifdef HAVE_DOCA
export HAVE_DOCA
# Add doca build tag
ifdef GO_BUILD_TAGS
GO_BUILD_TAGS := $(GO_BUILD_TAGS),doca
else
GO_BUILD_TAGS := -tags doca
endif
# Set CGO flags for DOCA/DPDK libraries (resolved by loxilb-ebpf/doca/Makefile)
export CGO_CFLAGS += $(shell cd loxilb-ebpf/doca && $(MAKE) HAVE_DOCA=1 --no-print-directory print-cgo-cflags 2>/dev/null)
export CGO_LDFLAGS += $(shell cd loxilb-ebpf/doca && $(MAKE) HAVE_DOCA=1 --no-print-directory print-cgo-ldflags 2>/dev/null)
endif

# DPU slim build profile - align Go CGO struct layout with eBPF/userspace
ifdef HAVE_DP_DPU_SLIM
export CGO_CFLAGS += -DHAVE_DP_DPU_SLIM=1
endif

# mTLS support - align Go CGO struct layout with eBPF/userspace C headers.
# Stable → compiled in by default. Opt out with `make HAVE_MTLS=` (empty).
# MUST be exported so the loxilb-ebpf sub-make (libloxilbdp.a) enables it too;
# otherwise dp_proxy_tacts is sized WITH mtls fields in the cgo Go binary but
# WITHOUT them in the static lib, and the per-TU _Static_assert cannot catch the
# cross-build mismatch → silent memory corruption for every proxy rule.
HAVE_MTLS ?= 1
export HAVE_MTLS
ifdef HAVE_MTLS
export CGO_CFLAGS += -DHAVE_MTLS=1
ifdef GO_BUILD_TAGS
GO_BUILD_TAGS := $(GO_BUILD_TAGS),mtls
else
GO_BUILD_TAGS := -tags mtls
endif
endif

subsys:
	cd loxilb-ebpf && $(MAKE) 

subsys-clean:
	cd loxilb-ebpf && $(MAKE) clean

# DPU build targets
dpu: subsys-clean
	cd loxilb-ebpf && $(MAKE) dpu HAVE_DP_DPU_SLIM=1 DPU_CPUS=$(DPU_CPUS)

bf2:
	$(MAKE) dpu DPU_CPUS=8
	$(MAKE) build HAVE_DOCA=1 HAVE_DP_DPU_SLIM=1

bf3: subsys-clean
	cd loxilb-ebpf && $(MAKE) dpu-bf3 HAVE_DP_DPU_BF3=1 DPU_CPUS=16

# api-models: ensure the go-swagger-generated api/ code exists before `go build`.
# The REST handlers (api/restapi/handler/cert.go, loadbalancer.go) reference generated
# types (models.Cert, operations.PostConfigCert*, and the mTLS/QoS/ALPN ServiceArguments
# fields) that are NOT committed. Plain `go build` does NOT regenerate them, so a clean
# checkout fails with "undefined: models.Cert". This guard regenerates them once via
# api/build_api.sh (dockerized go-swagger 0.30.3 — the same step the CI runs) from the
# committed api/swagger.yml, and NO-OPS when they are already present (incremental builds
# and CI runners that already generated are unaffected). Requires Docker for the first
# build of a clean checkout. See README.md "Build and run from source".
.PHONY: api-models
api-models:
	@if grep -rqsE 'type Cert struct' api/models/ 2>/dev/null; then \
		: ; \
	else \
		echo ">> api/ swagger models missing -> regenerating via api/build_api.sh (dockerized go-swagger)"; \
		( cd api && bash build_api.sh ) || { echo "ERROR: swagger regen failed (need Docker). See api/build_api.sh."; exit 1; }; \
	fi

build: subsys api-models
	@go build $(GO_BUILD_TAGS) -o ${bin} -ldflags="-X 'github.com/loxilb-io/loxilb/common.BuildInfo=${shell date '+%Y_%m_%d_%Hh:%Mm'}-${shell git branch --show-current}'"
	@if [ -n "$(GO_BUILD_TAGS)" ]; then \
		echo "Built with tags: $(GO_BUILD_TAGS)"; \
	fi
	
clean: subsys-clean
	go clean

test:
	go test .

test_sse:
	$(MAKE) -C loxilb-ebpf/common test_sse

test_request_id:
	$(MAKE) -C loxilb-ebpf/common test_rid

test_pd:
	$(MAKE) -C loxilb-ebpf/common test_pd

test_pd_cache_aware:
	$(MAKE) -C loxilb-ebpf/common test_pd_cache

test_kv_unit:
	$(MAKE) -C loxilb-ebpf/doca/kv test_kv_unit

kv-agent:
	$(MAKE) -C loxilb-ebpf/doca/kv HAVE_DOCA=$(HAVE_DOCA)
	CGO_ENABLED=1 go build $(GO_BUILD_TAGS) -o loxilb-kv-agent ./cmd/loxilb-kv-agent/

# Standalone global AI controller: PURE Go, no sub-make, no build tags, no cgo.
ai-controller:
	CGO_ENABLED=0 go build -o loxilb-ai-controller ./cmd/loxilb-ai-controller/

test_doca_bridge:
	$(MAKE) -C loxilb-ebpf/doca HAVE_DOCA=1 test_bridge

check:
	go test .

run:
	./$(bin)

docker-cp: build
	docker cp loxilb $(loxilbid):/root/loxilb-io/loxilb/loxilb
	docker cp loxilb-ebpf/kernel/llb_ebpf_main.o $(loxilbid):/opt/loxilb/llb_ebpf_main.o
	docker cp loxilb-ebpf/kernel/llb_ebpf_emain.o $(loxilbid):/opt/loxilb/llb_ebpf_emain.o
	docker cp loxilb-ebpf/kernel/llb_xdp_main.o $(loxilbid):/opt/loxilb/llb_xdp_main.o
	docker cp loxilb-ebpf/kernel/llb_kern_sock.o $(loxilbid):/opt/loxilb/llb_kern_sock.o
	docker cp loxilb-ebpf/kernel/llb_kern_sockmap.o $(loxilbid):/opt/loxilb/llb_kern_sockmap.o
	docker cp loxilb-ebpf/kernel/llb_kern_sockstream.o $(loxilbid):/opt/loxilb/llb_kern_sockstream.o
	docker cp loxilb-ebpf/kernel/llb_kern_sockdirect.o $(loxilbid):/opt/loxilb/llb_kern_sockdirect.o
	docker cp loxilb-ebpf/kernel/loxilb_dp_debug  $(loxilbid):/usr/local/sbin/
	docker cp loxilb-ebpf/libbpf/src/libbpf.so.1.5.0 $(loxilbid):/usr/lib64/
	docker cp loxilb-ebpf/utils/loxilb_dp_tool $(loxilbid):/usr/local/sbin/

docker-cp-ebpf: build
	docker cp loxilb-ebpf/kernel/llb_ebpf_main.o $(loxilbid):/opt/loxilb/llb_ebpf_main.o
	docker cp loxilb-ebpf/kernel/llb_ebpf_emain.o $(loxilbid):/opt/loxilb/llb_ebpf_emain.o
	docker cp loxilb-ebpf/kernel/llb_xdp_main.o $(loxilbid):/opt/loxilb/llb_xdp_main.o
	docker cp loxilb-ebpf/kernel/llb_kern_sock.o $(loxilbid):/opt/loxilb/llb_kern_sock.o
	docker cp loxilb-ebpf/kernel/loxilb_dp_debug  $(loxilbid):/usr/local/sbin/
	docker cp loxilb-ebpf/libbpf/src/libbpf.so.1.5.0 $(loxilbid):/usr/lib64/

docker-run:
	@docker stop $(dock) 2>&1 >> /dev/null || true
	@docker rm $(dock) 2>&1 >> /dev/null || true
	docker run -u root --cap-add SYS_ADMIN   --restart unless-stopped --privileged -dt --entrypoint /bin/bash  --name $(dock) $(IMAGE):$(TAG)

docker-rp: docker-run docker-cp
	@docker exec -it $(dock) mkllb_bpffs 2>&1 >> /dev/null || true
	docker commit ${loxilbid} $(IMAGE):$(TAG)
	@docker stop $(dock) 2>&1 >> /dev/null || true
	@docker rm $(dock) 2>&1 >> /dev/null || true

docker-rp-ebpf: docker-run docker-cp-ebpf
	docker commit ${loxilbid} $(IMAGE):$(TAG)
	@docker stop $(dock) 2>&1 >> /dev/null || true
	@docker rm $(dock) 2>&1 >> /dev/null || true
docker:
	@if [ -f /etc/os-release ]; then \
		. /etc/os-release; \
		if [ "$$ID" = "ubuntu" ] && [ "$$VERSION_ID" = "20.04" ]; then \
			echo "Detected Ubuntu 20.04 - using Dockerfile.u20"; \
			docker build -f Dockerfile.u20 -t $(IMAGE):$(TAG)-u20 .; \
		elif [ "$$ID" = "ubuntu" ] && [ "$$VERSION_ID" = "24.04" ]; then \
			echo "Detected Ubuntu 24.04 - using Dockerfile.u24"; \
			docker build -f Dockerfile.u24 -t $(IMAGE):$(TAG)-u24 .; \
		else \
			echo "Detected $$ID $$VERSION_ID - using default Dockerfile"; \
			docker build -t $(IMAGE):$(TAG) .; \
		fi \
	else \
		echo "Could not detect OS - using default Dockerfile"; \
		docker build -t $(IMAGE):$(TAG) .; \
	fi

docker-arm64:
	@if [ -f /etc/os-release ]; then \
		. /etc/os-release; \
		if [ "$$ID" = "ubuntu" ] && [ "$$VERSION_ID" = "20.04" ]; then \
			echo "Detected Ubuntu 20.04 - using Dockerfile.u20"; \
			docker buildx build --platform linux/arm64 --load -f Dockerfile.u20 -t $(IMAGE):$(ARM64_TAG)-u20 .; \
		elif [ "$$ID" = "ubuntu" ] && [ "$$VERSION_ID" = "24.04" ]; then \
			echo "Detected Ubuntu 24.04 - using Dockerfile.u24"; \
			docker buildx build --platform linux/arm64 --load -f Dockerfile.u24 -t $(IMAGE):$(ARM64_TAG)-u24 .; \
		else \
			echo "Detected $$ID $$VERSION_ID - using default Dockerfile"; \
			docker buildx build --platform linux/arm64 --load -t $(IMAGE):$(ARM64_TAG) .; \
		fi \
	else \
		echo "Could not detect OS - using default Dockerfile"; \
		docker buildx build --platform linux/arm64 --load -t $(IMAGE):$(ARM64_TAG) .; \
	fi

docker-u24:
	docker build -f Dockerfile.u24 -t $(IMAGE):$(TAG)-u24 .

docker-arm64-u22:
	docker buildx build --platform linux/arm64 --load -f Dockerfile -t $(IMAGE):$(ARM64_TAG) .

latest-arm64: docker-arm64-u22

docker-arm64-u24:
	docker buildx build --platform linux/arm64 --load -f Dockerfile.u24 -t $(IMAGE):$(ARM64_TAG)-u24 .

lint:
	golangci-lint run --enable-all
