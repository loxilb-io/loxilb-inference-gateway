#!/bin/bash
# Shared bring-up/teardown/assert helpers for the k3d in-cluster inference
# scenarios (cicd/k3d-incluster-inference-*). loxilb and kube-loxilb run as
# Pods inside a single k3d node; the model servers are mock vLLM pods; the
# client is a container on the k3d docker network.
#
# The VIP is the node container's IP on purpose: fullproxy binds a socket to
# it, and an address loxilb only owns as a /32 rule device cannot be bound.
#
# Requirements on the host: docker, kubectl, git, curl, jq, python3 (+PyYAML).
# k3d >= 5.7 is picked up from PATH or fetched privately (K3D_VERSION).

K8SINF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IGW_IMAGE="${IGW_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}"
KLB_IMAGE="${KLB_IMAGE:-}"       # preset to skip building kube-loxilb from source
KLB_REPO="${KLB_REPO:-https://github.com/loxilb-io/kube-loxilb.git}"
KLB_REF="${KLB_REF:-integration/inference-gateway}"
# Gateway API v1.5.1 CRDs carry CEL (isIP()) that needs k8s >= 1.30, and
# k3s >= 1.33 in turn needs k3d >= 5.7 to boot the node container.
K3S_IMAGE="${K3S_IMAGE:-rancher/k3s:v1.33.13-k3s2}"
K3D_VERSION="${K3D_VERSION:-v5.9.0}"
CLIENT_IMAGE="${CLIENT_IMAGE:-ghcr.io/loxilb-io/nettest:latest}"
GWAPI_VERSION="${GWAPI_VERSION:-v1.5.1}"
GIE_VERSION="${GIE_VERSION:-v1.6.0}"

say() { echo "### $*"; }

# ── k3d binary: system one when >= 5.7, else a private download ──────────────
k3d_bin() {
  local sysver
  if command -v k3d >/dev/null 2>&1; then
    sysver=$(k3d version 2>/dev/null | awk '/^k3d version/{print $3}' | tr -d v)
    if [ -n "$sysver" ] && [ "$(printf '%s\n' 5.7.0 "$sysver" | sort -V | head -1)" = "5.7.0" ]; then
      command -v k3d; return 0
    fi
  fi
  local arch bin="$K8SINF/.bin/k3d"
  case "$(uname -m)" in aarch64|arm64) arch=arm64 ;; *) arch=amd64 ;; esac
  if [ ! -x "$bin" ]; then
    mkdir -p "$K8SINF/.bin"
    curl -sfL "https://github.com/k3d-io/k3d/releases/download/$K3D_VERSION/k3d-linux-$arch" -o "$bin" || return 1
    chmod +x "$bin"
  fi
  echo "$bin"
}

# ── cluster lifecycle ────────────────────────────────────────────────────────
igw_cluster_up() { # <cluster-name>
  CLUSTER="$1"
  K3D="$(k3d_bin)" || { echo "FATAL: no usable k3d and download failed"; return 1; }
  "$K3D" cluster delete "$CLUSTER" >/dev/null 2>&1
  "$K3D" cluster create "$CLUSTER" --image "$K3S_IMAGE" --agents 0 --no-lb \
    --kubeconfig-update-default=false --kubeconfig-switch-context=false \
    --k3s-arg "--disable=traefik@server:0" --k3s-arg "--disable=servicelb@server:0" \
    --wait --timeout 300s >/dev/null || return 1
  export KUBECONFIG="$("$K3D" kubeconfig write "$CLUSTER")"
  NODE="k3d-$CLUSTER-server-0"
  NODE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NODE")
  [ -n "$NODE_IP" ] || return 1
  say "cluster $CLUSTER: node $NODE ($NODE_IP), $(kubectl get node "$NODE" -o jsonpath='{.status.nodeInfo.kubeletVersion}')"
}

igw_env_save() { # <scenario-dir>  — lets validation.sh/rmconfig.sh reattach
  cat > "$1/.env" <<ENV
CLUSTER=$CLUSTER
NODE=$NODE
NODE_IP=$NODE_IP
KUBECONFIG=$KUBECONFIG
KLB_IMAGE=$KLB_IMAGE
ENV
}
igw_env_load() { # <scenario-dir>
  [ -f "$1/.env" ] || { echo "FATAL: $1/.env missing - run ./config.sh first"; return 1; }
  . "$1/.env"
  export KUBECONFIG
}

igw_teardown() { # <cluster-name> <scenario-dir>
  docker rm -f "igw-client-$1" >/dev/null 2>&1
  local k3d; k3d="$(k3d_bin)" && "$k3d" cluster delete "$1" >/dev/null 2>&1
  rm -f "$2/.env"
}

# ── images ───────────────────────────────────────────────────────────────────
igw_prepare_images() {
  docker image inspect "$IGW_IMAGE" >/dev/null 2>&1 || docker pull -q "$IGW_IMAGE" >/dev/null || return 1
  # kube-loxilb checkout: always needed (the manifest is rendered from it);
  # the image build is skipped when KLB_IMAGE is preset.
  KLB_SRC="$K8SINF/.work/kube-loxilb"
  rm -rf "$KLB_SRC" && mkdir -p "$K8SINF/.work"
  git clone -q --depth 1 -b "$KLB_REF" "$KLB_REPO" "$KLB_SRC" || return 1
  say "kube-loxilb @ $(git -C "$KLB_SRC" log -1 --format=%h) ($KLB_REF)"
  if [ -z "$KLB_IMAGE" ]; then
    KLB_IMAGE="ghcr.io/loxilb-io/kube-loxilb:k3d-igw-local"
    say "building $KLB_IMAGE from source"
    docker build -q -t "$KLB_IMAGE" "$KLB_SRC" >/dev/null || return 1
  fi
}
igw_import_images() { "$K3D" image import "$IGW_IMAGE" "$KLB_IMAGE" -c "$CLUSTER" >/dev/null; }

# ── deployments ──────────────────────────────────────────────────────────────
igw_deploy_loxilb() {
  kubectl apply -f "$K8SINF/loxilb-incluster.yml" >/dev/null || return 1
  kubectl -n kube-system rollout status ds/loxilb-lb --timeout=180s >/dev/null || return 1
  local i; for i in $(seq 1 30); do
    curl -s --max-time 3 "http://$NODE_IP:11111/netlox/v1/version" | grep -q '"product":"loxilb-inference-gateway"' && return 0
    sleep 2
  done
  echo "FATAL: loxilb REST did not come up (or wrong flavor) on $NODE_IP:11111"; return 1
}

igw_deploy_mock() {
  kubectl apply -f "$K8SINF/mock-vllm.yaml" >/dev/null || return 1
  kubectl -n llm create configmap mock-vllm-py \
    --from-file=mock_vllm.py="$K8SINF/../../vllm-pd-disagg/mock_vllm.py" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null || return 1
  kubectl -n llm rollout status deploy/vllm-qwen3 --timeout=300s >/dev/null || return 1
}

igw_deploy_kube_loxilb() { # <extra kube-loxilb args appended to the baseline>
  local args="--cidrPools=defaultPool=$NODE_IP/32 --setRoles=0.0.0.0 --v=4 $*"
  KLB_IMAGE="$KLB_IMAGE" KLB_ARGS="$args" python3 "$K8SINF/render-kube-loxilb.py" \
    "$KLB_SRC/manifest/gateway-api/kube-loxilb.yaml" > "$K8SINF/.work/kube-loxilb-rendered.yaml" || return 1
  kubectl apply -f "$K8SINF/.work/kube-loxilb-rendered.yaml" >/dev/null || return 1
  kubectl -n kube-system rollout status deploy/kube-loxilb --timeout=180s >/dev/null || return 1
}

igw_install_gwapi_crds() {
  kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GWAPI_VERSION/standard-install.yaml" >/dev/null || return 1
  kubectl apply -k "https://github.com/kubernetes-sigs/gateway-api-inference-extension/config/crd?ref=$GIE_VERSION" >/dev/null || return 1
}

igw_client_up() {
  docker rm -f "igw-client-$CLUSTER" >/dev/null 2>&1
  docker run -d --name "igw-client-$CLUSTER" --network "k3d-$CLUSTER" \
    --entrypoint sleep "$CLIENT_IMAGE" infinity >/dev/null
}
client_curl() { docker exec "igw-client-$CLUSTER" curl "$@"; }

# ── assertion helpers ────────────────────────────────────────────────────────
fails=0
ok()   { echo "  [OK]   $1"; }
bad()  { echo "  [FAIL] $1${2:+ - $2}"; fails=$((fails+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
poll() { local t=$1; shift; local i; for ((i=0;i<t;i++)); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

rules_all() { curl -s --max-time 5 "http://$NODE_IP:11111/netlox/v1/config/loadbalancer/all"; }

# A rule that reads back over REST proves nothing about fullproxy: mode=4 is
# only real if a socket bound. /proc/net/tcp in the node netns is the witness.
node_listening() { # <ip> <port>
  local hex
  hex=$(printf '%02X%02X%02X%02X:%04X' $(echo "$1" | awk -F. '{print $4,$3,$2,$1}') "$2")
  docker exec "$NODE" cat /proc/net/tcp | awk 'NR>1 && $4=="0A"{print $2}' | grep -qi "^$hex$"
}
