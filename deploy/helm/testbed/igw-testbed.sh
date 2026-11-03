#!/bin/bash
# igw-testbed.sh: an inference-gateway test bed on an existing Kubernetes
# cluster, in one command.
#
#   up      install everything below and configure it
#   test    send requests through the VIP and check auth, EPP routing and audit
#   status  show what is installed and how it is wired
#   down    remove what `up` installed (CRDs and node-local loxilb state stay)
#
# What `up` installs:
#   - the loxilb-inference-gateway chart (loxilb-igw + kube-loxilb + Gateway)
#   - an Endpoint Picker: the llm-d Router chart (InferencePool, EPP, HTTPRoute)
#     in front of llm-d inference-sim model servers
#   - PostgreSQL as the gateway's API-key store (scripts/aigw-db-bootstrap.sql)
#   - Keycloak with the realm cicd/ai-jwtauth/mkrealm.py generates, a
#     JWTAuthProfile, and JWT auth on the pool
#   - a syslog-over-TLS receiver (cicd/audit-sink/syslog_receiver.py) as the
#     gateway's compliance audit sink
#
# Everything is reached through kubectl: the gateway's management API through a
# port-forward to its management Service, requests through a client pod.
#
# Usage: igw-testbed.sh [-c config.env] up|test|status|down [--failclose]
# Configuration: environment variables or a config file; see
# testbed.env.example and docs/HELM-TESTBED.md.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"

say()  { echo "### $*"; }
warn() { echo "WARN: $*" >&2; }
die()  { echo "FATAL: $*" >&2; exit 1; }

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

CONFIG=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--config) CONFIG="$2"; shift 2 ;;
    -h|--help)   usage 0 ;;
    *) break ;;
  esac
done
CMD="${1:-}"; [ -n "$CMD" ] || usage 1; shift
OPT_FAILCLOSE=0
for a in "$@"; do
  case "$a" in
    --failclose) OPT_FAILCLOSE=1 ;;
    *) die "unknown option $a" ;;
  esac
done
if [ -n "$CONFIG" ]; then
  [ -f "$CONFIG" ] || die "config file $CONFIG not found"
  # shellcheck disable=SC1090
  . "$CONFIG"
fi

# ── configuration ────────────────────────────────────────────────────────────
VIP="${VIP:-}"                                   # address of the loxilb node (required for up)
LISTENER_PORT="${LISTENER_PORT:-8080}"
LOXILB_NODE="${LOXILB_NODE:-}"                   # kubernetes.io/hostname for loxilb and kube-loxilb
IGW_IMAGE="${IGW_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}"
IGW_PULL_POLICY="${IGW_PULL_POLICY:-Always}"
KLB_IMAGE="${KLB_IMAGE:-}"                       # kube-loxilb built from feat/auth-annotation (required for up)
KLB_PULL_POLICY="${KLB_PULL_POLICY:-IfNotPresent}"
LOXILB_BLACKLIST="${LOXILB_BLACKLIST:-cni[0-9a-z]|veth.|flannel.|cali.|tunl.|vxlan[.]calico|docker.|br-.}"
EXTRA_VALUES="${EXTRA_VALUES:-}"                 # extra values file for the gateway chart

RELEASE="${RELEASE:-igw}"
RELEASE_NS="${RELEASE_NS:-kube-system}"
LLM_NS="${LLM_NS:-llm}"
AIGW_NS="${AIGW_NS:-aigw}"
GATEWAY_NAME="${GATEWAY_NAME:-inference-gw}"
POOL="${POOL:-sim-pool}"
MODEL="${MODEL:-llama-70b}"                      # the realm grants alice model:llama-70b
SIM_IMAGE="${SIM_IMAGE:-ghcr.io/llm-d/llm-d-inference-sim:v1.0.0}"
SIM_REPLICAS="${SIM_REPLICAS:-3}"

LLMD_REPO="${LLMD_REPO:-https://github.com/llm-d/llm-d-router.git}"
LLMD_REF="${LLMD_REF:-v1.0.0}"
EPP_IMAGE_TAG="${EPP_IMAGE_TAG:-v1.0.0}"
EPP_FAILURE_MODE="${EPP_FAILURE_MODE:-FailClose}"
EPP_CPU="${EPP_CPU:-500m}"
EPP_MEMORY="${EPP_MEMORY:-1Gi}"

PG_IMAGE="${PG_IMAGE:-postgres:18.6}"
KC_IMAGE="${KC_IMAGE:-quay.io/keycloak/keycloak:26.0}"
KC_PROFILE="${KC_PROFILE:-kc}"
SYSLOG_IMAGE="${SYSLOG_IMAGE:-python:3.12-slim}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.23.0}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.1}"   # applied only when the CRDs are missing

CHART="${CHART:-$REPO/deploy/helm/loxilb-inference-gateway}"
WORK="${WORK:-$HERE/_work}"
MANAGED_LABEL="app.kubernetes.io/managed-by=igw-testbed"

mkdir -p "$WORK"
k() { kubectl "$@"; }

need_tools() {
  local t
  for t in kubectl helm git openssl python3 curl; do
    command -v "$t" >/dev/null 2>&1 || die "$t is required"
  done
  k version --request-timeout=10s >/dev/null 2>&1 || die "kubectl cannot reach the cluster (KUBECONFIG?)"
}

svc_ip() { k -n "$1" get svc "$2" -o jsonpath='{.spec.clusterIP}'; }

# wait_for <seconds> <description> <command...>: retry until the command succeeds
wait_for() {
  local t=$1 what=$2 end; shift 2
  end=$(( $(date +%s) + t ))
  until "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$end" ] || die "timed out after ${t}s waiting for $what"
    sleep 3
  done
}

ensure_ns() {
  local phase
  phase=$(k get ns "$1" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  # A namespace a previous `down` is still deleting takes nothing new.
  if [ "$phase" = Terminating ]; then
    say "namespace $1 is still being deleted, waiting"
    wait_for 300 "namespace $1 to be deleted" sh -c "! kubectl get ns $1 >/dev/null 2>&1"
    phase=""
  fi
  if [ -z "$phase" ]; then
    k create ns "$1" >/dev/null
    k label ns "$1" "$MANAGED_LABEL" >/dev/null
  fi
}

# secret_key <ns> <secret> <key>: decoded value of one key
secret_key() { k -n "$1" get secret "$2" -o jsonpath="{.data.$3}" | base64 -d; }

# ── management API of the gateway, through a port-forward ────────────────────
PF_PID=""
MGMT=""
mgmt_up() {
  [ -n "$PF_PID" ] && return 0
  local port=$(( 20000 + RANDOM % 20000 ))
  local svc
  svc=$(helm get values "$RELEASE" -n "$RELEASE_NS" --all -o json 2>/dev/null \
        | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v.get("loxilb-igw",{}).get("mgmtService",{}).get("name","loxilb-lb-mgmt"))' 2>/dev/null || echo loxilb-lb-mgmt)
  k -n "$RELEASE_NS" port-forward "svc/$svc" "$port:11111" >"$WORK/port-forward.log" 2>&1 &
  PF_PID=$!
  MGMT="http://127.0.0.1:$port/netlox/v1"
  trap 'kill $PF_PID 2>/dev/null || true' EXIT
  wait_for 60 "the gateway management API ($svc)" curl -sf --max-time 3 "$MGMT/version"
}
mgmt() { # <method> <path> [json]
  mgmt_up
  if [ -n "${3:-}" ]; then
    curl -s --max-time 10 -X "$1" "$MGMT$2" -H "Content-Type: application/json" -d "$3" -w '\n%{http_code}'
  else
    curl -s --max-time 10 -X "$1" "$MGMT$2" -w '\n%{http_code}'
  fi
}

# client <script>: run a POSIX shell script in a throwaway curl pod
client() {
  k -n "$LLM_NS" run "igw-testbed-client-$RANDOM" --rm -i --restart=Never --quiet \
    --image="$CURL_IMAGE" --command -- sh -c "$1" 2>/dev/null
}

# ── up: CRDs ─────────────────────────────────────────────────────────────────
llmd_checkout() {
  local dir="$WORK/llm-d-router"
  if [ ! -d "$dir/.git" ] || [ "$(git -C "$dir" describe --tags --exact-match 2>/dev/null)" != "$LLMD_REF" ]; then
    rm -rf "$dir"
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$LLMD_REF" "$LLMD_REPO" "$dir" \
      2>"$WORK/llm-d-clone.log" || die "cannot clone $LLMD_REPO@$LLMD_REF (see $WORK/llm-d-clone.log)"
  fi
  echo "$dir"
}

up_crds() {
  if k get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
    say "Gateway API CRDs present (bundle $(k get crd gateways.gateway.networking.k8s.io \
      -o jsonpath='{.metadata.annotations.gateway\.networking\.k8s\.io/bundle-version}')), kept"
  else
    say "Gateway API CRDs $GATEWAY_API_VERSION"
    k apply --server-side -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" >/dev/null
  fi
  # llm-d's CRD set: InferencePool (inference.networking.k8s.io/v1) and the
  # llm-d.ai objects its EPP watches (InferenceObjective, InferenceModelRewrite).
  local dir; dir=$(llmd_checkout)
  say "llm-d Router $LLMD_REF CRDs (InferencePool, llm-d.ai)"
  k kustomize "$dir/config/crd" | k apply --server-side -f - >/dev/null
}

# ── up: PostgreSQL API-key store ─────────────────────────────────────────────
up_postgres() {
  say "PostgreSQL API-key store ($PG_IMAGE) in $AIGW_NS"
  if ! k -n "$AIGW_NS" get secret aigw-db >/dev/null 2>&1; then
    k -n "$AIGW_NS" create secret generic aigw-db \
      --from-literal=POSTGRES_PASSWORD="$(openssl rand -hex 16)" \
      --from-literal=AIGW_DB_PASSWORD="$(openssl rand -hex 16)" \
      --from-literal=AIGW_MGMT_DB_PASSWORD="$(openssl rand -hex 16)" >/dev/null
  fi
  k -n "$AIGW_NS" create configmap aigw-db-bootstrap \
    --from-file=10-aigw-bootstrap.sql="$REPO/scripts/aigw-db-bootstrap.sql" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  k apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: postgres, namespace: $AIGW_NS }
spec:
  replicas: 1
  selector: { matchLabels: { app: postgres } }
  template:
    metadata: { labels: { app: postgres } }
    spec:
      containers:
        - name: postgres
          image: $PG_IMAGE
          env:
            - { name: POSTGRES_USER, value: oamuser }
            - { name: POSTGRES_DB, value: loxilb }
            - { name: POSTGRES_PASSWORD, valueFrom: { secretKeyRef: { name: aigw-db, key: POSTGRES_PASSWORD } } }
            - { name: AIGW_DB_PASSWORD, valueFrom: { secretKeyRef: { name: aigw-db, key: AIGW_DB_PASSWORD } } }
            - { name: AIGW_MGMT_DB_PASSWORD, valueFrom: { secretKeyRef: { name: aigw-db, key: AIGW_MGMT_DB_PASSWORD } } }
          ports: [{ containerPort: 5432 }]
          readinessProbe:
            exec: { command: ["pg_isready", "-h", "127.0.0.1", "-U", "oamuser", "-d", "loxilb"] }
            periodSeconds: 5
          volumeMounts:
            - { name: init, mountPath: /docker-entrypoint-initdb.d }
            - { name: data, mountPath: /var/lib/postgresql }
      volumes:
        - { name: init, configMap: { name: aigw-db-bootstrap } }
        # Test bed: the store lives as long as the pod.
        - { name: data, emptyDir: {} }
---
apiVersion: v1
kind: Service
metadata: { name: postgres, namespace: $AIGW_NS }
spec:
  selector: { app: postgres }
  ports: [{ port: 5432, targetPort: 5432 }]
EOF
  k -n "$AIGW_NS" rollout status deploy/postgres --timeout=300s >/dev/null
  # The gateway reads its data-plane password from a Secret in its own namespace.
  k -n "$RELEASE_NS" create secret generic aigw-db-dp \
    --from-literal=password="$(secret_key "$AIGW_NS" aigw-db AIGW_DB_PASSWORD)" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
}

# ── up: Keycloak ─────────────────────────────────────────────────────────────
up_keycloak() {
  say "Keycloak ($KC_IMAGE, realm aigw) in $AIGW_NS"
  python3 "$REPO/cicd/ai-jwtauth/mkrealm.py" "$WORK/aigw-realm.json" >/dev/null
  k -n "$AIGW_NS" create configmap keycloak-realm --from-file=aigw-realm.json="$WORK/aigw-realm.json" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  if ! k -n "$AIGW_NS" get secret keycloak-admin >/dev/null 2>&1; then
    k -n "$AIGW_NS" create secret generic keycloak-admin \
      --from-literal=username=admin --from-literal=password="$(openssl rand -hex 16)" >/dev/null
  fi
  k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: { name: keycloak, namespace: $AIGW_NS }
spec:
  selector: { app: keycloak }
  ports: [{ port: 8080, targetPort: 8080 }]
EOF
  local kc_ip; kc_ip=$(svc_ip "$AIGW_NS" keycloak)
  # The issuer is pinned to the Service address: the gateway (hostNetwork) fetches
  # the JWKS there, and tokens minted through any other URL (a port-forward, a
  # client pod) still carry this iss.
  k apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: keycloak, namespace: $AIGW_NS }
spec:
  replicas: 1
  selector: { matchLabels: { app: keycloak } }
  template:
    metadata: { labels: { app: keycloak } }
    spec:
      containers:
        - name: keycloak
          image: $KC_IMAGE
          args: ["start-dev", "--import-realm"]
          env:
            - { name: KC_HOSTNAME, value: "http://$kc_ip:8080" }
            - { name: KC_HTTP_ENABLED, value: "true" }
            - { name: KC_HEALTH_ENABLED, value: "true" }
            - { name: KC_BOOTSTRAP_ADMIN_USERNAME, valueFrom: { secretKeyRef: { name: keycloak-admin, key: username } } }
            - { name: KC_BOOTSTRAP_ADMIN_PASSWORD, valueFrom: { secretKeyRef: { name: keycloak-admin, key: password } } }
          ports: [{ containerPort: 8080 }]
          readinessProbe:
            httpGet: { path: /realms/aigw/protocol/openid-connect/certs, port: 8080 }
            periodSeconds: 5
            failureThreshold: 60
          volumeMounts:
            - { name: realm, mountPath: /opt/keycloak/data/import }
      volumes:
        - { name: realm, configMap: { name: keycloak-realm } }
EOF
  k -n "$AIGW_NS" rollout status deploy/keycloak --timeout=420s >/dev/null
}

# ── up: syslog-over-TLS receiver ─────────────────────────────────────────────
up_syslog() {
  say "syslog TLS receiver ($SYSLOG_IMAGE) in $AIGW_NS"
  k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: { name: syslog, namespace: $AIGW_NS }
spec:
  selector: { app: syslog-receiver }
  ports:
    - { name: syslog-tls, port: 6514, targetPort: 6514 }
    - { name: control, port: 6515, targetPort: 6515 }
EOF
  local sip pki="$WORK/pki"; sip=$(svc_ip "$AIGW_NS" syslog)
  mkdir -p "$pki"
  # The gateway verifies the receiver against server_name (the Service IP), so
  # the certificate carries it as an IP SAN; a run CA signs it.
  if [ ! -f "$pki/srv.pem" ] || ! openssl x509 -in "$pki/srv.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address:$sip\$"; then
    ( cd "$pki" && umask 077 \
      && openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout ca.key -out ca.pem -subj "/CN=igw-testbed-audit-ca" 2>/dev/null \
      && openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=audit-sink-receiver-$sip" 2>/dev/null \
      && printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$sip" > srv.ext \
      && openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -extfile srv.ext -out srv.pem 2>/dev/null ) \
      || die "certificate generation failed"
  fi
  k -n "$AIGW_NS" create secret generic syslog-tls --from-file=srv.pem="$pki/srv.pem" --from-file=srv.key="$pki/srv.key" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  k -n "$AIGW_NS" create configmap syslog-receiver --from-file=syslog_receiver.py="$REPO/cicd/audit-sink/syslog_receiver.py" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  # The CA the gateway verifies the receiver with (loxilb-igw.trust).
  k -n "$RELEASE_NS" create configmap aigw-integration-ca --from-file=sink-ca.pem="$pki/ca.pem" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  k apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: syslog-receiver, namespace: $AIGW_NS }
spec:
  replicas: 1
  selector: { matchLabels: { app: syslog-receiver } }
  template:
    metadata:
      labels: { app: syslog-receiver }
      annotations: { igw-testbed/cert-san: "$sip" }
    spec:
      containers:
        - name: receiver
          image: $SYSLOG_IMAGE
          command: ["python3", "-u", "/app/syslog_receiver.py",
                    "--sink", "compliance", "--port", "6514", "--control", "0.0.0.0:6515",
                    "--pen", "32473", "--cert", "/tls/srv.pem", "--key", "/tls/srv.key",
                    "--out", "/data/audit-sink-compliance.jsonl"]
          ports: [{ containerPort: 6514 }, { containerPort: 6515 }]
          readinessProbe:
            httpGet: { path: /__stats, port: 6515 }
            periodSeconds: 5
          volumeMounts:
            - { name: app, mountPath: /app }
            - { name: tls, mountPath: /tls }
            - { name: data, mountPath: /data }
      volumes:
        - { name: app, configMap: { name: syslog-receiver } }
        - { name: tls, secret: { secretName: syslog-tls } }
        - { name: data, emptyDir: {} }
EOF
  k -n "$AIGW_NS" rollout status deploy/syslog-receiver --timeout=300s >/dev/null
}

# ── up: the gateway chart ────────────────────────────────────────────────────
gateway_values() {
  local pg_ip; pg_ip=$(svc_ip "$AIGW_NS" postgres)
  local node_sel="{}"
  [ -n "$LOXILB_NODE" ] && node_sel="{ kubernetes.io/hostname: \"$LOXILB_NODE\" }"
  local repo="${IGW_IMAGE%:*}" tag="${IGW_IMAGE##*:}"
  local krepo="${KLB_IMAGE%:*}" ktag="${KLB_IMAGE##*:}"
  cat <<EOF
# Generated by igw-testbed.sh; edit the config, not this file.
loxilb-igw:
  image: { repository: "$repo", tag: "$tag", pullPolicy: $IGW_PULL_POLICY }
  nodeSelector: $node_sel
  # Rancher/RKE2 control-plane nodes also carry an etcd NoExecute taint.
  tolerations:
    - { key: node-role.kubernetes.io/master, operator: Exists }
    - { key: node-role.kubernetes.io/control-plane, operator: Exists }
    - { key: node-role.kubernetes.io/etcd, operator: Exists, effect: NoExecute }
  loxilb:
    blacklist: "$LOXILB_BLACKLIST"
    extraArgs:
      - --aikey-db-host=$pg_ip
      - --aikey-db-port=5432
      - --aikey-db-user=aigwuser
      - --aikey-db-name=loxilb
  extraEnv:
    - name: AIGW_DB_PASSWORD
      valueFrom: { secretKeyRef: { name: aigw-db-dp, key: password } }
  trust:
    enabled: true
    existingConfigMap: aigw-integration-ca
kube-loxilb:
  image: { repository: "$krepo", tag: "$ktag", pullPolicy: $KLB_PULL_POLICY }
  cidrPools: { defaultPool: "$VIP/32" }
  nodeSelector: $node_sel
  tolerations:
    - { key: CriticalAddonsOnly, operator: Exists }
    - { key: node-role.kubernetes.io/master, operator: Exists }
    - { key: node-role.kubernetes.io/control-plane, operator: Exists }
    - { key: node-role.kubernetes.io/etcd, operator: Exists, effect: NoExecute }
inference:
  gateway:
    name: $GATEWAY_NAME
    namespace: $LLM_NS
    listeners:
      - { name: http, protocol: HTTP, port: $LISTENER_PORT, allowedRoutes: { namespaces: { from: All } } }
  # The InferencePool, its EPP and the HTTPRoute come from the llm-d Router chart.
  pools: []
EOF
}

up_gateway() {
  say "loxilb-inference-gateway chart: release $RELEASE in $RELEASE_NS (VIP $VIP:$LISTENER_PORT)"
  gateway_values > "$WORK/values-gateway.yaml"
  local extra=()
  [ -n "$EXTRA_VALUES" ] && extra=(-f "$EXTRA_VALUES")
  helm upgrade --install "$RELEASE" "$CHART" -n "$RELEASE_NS" -f "$WORK/values-gateway.yaml" ${extra[@]+"${extra[@]}"} \
    --wait --timeout 10m >/dev/null
  local v; v=$(mgmt GET /version | head -1)
  echo "    gateway /version: $v"
  local f
  for f in epp api_key_auth jwt_auth_profile; do
    echo "$v" | grep -q "\"$f\"" || warn "the gateway image does not list \"$f\" in /version features"
  done
}

# ── up: model servers and the Endpoint Picker ────────────────────────────────
up_models() {
  say "model servers: $SIM_REPLICAS x $SIM_IMAGE (model $MODEL) in $LLM_NS"
  k apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: $POOL, namespace: $LLM_NS }
spec:
  replicas: $SIM_REPLICAS
  selector: { matchLabels: { app: $POOL } }
  template:
    metadata: { labels: { app: $POOL } }
    spec:
      containers:
        - name: sim
          image: $SIM_IMAGE
          args: ["--model", "$MODEL", "--port", "8000", "--max-num-seqs", "4",
                 "--time-to-first-token", "200ms", "--inter-token-latency", "20ms"]
          env:
            - { name: POD_NAME, valueFrom: { fieldRef: { fieldPath: metadata.name } } }
            - { name: POD_NAMESPACE, valueFrom: { fieldRef: { fieldPath: metadata.namespace } } }
            - { name: POD_IP, valueFrom: { fieldRef: { fieldPath: status.podIP } } }
          ports: [{ containerPort: 8000, name: http }]
          readinessProbe:
            httpGet: { path: /health, port: 8000 }
            periodSeconds: 5
EOF
  k -n "$LLM_NS" rollout status "deploy/$POOL" --timeout=300s >/dev/null
}

pool_resolved() {
  k -n "$LLM_NS" get inferencepool "$POOL" \
    -o jsonpath='{.status.parents[*].conditions[?(@.type=="ResolvedRefs")].status}' | grep -q True
}

up_epp() {
  say "Endpoint Picker: llm-d Router $LLMD_REF chart (release $POOL in $LLM_NS, failureMode $EPP_FAILURE_MODE)"
  local dir; dir=$(llmd_checkout)
  local chart="$dir/config/charts/llm-d-router-gateway"
  helm dependency build "$chart" >/dev/null
  cat > "$WORK/values-llmd.yaml" <<EOF
# Generated by igw-testbed.sh.
router:
  modelServers:
    matchLabels: { app: $POOL }
  epp:
    image: { tag: $EPP_IMAGE_TAG, pullPolicy: IfNotPresent }
    resources:
      requests: { cpu: $EPP_CPU, memory: $EPP_MEMORY }
      limits: { memory: 2Gi }
  # With create=false the EPP would select pods by label instead of following
  # the InferencePool, which is the path under test.
  inferencePool:
    create: true
    failureMode: $EPP_FAILURE_MODE
httpRoute:
  create: true
  inferenceGatewayName: $GATEWAY_NAME
  inferenceGatewayNamespace: $LLM_NS
EOF
  helm upgrade --install "$POOL" "$chart" -n "$LLM_NS" -f "$WORK/values-llmd.yaml" --wait --timeout 10m >/dev/null
  wait_for 180 "InferencePool $POOL to resolve its endpoint picker" pool_resolved
}

# ── up: JWT auth and the audit sink ──────────────────────────────────────────
rule_has() { mgmt GET /config/loadbalancer/all | head -1 | grep -q "$1"; }
profile_programmed() {
  k get jwtauthprofile "$KC_PROFILE" -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}' | grep -q True
}

up_auth() {
  local kc_ip; kc_ip=$(svc_ip "$AIGW_NS" keycloak)
  say "JWTAuthProfile $KC_PROFILE and JWT auth on InferencePool $POOL"
  k apply -f - >/dev/null <<EOF
apiVersion: jwtauthprofile.loxilb.io/v1
kind: JWTAuthProfile
metadata:
  name: $KC_PROFILE
  labels: { app.kubernetes.io/managed-by: igw-testbed }
spec:
  issuer: http://$kc_ip:8080/realms/aigw
  jwksUrl: http://$kc_ip:8080/realms/aigw/protocol/openid-connect/certs
  audiences: ["aigw-api"]
  refreshSec: 300
EOF
  wait_for 120 "JWTAuthProfile $KC_PROFILE to be programmed" profile_programmed
  k -n "$LLM_NS" annotate inferencepool "$POOL" --overwrite \
    loxilb.io/api-key-auth=jwt loxilb.io/jwt-auth-profile="$KC_PROFILE" loxilb.io/sse-mode=true >/dev/null
  wait_for 120 "the pool's rule to carry api_key_auth" rule_has '"api_key_auth":"jwt"'
}

sink_connected() { mgmt GET /audit/status | head -1 | grep -q '"state":"connected"'; }

up_audit() {
  local sip; sip=$(svc_ip "$AIGW_NS" syslog)
  say "audit sink: syslog over TLS to $sip:6514"
  local out
  out=$(mgmt POST /audit/sink "{\"enabled\":true,\"address\":\"$sip:6514\",\"ca_bundle_path\":\"/run/integration-ca/sink-ca.pem\",\"server_name\":\"$sip\"}")
  [ "$(echo "$out" | tail -1)" = 204 ] || die "POST /audit/sink answered: $out"
  wait_for 60 "the audit sink to connect" sink_connected
}

cmd_up() {
  [ -n "$VIP" ] || die "VIP is required (the address of the node loxilb runs on)"
  [ -n "$KLB_IMAGE" ] || die "KLB_IMAGE is required (kube-loxilb built from feat/auth-annotation)"
  need_tools
  ensure_ns "$LLM_NS"; ensure_ns "$AIGW_NS"
  up_crds
  up_postgres
  up_keycloak
  up_syslog
  up_gateway
  up_models
  up_epp
  up_auth
  up_audit
  cmd_status
  say "up: done. Next: $0 ${CONFIG:+-c $CONFIG }test"
}

# ── test ─────────────────────────────────────────────────────────────────────
PASS=0; FAIL=0
check() { # <label> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "[OK]   $1 ($3)"; PASS=$((PASS + 1))
  else echo "[FAIL] $1: expected $2, got $3"; FAIL=$((FAIL + 1)); fi
}

client_script() { # requests from inside the cluster to the VIP
  local kc_ip sip; kc_ip=$(svc_ip "$AIGW_NS" keycloak); sip=$(svc_ip "$AIGW_NS" syslog)
  cat <<EOF
TOKEN_URL=http://$kc_ip:8080/realms/aigw/protocol/openid-connect/token
URL=http://$VIP:$LISTENER_PORT/v1/chat/completions
tok() { curl -s -m 10 -d client_id=aigw-client -d username=\$1 -d password=\${1}pw -d grant_type=password \$TOKEN_URL | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'; }
code() { curl -s -m 15 -o /dev/null -w '%{http_code}' \$URL -H 'Content-Type: application/json' "\$@"; }
BODY='{"model":"$MODEL","messages":[{"role":"user","content":"igw-testbed"}],"max_tokens":4}'
SBODY='{"model":"$MODEL","stream":true,"messages":[{"role":"user","content":"igw-testbed"}],"max_tokens":4}'
TA=\$(tok alice); TB=\$(tok bob)
echo "TOKENS \${#TA} \${#TB}"
echo "STATS0 \$(curl -s -m 5 http://$sip:6515/__stats | tr -d '\n')"
echo "NO_TOKEN \$(code -d "\$BODY")"
echo "BOB \$(code -H "Authorization: Bearer \$TB" -d "\$BODY")"
# Flip the signature's first character: its last one carries unused bits, so
# changing it can leave the signature bytes as they were.
SIG=\${TA##*.}; F=\$(printf %s "\$SIG" | cut -c1); if [ "\$F" = A ]; then R=B; else R=A; fi
TX="\${TA%.*}.\$R\${SIG#?}"
echo "TAMPERED \$(code -H "Authorization: Bearer \$TX" -d "\$BODY")"
ok=0; for i in 1 2 3 4 5 6 7 8 9 10; do [ "\$(code -H "Authorization: Bearer \$TA" -d "\$BODY")" = 200 ] && ok=\$((ok+1)); done
echo "ALICE_OK \$ok"
echo "STREAM \$(curl -sN -m 15 \$URL -H 'Content-Type: application/json' -H "Authorization: Bearer \$TA" -d "\$SBODY" | grep -c '^data:')"
sleep 3
echo "STATS1 \$(curl -s -m 5 http://$sip:6515/__stats | tr -d '\n')"
EOF
}

stat_field() { # <json> <field>
  python3 -c 'import json,sys; print(json.loads(sys.argv[1] or "{}").get(sys.argv[2], ""))' "$1" "$2" 2>/dev/null
}

epp_decisions_since() { # <RFC3339>
  k -n "$RELEASE_NS" logs "ds/$RELEASE-loxilb-igw" --since-time="$1" 2>/dev/null | grep -cE '\[EPP\] fd=[0-9]+ sid=[0-9]+ -> ' || true
}

test_failclose() {
  local epp_label="llm-d-router-gateway=$POOL-epp" before
  say "FailClose: EPP scaled to 0"
  k -n "$LLM_NS" scale "deploy/$POOL-epp" --replicas=0 >/dev/null
  # The EPP keeps answering on open streams for its termination grace period.
  k -n "$LLM_NS" wait --for=delete pod -l "$epp_label" --timeout=240s >/dev/null 2>&1 || true
  local kc_ip; kc_ip=$(svc_ip "$AIGW_NS" keycloak)
  before=$(client "TA=\$(curl -s -m 10 -d client_id=aigw-client -d username=alice -d password=alicepw -d grant_type=password http://$kc_ip:8080/realms/aigw/protocol/openid-connect/token | sed -n 's/.*\"access_token\":\"\([^\"]*\)\".*/\1/p'); curl -s -m 10 http://$VIP:$LISTENER_PORT/v1/chat/completions -H 'Content-Type: application/json' -H \"Authorization: Bearer \$TA\" -d '{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"failclose\"}],\"max_tokens\":4}' -w ' %{http_code}'")
  check "EPP down: request refused with 503" 503 "${before##* }"
  echo "$before" | grep -q epp_unavailable && check "EPP down: error epp_unavailable" yes yes \
    || check "EPP down: error epp_unavailable" yes no
  say "FailClose: EPP scaled back to 1"
  k -n "$LLM_NS" scale "deploy/$POOL-epp" --replicas=1 >/dev/null
  k -n "$LLM_NS" rollout status "deploy/$POOL-epp" --timeout=240s >/dev/null
  local code="" _
  for _ in $(seq 1 20); do
    code=$(client "TA=\$(curl -s -m 10 -d client_id=aigw-client -d username=alice -d password=alicepw -d grant_type=password http://$kc_ip:8080/realms/aigw/protocol/openid-connect/token | sed -n 's/.*\"access_token\":\"\([^\"]*\)\".*/\1/p'); curl -s -m 10 -o /dev/null -w '%{http_code}' http://$VIP:$LISTENER_PORT/v1/chat/completions -H 'Content-Type: application/json' -H \"Authorization: Bearer \$TA\" -d '{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"recover\"}],\"max_tokens\":4}'")
    [ "$code" = 200 ] && break
    sleep 2
  done
  check "EPP back: requests served again" 200 "$code"
}

cmd_test() {
  need_tools
  [ -n "$VIP" ] || die "VIP is required"
  local t0 out
  t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  say "requests from a client pod to $VIP:$LISTENER_PORT (model $MODEL)"
  out=$(client "$(client_script)")
  echo "$out" | grep -vE '^STATS' | sed 's/^/    /'
  v() { echo "$out" | sed -n "s/^$1 //p" | head -1; }
  check "no token: 401" 401 "$(v NO_TOKEN)"
  check "bob (no model:$MODEL role): 403" 403 "$(v BOB)"
  check "tampered token: 401" 401 "$(v TAMPERED)"
  check "alice: 10 of 10 served" 10 "$(v ALICE_OK)"
  local stream; stream=$(v STREAM)
  check "alice stream: SSE data lines" yes "$([ "${stream:-0}" -gt 0 ] && echo yes || echo no)"
  local decisions; decisions=$(epp_decisions_since "$t0")
  check "every served request went through the EPP (11)" 11 "$decisions"
  local s0 s1; s0=$(v STATS0); s1=$(v STATS1)
  local r0 r1; r0=$(stat_field "$s0" records); r1=$(stat_field "$s1" records)
  check "audit records reached the syslog receiver" yes "$([ "${r1:-0}" -gt "${r0:-0}" ] && echo yes || echo no)"
  local e f; e=$(stat_field "$s1" framing_errors); f=$(stat_field "$s1" header_errors)
  check "syslog framing/header errors" "0/0" "${e:-?}/${f:-?}"
  [ "$OPT_FAILCLOSE" = 1 ] && test_failclose
  echo
  if [ "$FAIL" = 0 ]; then echo "RESULT: PASS ($PASS checks)"; else echo "RESULT: FAIL ($FAIL of $((PASS + FAIL)) checks)"; exit 1; fi
}

# ── status ───────────────────────────────────────────────────────────────────
cmd_status() {
  need_tools
  say "pods"
  k -n "$RELEASE_NS" get pods -l "app.kubernetes.io/instance=$RELEASE" -o wide 2>/dev/null | cut -c1-120 || true
  k -n "$LLM_NS" get pods -o wide 2>/dev/null | cut -c1-120 || true
  k -n "$AIGW_NS" get pods -o wide 2>/dev/null | cut -c1-120 || true
  say "Gateway $LLM_NS/$GATEWAY_NAME"
  k -n "$LLM_NS" get gateway "$GATEWAY_NAME" \
    -o jsonpath='{range .status.conditions[*]}  {.type}={.status}{"\n"}{end}  address {.status.addresses[*].value}{"\n"}' 2>/dev/null || echo "  (none)"
  say "InferencePool $LLM_NS/$POOL"
  k -n "$LLM_NS" get inferencepool "$POOL" \
    -o jsonpath='{range .status.parents[*].conditions[*]}  {.type}={.status}: {.message}{"\n"}{end}' 2>/dev/null || echo "  (none)"
  say "JWTAuthProfile $KC_PROFILE"
  k get jwtauthprofile "$KC_PROFILE" -o wide 2>/dev/null | sed 's/^/  /' || echo "  (none)"
  if helm status "$RELEASE" -n "$RELEASE_NS" >/dev/null 2>&1; then
    say "gateway rules"
    mgmt GET /config/loadbalancer/all | head -1 | python3 -c '
import json,sys
for r in json.load(sys.stdin).get("lbAttr",[]):
    s=r["serviceArguments"]
    keys=("eppEndpoint","eppFailureMode","api_key_auth","jwt_auth_profile","sse_mode")
    print("  %s:%s mode %s %s" % (s.get("externalIP"), s.get("port"), s.get("mode"),
          {k: s[k] for k in keys if s.get(k) not in (None, "")}))
    print("    endpoints", [e["endpointIP"] for e in r.get("endpoints", [])])' 2>/dev/null || true
    say "audit sinks"
    mgmt GET /audit/status | head -1 | python3 -c '
import json,sys
for s in json.load(sys.stdin).get("sinks",[]): print("  %s state=%s" % (s.get("name"), s.get("state")))' 2>/dev/null || true
  fi
}

# ── down ─────────────────────────────────────────────────────────────────────
cmd_down() {
  need_tools
  if helm status "$RELEASE" -n "$RELEASE_NS" >/dev/null 2>&1; then
    mgmt POST /audit/sink '{"enabled":false}' >/dev/null 2>&1 || true
  fi
  # The pool goes first, while kube-loxilb is still there to remove the
  # Service and the rule it derived from it.
  if helm status "$POOL" -n "$LLM_NS" >/dev/null 2>&1; then
    say "uninstall the llm-d Router release $POOL"
    helm uninstall "$POOL" -n "$LLM_NS" --wait >/dev/null || true
    wait_for 120 "the Service derived from $POOL to go" \
      sh -c "! kubectl -n $LLM_NS get svc -l loxilb.io/inference-pool=$POOL --no-headers 2>/dev/null | grep -q ."
  fi
  k delete jwtauthprofile "$KC_PROFILE" --ignore-not-found >/dev/null
  k -n "$LLM_NS" delete deploy "$POOL" --ignore-not-found >/dev/null
  if helm status "$RELEASE" -n "$RELEASE_NS" >/dev/null 2>&1; then
    say "uninstall the gateway release $RELEASE"
    helm uninstall "$RELEASE" -n "$RELEASE_NS" --wait >/dev/null || true
  fi
  k -n "$RELEASE_NS" delete secret aigw-db-dp --ignore-not-found >/dev/null
  k -n "$RELEASE_NS" delete configmap aigw-integration-ca --ignore-not-found >/dev/null
  local ns
  for ns in "$AIGW_NS" "$LLM_NS"; do
    if [ "$(k get ns "$ns" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}' 2>/dev/null)" = igw-testbed ]; then
      say "delete namespace $ns"
      # Waits, so an `up` right after starts on a namespace that is gone.
      k delete ns "$ns" --timeout=300s >/dev/null
    fi
  done
  say "down: done. CRDs and loxilb's node-local snapshot (/etc/loxilb) are left in place"
}

case "$CMD" in
  up)     cmd_up ;;
  test)   cmd_test ;;
  status) cmd_status ;;
  down)   cmd_down ;;
  *)      usage 1 ;;
esac
