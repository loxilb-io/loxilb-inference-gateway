#!/bin/bash
# k3d-incluster-inference-gwapi — bring-up.
# Same in-cluster topology as ../k3d-incluster-inference-svc, but inference is
# asked for through the Gateway API: an InferencePool referenced from an
# HTTPRoute, served by kube-loxilb --gatewayAPI --inferenceExtension.
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../common/k8s-inference/k3d_common.sh"

igw_cluster_up igw-gwapi          || exit 1
igw_prepare_images                || exit 1
igw_import_images                 || exit 1
say "loxilb (in-cluster DaemonSet)";  igw_deploy_loxilb       || exit 1
say "mock vLLM servers";              igw_deploy_mock         || exit 1
say "Gateway API $GWAPI_VERSION + Inference Extension $GIE_VERSION CRDs"
igw_install_gwapi_crds            || exit 1
say "kube-loxilb (--gatewayAPI --inferenceExtension)"
igw_deploy_kube_loxilb --gatewayAPI --inferenceExtension || exit 1
say "client container";               igw_client_up           || exit 1
say "gateway resources"
kubectl apply -f "$HERE/fixtures/gatewayclass.yaml" -f "$HERE/fixtures/gateway.yaml" >/dev/null || exit 1
kubectl apply -f "$HERE/fixtures/inferencepool.yaml" -f "$HERE/fixtures/httproute.yaml" >/dev/null || exit 1
igw_env_save "$HERE"
say "testbed up (gateway address $NODE_IP)"
