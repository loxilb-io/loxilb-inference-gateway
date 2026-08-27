#!/bin/bash
# k3d-incluster-inference-svc — bring-up.
# loxilb + kube-loxilb as Pods in a single-node k3d cluster; inference is asked
# for through Service annotations (no Gateway API involved).
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../common/k8s-inference/k3d_common.sh"

igw_cluster_up igw-svc            || exit 1
igw_prepare_images                || exit 1
igw_import_images                 || exit 1
say "loxilb (in-cluster DaemonSet)";      igw_deploy_loxilb      || exit 1
say "mock vLLM servers";                  igw_deploy_mock        || exit 1
say "kube-loxilb";                        igw_deploy_kube_loxilb || exit 1
say "client container";                   igw_client_up          || exit 1
say "annotated services"
kubectl apply -f "$HERE/svc-chwbl.yaml" -f "$HERE/svc-invalid.yaml" >/dev/null || exit 1
igw_env_save "$HERE"
say "testbed up (VIP $NODE_IP)"
