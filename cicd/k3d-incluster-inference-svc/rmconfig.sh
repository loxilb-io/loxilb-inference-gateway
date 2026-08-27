#!/bin/bash
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../common/k8s-inference/k3d_common.sh"
igw_teardown igw-svc "$HERE"
echo "testbed removed"
