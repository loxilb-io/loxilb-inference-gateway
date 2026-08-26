#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../common.sh
exec < /dev/null

for ep in l3ep1 l3ep2 l3ep3; do
  $dexec $ep pkill -f 'mock_llamacpp.py' 2>/dev/null
  $dexec $ep pkill -f 'mock_trtllm.py' 2>/dev/null
  $dexec $ep pkill -f 'mock_sglang_pd.py' 2>/dev/null
  $dexec $ep pkill -f 'mock_vllm.py' 2>/dev/null
done

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep2 llb1
disconnect_docker_hosts l3ep3 llb1

delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2
delete_docker_host l3ep3
delete_docker_host llb1

rm -rf 10.10.10.254/ minica.pem minica-key.pem 2>/dev/null
