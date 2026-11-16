#!/bin/bash

source ../common.sh

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1

echo "#########################################"
echo "Connecting and configuring  hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1

sleep 5

#L3 config
config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24

sleep 5

# The full-proxy listener uses TLS when checking frontend mTLS readback.
cert_dir=$(mktemp -d) || exit 1
trap 'rm -rf -- "$cert_dir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=lbreplace.test' \
    -keyout "$cert_dir/server.key" -out "$cert_dir/server.crt" || exit 1
sudo docker cp "$cert_dir/server.crt" llb1:/opt/loxilb/cert/server.crt || exit 1
sudo docker cp "$cert_dir/server.key" llb1:/opt/loxilb/cert/server.key || exit 1

# The rules are created by validation.sh: what it checks is the answer to
# each request, starting with the create.
