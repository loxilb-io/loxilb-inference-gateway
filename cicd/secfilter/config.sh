#!/bin/bash

source ../common.sh

# Enable the prometheus collector thread so /metrics exposes the security series.
extra_opts="-p"

echo "#########################################"
echo "Spawning all hosts (secfilter)"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1

sleep 5

# L3 config: l3h1 is the client, l3ep1 the backend
config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24

sleep 5
# A single TCP LB VIP the client will hit; ipfilter runs at XDP ingress before it.
create_lb_rule llb1 20.20.20.1 --tcp=2020:8080 --endpoints=31.31.31.1:1
