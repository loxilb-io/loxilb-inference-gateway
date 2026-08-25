#!/bin/bash

source ../common.sh

echo "#########################################"
echo "Spawning all hosts"
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

config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24

sleep 5

# Fullproxy VIPs must be locally bindable — the sockproxy listener binds the
# VIP itself (no eBPF interception in front of an L7 listen socket). The
# 20.20.20.5 address is added now even though its rule is created
# mid-validation (policy-before-rule leg).
$dexec llb1 ip addr add 20.20.20.3/32 dev lo
$dexec llb1 ip addr add 20.20.20.4/32 dev lo
$dexec llb1 ip addr add 20.20.20.5/32 dev lo

# Fullproxy (L7) rules under shaper test. Two VIPs so per-rule isolation is
# provable; a third VIP (20.20.20.5) is deliberately NOT created here — the
# policy-before-rule leg creates it mid-validation.
create_lb_rule llb1 20.20.20.3 --tcp=2020:8080 --endpoints=31.31.31.1:1 --mode=fullproxy --host=20.20.20.3
create_lb_rule llb1 20.20.20.4 --tcp=2020:8080 --endpoints=31.31.31.1:1 --mode=fullproxy --host=20.20.20.4
