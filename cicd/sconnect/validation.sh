#!/bin/bash
code=0
sizes=( 64 100 500 1000 1500 2000 5000 )

# Prime ARP/ND and bridge FDB for (ns -> target) with retries.
# Retries up to 10 times (~20s) so cold neighbor state recovers from
# INCOMPLETE/FAILED before the measurement ping runs.
#
# $4 names the namespace that owns the target and $5 the source address; both
# are optional and only feed the diagnostics below.
warmup_pair() {
    local ns=$1 target=$2 iface=$3 dstns=$4 src=$5
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if [ -n "$iface" ]; then
            sudo ip netns exec $ns ping $target -c 1 -W 2 -I $iface >/dev/null 2>&1 && return 0
        else
            sudo ip netns exec $ns ping $target -c 1 -W 2 >/dev/null 2>&1 && return 0
        fi
        [ "$i" = 1 ] && diag early "$ns" "$target" "$dstns" "${src:-$iface}" "$iface"
    done
    return 1
}

# ---------------------------------------------------------------------------
# Failure diagnostics
#
# A [NOK] line cannot say which layer lost the packets, and the CI step ends
# with this script's exit status, so nothing else is recorded. When a pair
# stops answering, the helpers below record what the namespaces on the path
# (source, loxilb, destination) and loxilb itself knew at that moment, and
# print it just before the verdict:
#
#   early  the first warmup ping timed out. Collected in the background, so
#          the warmup and the measured pings keep the timing they had.
#   nok    the pair's first [NOK], with three more pings under capture.
#   after  the size loop that produced the [NOK] has finished.
#   final  the end of the run, by when the path has usually recovered.
#
# Diagnostics never change the verdict: a pair is only snapshotted in the
# foreground once it has already failed. Those snapshots take a few seconds,
# so the sizes after a pair's first [NOK] run later than they otherwise would
# and fewer of them may fall inside a short outage.
#
# SCONNECT_DIAG_PAIRS caps how many failing pairs are recorded (default 3,
# 0 turns diagnostics off) and SCONNECT_DIAG_DIR keeps the snapshot files
# instead of deleting them.
# ---------------------------------------------------------------------------
LLB=${SCONNECT_LLB:-llb1}
LLB_REST="http://127.0.0.1:${SCONNECT_LLB_PORT:-11111}/netlox/v1/config"
DIAG_PAIRS_MAX=${SCONNECT_DIAG_PAIRS:-3}
DIAG_DIR=${SCONNECT_DIAG_DIR:-}
diag_own_dir=0
diag_seq=0
declare -A diag_pair=()   # "ns1>target" -> "dstns|src|bind"
declare -A diag_seen=()   # "ns1>target@phase" -> 1
diag_order=()             # pair keys in the order they failed
diag_bg=()

# Run one read-only command for a snapshot. Bounded in time and in output, so
# a stuck tool cannot hang the scenario.
diag_cmd() {
    local title=$1; shift
    echo "--- $title"
    sudo timeout --kill-after=1 5 "$@" 2>&1 | head -n 150
}

# The kernel's view inside one namespace: neighbour states with their timers,
# the route and interface it would use towards each peer, IP/ICMP counters.
diag_netns() {
    local ns=$1 peer dev; shift
    [ -n "$ns" ] || return 0
    diag_cmd "[$ns] ip -4 -s neigh" ip netns exec "$ns" ip -4 -s neigh show
    for peer in "$@"; do
        [ -n "$peer" ] || continue
        diag_cmd "[$ns] ip -4 route get $peer" ip netns exec "$ns" ip -4 route get "$peer"
        dev=$(sudo timeout --kill-after=1 5 ip netns exec "$ns" ip -4 route get "$peer" 2>/dev/null |
            sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1)
        [ -n "$dev" ] && diag_cmd "[$ns] ip -s link show dev $dev" ip netns exec "$ns" ip -s link show dev "$dev"
    done
    diag_cmd "[$ns] nstat IPv4 Ip* Icmp* (absolute, non-zero)" ip netns exec "$ns" nstat -as 'Ip[!6]*' 'Icmp[!6M]*'
}

# loxilb's control-plane tables over REST, one entry per line.
diag_rest() {
    local path=$1 filter=${2:-}
    echo "--- [$LLB] GET /netlox/v1/config/$path${filter:+ (entries matching $filter)}"
    sudo timeout --kill-after=1 5 docker exec "$LLB" curl -s -m 3 "$LLB_REST/$path" 2>&1 |
        sed 's/},{/},\n{/g' | grep -F -e "$filter" | head -n 150
}

# One pinned datapath map. bpftool's JSON is a single line: put one entry per
# line, drop the all-zero slots of array maps and squeeze the byte lists.
diag_bpfmap() {
    echo "--- [$LLB] bpftool map dump $1 (non-zero entries, hex)"
    sudo timeout --kill-after=1 8 docker exec "$LLB" bpftool -j map dump pinned "/opt/loxilb/dp/bpf/$1" 2>&1 |
        sed 's/},{/},\n{/g' | grep -E -v '"value":\[("0x00",?)+\]' |
        sed -E 's/"0x([0-9a-f]{2})",?/\1/g' | head -n 200
}

# Watch ARP and ICMP in every namespace on the path for $2 seconds. In
# "active" mode three pings are sent meanwhile; "passive" observes the
# caller's own.
diag_capture() {
    local out=$1 secs=$2 mode=$3 ns1=$4 target=$5 dstns=$6 bind=$7
    local ns seen=" " pids=()
    if ! command -v tcpdump >/dev/null 2>&1; then
        echo "--- capture skipped: tcpdump is not installed"
        return 0
    fi
    for ns in "$ns1" "$LLB" "$dstns"; do
        [ -n "$ns" ] || continue
        case "$seen" in *" $ns "*) continue ;; esac
        seen="$seen$ns "
        # Through a pipe: tcpdump's AppArmor profile may not write to a file
        # another user owns, and would silently lose a redirected stdout.
        sudo timeout --kill-after=1 "$secs" ip netns exec "$ns" \
            tcpdump --immediate-mode -l -nn -e -i any -c 60 'arp or icmp' 2>&1 |
            cat > "$out.pcap.$ns" &
        pids+=("$!")
    done
    if [ "$mode" = active ]; then
        sleep 0.5
        echo "--- [$ns1] ping $target -c 3 ${bind:+-I $bind }(under capture)"
        sudo timeout --kill-after=1 "$secs" ip netns exec "$ns1" \
            ping "$target" -c 3 -i 0.3 -W 1 ${bind:+-I "$bind"} 2>&1 | tail -n 4
    fi
    wait "${pids[@]}" 2>/dev/null
    for ns in $seen; do
        echo "--- [$ns] tcpdump -i any 'arp or icmp' (${secs}s, $mode)"
        cat "$out.pcap.$ns" 2>/dev/null
        rm -f "$out.pcap.$ns"
    done
}

# Write one snapshot file. $1 phase, $2 file, then the pair.
diag_write() {
    local phase=$1 out=$2 ns1=$3 target=$4 dstns=$5 src=$6 bind=$7
    {
        echo "=== sconnect diag: $phase  $ns1${src:+ ($src)} -> $target${dstns:+ in $dstns}" \
            " t=+${SECONDS}s  $(date -u +%H:%M:%S.%3N)Z  kernel=$(uname -r)"
        [ "$ns1" != "$LLB" ] && diag_netns "$ns1" "$target"
        diag_netns "$LLB" "$target" "$src"
        [ "$dstns" != "$LLB" ] && diag_netns "$dstns" "$src"
        diag_rest neighbor/all
        if [ "$phase" = nok ] || [ "$phase" = after ]; then
            # The connected route and the host routes share the target's /24.
            diag_rest route/all "\"${target%.*}."
            [ -n "$src" ] && diag_rest route/all "\"${src%.*}."
            diag_rest fdb/all
            diag_bpfmap rt_v4_map
            diag_bpfmap nh_map
        fi
        if [ "$phase" = nok ]; then
            # The ARP table and its garbage-collection thresholds are shared
            # by every namespace on the host.
            diag_cmd "[host] /proc/net/stat/arp_cache" cat /proc/net/stat/arp_cache
            diag_cmd "[host] neighbour sysctls" sysctl net.ipv4.neigh.default.gc_thresh1 \
                net.ipv4.neigh.default.gc_thresh2 net.ipv4.neigh.default.gc_thresh3 \
                net.ipv4.neigh.default.gc_stale_time net.ipv4.neigh.default.base_reachable_time_ms
            diag_cmd "[$LLB] forwarding sysctls" ip netns exec "$LLB" sysctl net.ipv4.ip_forward \
                net.ipv4.conf.all.rp_filter net.ipv4.conf.all.arp_accept net.ipv4.conf.all.arp_ignore
            diag_capture "$out" 4 active "$ns1" "$target" "$dstns" "$bind"
        elif [ "$phase" = early ]; then
            diag_capture "$out" 6 passive "$ns1" "$target" "$dstns" "$bind"
        fi
    } > "$out" 2>&1
}

# diag <phase> <ns1> <target> [<dstns> <src> <bind>]
# Take the snapshot of one phase for a pair, at most once. The first call for
# a pair registers it; later calls reuse what was registered.
diag() {
    local phase=$1 ns1=$2 target=$3 key="$2>$3" out dstns src bind
    if [ -z "${diag_pair["$key"]+x}" ]; then
        [ "${#diag_order[@]}" -lt "$DIAG_PAIRS_MAX" ] || return 0
        diag_pair["$key"]="$4|$5|$6"
        diag_order+=("$key")
    fi
    [ -z "${diag_seen["$key@$phase"]+x}" ] || return 0
    diag_seen["$key@$phase"]=1
    if [ -z "$DIAG_DIR" ]; then
        DIAG_DIR=$(mktemp -d) || return 0
        diag_own_dir=1
    fi
    mkdir -p "$DIAG_DIR" || return 0
    IFS='|' read -r dstns src bind <<< "${diag_pair["$key"]}"
    out=$(printf '%s/%02d-%s-%s-%s.txt' "$DIAG_DIR" "$diag_seq" "$phase" "$ns1" "$target")
    diag_seq=$((diag_seq + 1))
    echo "[diag] $phase snapshot: $ns1 -> $target (t=+${SECONDS}s)"
    if [ "$phase" = early ]; then
        diag_write "$phase" "$out" "$ns1" "$target" "$dstns" "$src" "$bind" &
        diag_bg+=("$!")
    else
        diag_write "$phase" "$out" "$ns1" "$target" "$dstns" "$src" "$bind"
    fi
}

# Snapshot once more every pair that produced a [NOK] in the loop just ended.
diag_after() {
    local key
    for key in "${diag_order[@]}"; do
        [ -n "${diag_seen["$key@nok"]+x}" ] || continue
        diag after "${key%%>*}" "${key#*>}"
    done
}

# loxilb's own account: its log lines about the failing addresses, its stderr
# and anything the kernel said about neighbours.
diag_logs() {
    local key pat=()
    for key in "${diag_order[@]}"; do
        pat+=(-e "${key#*>}")
    done
    echo "=== sconnect diag: logs  $(date -u +%H:%M:%S.%3N)Z"
    diag_cmd "[$LLB] /var/log/loxilb*.log lines naming the failing targets" \
        docker exec "$LLB" sh -c 'grep -H -F "$@" /var/log/loxilb*.log | tail -n 150' sh "${pat[@]}"
    diag_cmd "[$LLB] /tmp/loxilb.err (tail)" docker exec "$LLB" tail -n 40 /tmp/loxilb.err
    diag_cmd "[host] dmesg (neighbour table, martians, kernel warnings)" \
        sh -c 'dmesg -T | grep -E "[Nn]eighbour|arp_cache|martian|table overflow|BUG:|WARNING:|Call Trace" | tail -n 30'
}

# Print every snapshot, each in its own foldable group on GitHub Actions.
diag_report() {
    local key f
    [ "${#diag_order[@]}" -gt 0 ] || return 0
    [ "${#diag_bg[@]}" -gt 0 ] && wait "${diag_bg[@]}" 2>/dev/null
    diag_bg=()
    for key in "${diag_order[@]}"; do
        diag final "${key%%>*}" "${key#*>}"
    done
    diag_logs > "$DIAG_DIR/99-logs.txt" 2>&1
    echo -e "********************************************************************"
    echo "sconnect diagnostics: ${#diag_order[@]} pair(s) stopped answering"
    for f in "$DIAG_DIR"/*.txt; do
        [ -n "$GITHUB_ACTIONS" ] && echo "::group::sconnect diag $(basename "$f" .txt)"
        cat "$f"
        [ -n "$GITHUB_ACTIONS" ] && echo "::endgroup::"
    done
}

diag_cleanup() {
    [ "${#diag_bg[@]}" -gt 0 ] && kill "${diag_bg[@]}" 2>/dev/null
    [ "$diag_own_dir" = 1 ] && [ -n "$DIAG_DIR" ] && rm -rf "$DIAG_DIR"
}
trap diag_cleanup EXIT

echo "SCENARIO sconnect"
if [[ $# -gt 0 ]]; then
    nslist=( "$@" )
else
    nslist=( `sudo ip netns | cut -d " " -f 1` )
fi

for ns1 in "${nslist[@]}"; do
    onlyL2=0
    ns1L2=0
	dev1=`sudo ip netns exec $ns1 ip route | grep "default" | cut -d " " -f 5`
    gw1=""
    if [[ -z "$dev1" || "$dev1" == "eth0" ]]
    then
        # No default route present, will try L2 now
        net1=( `sudo ip netns exec $ns1 ip route | grep -v "eth0" | cut -d " " -f 1` )
	    allhosts1=( `sudo ip netns exec $ns1 ip route | grep -v "eth0" cut -d " " -f 9` )
        ns1L2=1
        echo -e "$ns1 can do only L2"
    else
	    hosts1=( `sudo ip netns exec $ns1 ip addr show dev $dev1 | grep -v "eth0" | grep -w inet | cut -d " " -f 6 | cut -d "/" -f 1` )
	    gw1=`sudo ip netns exec $ns1 ip route | grep -v "eth0" | grep "default" | cut -d " " -f 3`
    fi

    if [ ! -z "$gw1" ]
    then
		echo -e "********************************************************************"
		printf "%-16s \t->\t %-16s(Gateway)\n" $ns1 $gw1;
        # Every gateway in this topology is an address of loxilb.
        warmup_pair $ns1 $gw1 "" "$LLB"
        for size in ${sizes[@]}
        do
			sudo ip netns exec $ns1 ping $gw1 -f -c 50 -s $size -W 2 2>&1> /dev/null;
            if [[ $? -eq 0 ]]
			then
			    #echo -e "Ping [OK]"
				#echo -e "Ping (${hosts1[h1]}) \t->\t ($gw1) \t\t: Packet Size : $size :\t[OK]";
			    printf "Ping %-16s \t->\t %-16s \t\t: Packet Size : %-5s :\t[OK]\n" $ns1 $gw1 $size ;
		    else
			    #echo -e "Ping [NOK]"
				#echo -e "Ping (${hosts1[h1]}) \t->\t ($gw1) \t\t: Packet Size : $size :\t[NOK]";
			    printf "Ping %-16s \t->\t %-16s \t\t: Packet Size : %-5s :\t[NOK]\n" $ns1 $gw1 $size ;
                code=1
                diag nok "$ns1" "$gw1" "$LLB" "" ""
	        fi
        done
        diag_after
    fi

	for ns2 in "${nslist[@]}" ; do
		if [ \( "$ns1" = "$ns2" \) -o \( "$ns1" = "loxilb" \) -o \( "$ns2" = "loxilb" \) ]; then 
			continue ;
 		fi;

		echo -e "********************************************************************"
        #Reset onlyL2 flag
        if [ \( $ns1L2 -eq 0 \) -a \( $onlyL2 -eq 1 \) ]
        then
            onlyL2=0
	        hosts1=( `sudo ip netns exec $ns1 ip addr show dev $dev1 | grep -v "eth0" | grep -w inet | cut -d " " -f 6 | cut -d "/" -f 1` )
        fi

		dev2=`sudo ip netns exec $ns2 ip route | grep -v "eth0" | grep "default" | cut -d " " -f 5`
        if [ \( "$dev2" = "" \) -o \( $ns1L2 -eq 1 \) -o \( "$dev2" = "eth0" \) ]
        then
            net1=( `sudo ip netns exec $ns1 ip route | grep -v "eth0" | grep src | cut -d " " -f 1` )
	        allhosts1=( `sudo ip netns exec $ns1 ip route | grep -v "eth0" | grep src | cut -d " " -f 9` )
            onlyL2=1
            echo -e "$ns2 can do only L2 with $ns1"
        fi
		echo -e "$ns1 \t-> $ns2"

        if [ $onlyL2 == 1 ]
        then
            net2=( `sudo ip netns exec $ns2 ip route | grep -v "eth0" | grep src | cut -d " " -f 1` )
	        allhosts2=( `sudo ip netns exec $ns2 ip route | grep -v "eth0" | grep src | cut -d " " -f 9` )
            hosts1=()
            hosts2=()

		    for n1 in "${!net1[@]}"
            do
		        for n2 in "${!net2[@]}"
                do
                    if [ "${net1[n1]}" == "${net2[n2]}" ]
                    then
                        hosts1+=("${allhosts1[$n1]}")
                        hosts2+=("${allhosts2[$n2]}")
                        #echo -e "${net1[n1]}" == "${net2[n2]}"
                        #echo -e "${allhosts1[n1]} and ${allhosts2[n2]}"
                    fi
                done
            done
            for h1 in "${!hosts1[@]}"
            do
                warmup_pair $ns1 ${hosts2[h1]} "" "$ns2" "${hosts1[h1]}"
            done
            for size in ${sizes[@]}
            do
		        for h1 in "${!hosts1[@]}"
		        do
				    sudo ip netns exec $ns1 ping ${hosts2[h1]} -f -c 50 -s $size -W 2 2>&1> /dev/null;
				    if [[ $? -eq 0 ]]
				    then
				        #echo -e "Ping [OK]"
			            #echo -e "Ping (${hosts1[h1]}) \t->\t (${hosts2[h1]}) \t\t: Packet Size : $size :\t[OK]";
			            printf "Ping %-16s \t->\t %-16s \t\t: Packet Size : %-5s :\t[OK]\n" ${hosts1[h1]} ${hosts2[h1]} $size ;
				    else
				        #echo -e "Ping [NOK]"
			            #echo -e "Ping (${hosts1[h1]}) \t->\t (${hosts2[h1]}) \t\t: Packet Size : $size :\t[NOK]";
			            printf "Ping %-16s \t->\t %-16s \t\t: Packet Size : %-5s :\t[NOK]\n" ${hosts1[h1]} ${hosts2[h1]} $size ;
                        code=1
                        diag nok "$ns1" "${hosts2[h1]}" "$ns2" "${hosts1[h1]}" ""
				    fi
		        done
            done
            diag_after

        else    
		    dev2=`sudo ip netns exec $ns2 ip route | grep -v "eth0" | grep "default" | cut -d " " -f 5`
		    hosts2=( `sudo ip netns exec $ns2 ip addr show dev $dev2 | grep -v "eth0" | grep -w inet | cut -d " " -f 6 | cut -d "/" -f 1` )
            for h1 in "${hosts1[@]}"
            do
                for h2 in "${hosts2[@]}"
                do
                    warmup_pair $ns1 $h2 $h1 "$ns2"
                done
            done
            for size in ${sizes[@]}
            do
		        for h1 in "${hosts1[@]}"
		        do
			        for h2 in "${hosts2[@]}"
			        do
				        sudo ip netns exec $ns1 ping $h2 -f -c 50 -I $h1 -s $size -W 2 2>&1> /dev/null;
				        if [[ $? -eq 0 ]]
				        then
					        #echo -e "Ping [OK]"
				            #echo -e "Ping ($h1) \t-> \t($h2) \t\t: Packet Size : $size :\t[OK]";
			                printf "Ping %-16s \t->\t %-16s \t\t: Packet Size : %-5s :\t[OK]\n" $h1 $h2 $size ;
				        else
					        #echo -e "Ping [NOK]"
				            #echo -e "Ping ($h1) \t-> \t($h2) \t\t: Packet Size : $size :\t[NOK]";
			                printf "Ping %-16s \t->\t %-16s \t\t: Packet Size : %-5s :\t[NOK]\n" $h1 $h2 $size ;
                            code=1
                            diag nok "$ns1" "$h2" "$ns2" "$h1" "$h1"
				        fi
			        done
		        done
            done
            diag_after
        fi
	done
done
diag_report
echo -e "********************************************************************"
if [[ $code == 0 ]]
then
    echo SCENARIO-sconnect [OK]
else
    echo SCENARIO-sconnect [FAILED]
fi

exit $code
