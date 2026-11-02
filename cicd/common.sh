#!/bin/bash

if [[ "${1:-}" == "init" ]]; then
  pull_dockers
fi

hn="netns"
pid=""
vrn="/var/run/"
hexec="sudo ip netns exec "
dexec="sudo docker exec -i "

# ---------------------------------------------------------------------------
# Scenario helpers are stopped BY PID, never by process name.
#
# WHY: `hexec` is `ip netns exec`, which shares only the NETWORK namespace. A
# helper launched that way keeps the host's pid namespace, so `killall -9 node`
# or `pkill -f <name>` reaches every matching process on the runner — other
# scenarios' backends and the operator's own. The scenarios that do this run
# sequentially today, which hides it, but it also MASKS the leak detector: a
# scenario that sweeps up a neighbour's leftovers ensures the neighbour's leak
# is never reported.
#
# WHY NOT `docker exec`: the helpers are not container processes. They are host
# processes that merely borrow the container's netns, and their binaries (e.g.
# ../common/http2/http-server/http-server) do not exist inside the image at all,
# so `docker exec <c> pkill ...` cannot see them.
#
# WHY TWO KILLS: `$!` after `$hexec ... &` is the root-owned `sudo` wrapper, not
# the workload — `ip netns exec` execs the command, so the workload is sudo's
# direct child. Measured: $! -> `sudo` (root), its child -> the real process.
# A non-root kill on the wrapper fails, and killing the wrapper first orphans
# the workload. So: children first, then the wrapper, both under sudo.
# ---------------------------------------------------------------------------
# The record is a FILE, not just a variable: a scenario launches its helpers in
# validation.sh and often stops them in rmconfig.sh, which is a separate
# process. Each entry is "pid starttime", where starttime is field 22 of
# /proc/<pid>/stat. The starttime is what makes a stale record safe: pids are
# recycled, and a leftover file must never let a later run kill whatever
# process happens to hold that number now.
LOXI_HELPER_PIDFILE="${LOXI_HELPER_PIDFILE:-.loxi-helpers.pid}"

_loxi_starttime() { awk '{print $22}' "/proc/$1/stat" 2>/dev/null; }

# track_helper [pid] — record a backgrounded helper. Defaults to $!, so the
# idiom is a bare `track_helper` on the line after the launch.
track_helper() {
  local p="${1:-$!}" st
  [[ -n "$p" ]] || return 0
  st=$(_loxi_starttime "$p")
  [[ -n "$st" ]] || return 0          # already gone; nothing to track
  printf '%s %s\n' "$p" "$st" >> "$LOXI_HELPER_PIDFILE" 2>/dev/null
  return 0
}

# stop_helpers — stop every tracked helper, then forget them. Safe to call more
# than once, and safe when nothing was tracked.
stop_helpers() {
  local p st now
  [[ -f "$LOXI_HELPER_PIDFILE" ]] || return 0
  while read -r p st; do
    [[ -n "$p" ]] || continue
    now=$(_loxi_starttime "$p")
    # Gone, or the number belongs to a different process now: leave it alone.
    [[ -n "$now" && "$now" == "$st" ]] || continue
    # Children first: $! after `$hexec ... &` is the root-owned sudo wrapper and
    # the workload is its child, so killing the wrapper first would orphan it.
    sudo pkill -9 -P "$p" 2>/dev/null
    sudo kill  -9    "$p" 2>/dev/null
  done < "$LOXI_HELPER_PIDFILE"
  rm -f "$LOXI_HELPER_PIDFILE" 2>/dev/null
  return 0
}
hns="sudo ip netns "
hexist="$vrn$hn"
lxdocker="ghcr.io/loxilb-io/loxilb-inference-gateway:main"
hostdocker="ghcr.io/loxilb-io/nettest:latest"
cluster_opts=""
extra_opts=""
ka_opts=""
docker_extra_opts=""
# Prometheus metrics are a first-class feature: enable them by default so every
# scenario can scrape GET /netlox/v1/metrics (else that endpoint returns 503
# "Prometheus option is disabled."). Set prom_opts="" before spawn_docker_host
# to opt a scenario out.
prom_opts="-p"
var=$(lsb_release -r | cut -f2)
if [[ $var == *"22.04"* ]];then
 lxdocker="ghcr.io/loxilb-io/loxilb-inference-gateway:main"
fi
var=$(lsb_release -r | cut -f2)
if [[ $var == *"24.04"* ]];then
 lxdocker="ghcr.io/loxilb-io/loxilb-inference-gateway:main-u24"
fi

# Allow callers (e.g. CI workflows) to override the auto-detected image.
# LOXILB_DOCKER_IMAGE takes precedence: set a full image ref, or a bare tag
# (e.g. "main") to pin the loxilb-inference-gateway repo to that tag.
# Use case: the main-u24 image trips the eBPF verifier E2BIG limit on
# hosted ubuntu-24.04 (6.x-azure) runners, so those workflows force :main.
if [[ -n "${LOXILB_DOCKER_IMAGE:-}" ]]; then
  if [[ "$LOXILB_DOCKER_IMAGE" == *"/"* || "$LOXILB_DOCKER_IMAGE" == *":"* ]]; then
    lxdocker="$LOXILB_DOCKER_IMAGE"
  else
    lxdocker="ghcr.io/loxilb-io/loxilb-inference-gateway:$LOXILB_DOCKER_IMAGE"
  fi
fi


if [ ! -d loxilb.io ]; then
  ../common/minica --domains loxilb.io
  mkdir cert
  cp minica.pem cert/rootCA.crt
  cp loxilb.io/cert.pem cert/server.crt
  cp loxilb.io/key.pem cert/server.key
fi

loxilbs=()

## Given a docker name(arg1), return its pid
get_docker_pid() {
  id=`docker ps -f name=$1| grep -w $1 | cut  -d " "  -f 1 | grep -iv  "CONTAINER"`
  pid=`docker inspect -f '{{.State.Pid}}' $id`
}

## Pull all necessary dockers for testbed
pull_dockers() {
  ## loxilb docker
  docker pull $lxdocker
  ## Host docker 
  docker pull docker pull $hostdocker
  ## BGP host docker
  docker pull ewindisch/quagga
}

## REST readiness probe for a loxilb container (issue #423).
##
## On hosted ubuntu-24.04 runners the first `loxicmd` of a scenario sometimes
## times out against a loxilb spawned 17-27 s earlier, and the logs cannot tell
## a slow start from a loxilb that died or hung. After spawning a loxilb this
## polls GET /netlox/v1/version from inside the container and prints one
## `[rest-probe]` line with the time to the first answer. If nothing answers
## within the deadline it prints the container state, the loxilb process list
## and the tails of /tmp/loxilb.err and /tmp/loxilb.out.
##
##   LOXILB_REST_PROBE       log  (default) wait, report, never fail
##                           fail wait, report, exit 1 on timeout
##                           off  skip the probe
##   LOXILB_REST_PROBE_SECS  deadline in seconds (default 60)
##
## The URL follows the loxilb flags in extra_opts: --port N and --tls.
## arg1 - loxilb instance name; arg2 - epoch seconds of its spawn
probe_loxilb_rest() {
  local name="$1" t0="$2" mode="${LOXILB_REST_PROBE:-log}"
  local deadline="${LOXILB_REST_PROBE_SECS:-60}"
  local port=11111 scheme=http curl_tls="" url now elapsed
  [[ "$mode" == "off" ]] && return 0
  if [[ "$extra_opts" =~ (^|[[:space:]])--port[=[:space:]]+([0-9]+) ]]; then
    port="${BASH_REMATCH[2]}"
  fi
  case " $extra_opts " in
    *" --tls "*|*" --tls="*) scheme=https; curl_tls="-k" ;;
  esac
  url="$scheme://127.0.0.1:$port/netlox/v1/version"
  while :; do
    if $dexec "$name" curl -sf -m 2 $curl_tls -o /dev/null "$url" 2>/dev/null; then
      now=$(date +%s); elapsed=$(( now - t0 ))
      echo "[rest-probe] name=$name ready=1 after=${elapsed}s url=$url image=$lxdocker kernel=$(uname -r)"
      return 0
    fi
    now=$(date +%s); elapsed=$(( now - t0 ))
    if (( elapsed >= deadline )); then
      break
    fi
    sleep 1
  done
  echo "[rest-probe] name=$name ready=0 after=${elapsed}s url=$url image=$lxdocker kernel=$(uname -r) mode=$mode"
  echo "[rest-probe] --- docker ps ($name)"
  docker ps -a --filter "name=^/${name}\$" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' 2>&1 || true
  echo "[rest-probe] --- processes and listeners in $name"
  $dexec "$name" bash -c 'pgrep -a loxilb || echo "no loxilb process"; (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null) | head -n 20' 2>&1 || true
  # A crashed process says why at the HEAD of its stderr (the signal, the
  # cgo frame, the first goroutine); the tail is the end of the dump.
  echo "[rest-probe] --- /tmp/loxilb.err (head) in $name"
  $dexec "$name" head -n 80 /tmp/loxilb.err 2>&1 || true
  echo "[rest-probe] --- /tmp/loxilb.err (tail) in $name"
  $dexec "$name" tail -n 40 /tmp/loxilb.err 2>&1 || true
  echo "[rest-probe] --- /tmp/loxilb.out (tail) in $name"
  $dexec "$name" tail -n 20 /tmp/loxilb.out 2>&1 || true
  echo "[rest-probe] --- end of dump ($name)"
  if [[ "$mode" == "fail" ]]; then
    echo "FATAL: loxilb REST API of $name never answered within ${deadline}s"
    exit 1
  fi
  return 0
}

# Docker resolves short arguments as either names or ID prefixes. A missing
# host named c1 must never resolve to a different container whose ID starts c1.
# Verify the exact name, then mutate by full ID to avoid a second name lookup.
loxi_exact_container_id() {
  local record actual_name container_id
  record=$(docker container inspect --format '{{.Name}} {{.Id}}' "$1" 2>/dev/null) || return 1
  read -r actual_name container_id <<< "$record"
  [[ "$actual_name" == "/$1" && "$container_id" =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s\n' "$container_id"
}

## Creates a docker host
## arg1 - "loxilb"|"host"
## arg2 - instance-name
spawn_docker_host() {
  POSITIONAL_ARGS=()
  local bpath
  local kpath
  local ka
  local bgp
  while [[ $# -gt 0 ]]; do
  case "$1" in
    -t | --dock-type )
      dtype="$2"
      shift 2
      ;;
    -d | --dock-name )
      dname="$2"
      shift 2
      ;;
    -b | --with-bgp )
      if [[ "$2" == "yes" ]]; then
          bgp=$2
      fi
      shift 2
      ;;
    -c | --bgp-config )
      bpath="$2"
      bgp="yes"
      shift 2
      ;;
    -k | --with-ka )
      ka="in"
      if [[ "$2" == "out" ]]; then
          ka=$2
      fi
      shift 2
      ;;
    -n | --ka-config )
      kpath="$2"
      if [[ -z ${ka+x} ]]; then
        ka="in"
      fi
      shift 2
      ;;
    -e | --extra-args)
      extra_opts="$2"
      shift 2
      ;;
    -x | --docker-args)
      docker_extra_opts="$2"
      shift 2
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit
      ;;
  esac
  done  
  set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters
  echo "Spawning $dname($dtype)" >&2
  # Idempotency guard: a prior scenario that failed to tear down (or a killed
  # run) can leave a same-named container + stale netns registration behind.
  # Reusing them silently corrupts this scenario (name/IP conflicts, a backend
  # that never restarts) and shows up as a long hang rather than a clear error.
  # Purge any stale namesake so every spawn starts from a clean slate; both
  # commands are no-ops when the environment is already clean.
  local stale_container_id
  if stale_container_id=$(loxi_exact_container_id "$dname"); then
    echo "  (removing stale container $dname left by a previous run)" >&2
    docker rm -f "$stale_container_id" >/dev/null 2>&1 || true
  fi
  if [ -f "$hexist/$dname" ]; then
    $hns del "$dname" >/dev/null 2>&1 || true
    sudo rm -f "$hexist/$dname" >/dev/null 2>&1 || true
  fi
  if [[ "$dtype" == "loxilb" ]]; then
    loxilbs+=("$dname")
    if [[ "$pick_config" == "yes" ]]; then
        echo "$dname will pick config from $(pwd)/${dname}_config"
        loxilb_config="-v $(pwd)/${dname}_config:/etc/loxilb/"
    fi
    if [[ "$bgp" == "yes" ]]; then
      bgp_opts="-b"
      if [[ ! -z "$bpath" ]]; then
        bgp_conf="-v $bpath:/etc/gobgp/"
      fi
    fi
    # The datapath's per-request receipts (prefix extraction, fallback and
    # stream markers in /var/log/loxilbdp.log) are emitted at debug and
    # several suites assert on them. The shipped default level is info, so
    # the harness asks for debug unless the suite sets its own level.
    case " $extra_opts " in
      *" --loglevel "*|*" --loglevel="*) ;;
      *) extra_opts="$extra_opts --loglevel debug" ;;
    esac
    if [[ ! -z ${ka+x} ]]; then
      sudo mkdir -p /etc/shared/$dname/
      docker run -u root --cap-add SYS_ADMIN   --restart unless-stopped --privileged -dt $docker_extra_opts --entrypoint /bin/bash $bgp_conf -v /dev/log:/dev/log -v /etc/shared/$dname:/etc/shared $loxilb_config --name $dname $lxdocker
      get_llb_peerIP $dname
      loxilb_spawn_t0=$(date +%s)
      docker exec -d $dname bash -c "/root/loxilb-io/loxilb/loxilb $bgp_opts $cluster_opts $ka_opts $prom_opts $extra_opts > /tmp/loxilb.out 2> /tmp/loxilb.err"
    else
      docker run -u root --cap-add SYS_ADMIN   --restart unless-stopped --privileged -dt $docker_extra_opts --entrypoint /bin/bash $bgp_conf -v /dev/log:/dev/log -v `pwd`/cert:/opt/loxilb/cert/ $loxilb_config --name $dname $lxdocker $bgp_opts
      loxilb_spawn_t0=$(date +%s)
      docker exec -d $dname bash -c "/root/loxilb-io/loxilb/loxilb $bgp_opts $cluster_opts $prom_opts $extra_opts > /tmp/loxilb.out 2> /tmp/loxilb.err"
    fi
  elif [[ "$dtype" == "host" ]]; then
    if [[ ! -z "$bpath" ]]; then
      bgp_conf="--volume $bpath:/etc/quagga" 
    fi
    if [[ "$bgp" == "yes" || ! -z "$bpath" ]]; then
      docker run -u root --cap-add SYS_ADMIN  --restart unless-stopped --privileged -dit $bgp_conf --name $dname ewindisch/quagga
    else
      docker run -u root --cap-add SYS_ADMIN -dit --name $dname $hostdocker
    fi
  elif [[ "$dtype" == "seahost" ]]; then
      docker run -u root --cap-add SYS_ADMIN -i -t --rm --detach --entrypoint /bin/bash --name $dname  ghcr.io/loxilb-io/seagull:ubuntu1804
  elif [[ "$dtype" == "reflect-echo" ]]; then
      # Header-reflecting echo backend. Image built via cicd/common/reflect-echo/docker-build.sh
      # (ghcr.io/loxilb-io/reflect-echo:latest); behaviour is driven per-container via -e env
      # (ECHO_NAME/HEALTHZ_CODE/SLOW_MS/LISTEN_PORT) passed through --docker-args (docker_extra_opts).
      # shellcheck disable=SC2086
      docker run -u root --cap-add SYS_ADMIN --privileged -dit --rm --detach $docker_extra_opts --name $dname ghcr.io/loxilb-io/reflect-echo:latest
  elif [[ "$dtype" == "grpc-h2server" ]]; then
      docker run -u root --cap-add SYS_ADMIN -i -t --rm -v `pwd`/cert:/certs --detach --name $dname  ghcr.io/loxilb-io/grpc-h2server:latest
  elif [[ "$dtype" == "grpc-h2client" ]]; then
      docker run -u root --cap-add SYS_ADMIN -i -t --rm -v `pwd`/cert:/certs --detach --name $dname  ghcr.io/loxilb-io/grpc-h2client:latest
  elif [[ "$dtype" == "mcp-server" ]]; then
      docker run -u root --cap-add SYS_ADMIN -i -t --rm -v `pwd`/cert:/certs --detach --name $dname  ghcr.io/loxilb-io/mcp-server:latest
  elif [[ "$dtype" == "mcp-hserver" ]]; then
      docker run -u root --cap-add SYS_ADMIN -i -t --rm -v `pwd`/cert:/certs --detach --name $dname  ghcr.io/loxilb-io/mcp-server-https:latest
  elif [[ "$dtype" == "mcp-client" ]]; then
      docker run -u root --cap-add SYS_ADMIN -i -t --rm -v `pwd`/cert:/certs --detach --name $dname  ghcr.io/loxilb-io/mcp-client:latest
  elif [[ "$dtype" == "vllm-server" ]]; then
      # Real vLLM backend (OpenAI-compatible). Mounts /tmp/hf-cache if pre-warmed;
      # otherwise the model downloads from HuggingFace at container startup.
      _hf_vol=""
      if [[ -d /tmp/hf-cache ]]; then _hf_vol="-v /tmp/hf-cache:/root/.cache/huggingface"; fi
      # shellcheck disable=SC2086
      docker run -u root --cap-add SYS_ADMIN --cap-add SYS_NICE --security-opt seccomp=unconfined --shm-size=4g -i -t --rm --detach --name $dname $_hf_vol ghcr.io/loxilb-io/vllm-server:latest
  fi

  pid=""

  sleep 2
  get_docker_pid $dname
  echo $pid
  if [ ! -f "$hexist/$dname" -a "$pid" != "" ]; then
    sudo mkdir -p /var/run/netns  
    sudo touch /var/run/netns/$dname
    #echo "sudo mount -o bind /proc/$pid/ns/net /var/run/netns/$2"
    sudo mount -o bind /proc/$pid/ns/net /var/run/netns/$dname
  fi

  $hexec $dname ip link set lo up
  $hexec $dname sysctl net.ipv6.conf.all.disable_ipv6=1 2>&1 >> /dev/null
  #$hexec $dname sysctl net.ipv4.conf.all.arp_accept=1 2>&1 >> /dev/null
  if [ -f /proc/sys/net/ipv4/conf/eth0/arp_ignore ]; then
    $hexec $dname sysctl net.ipv4.conf.eth0.arp_ignore=2 2>&1 >> /dev/null
  fi
  if [[ "$dtype" == "loxilb" ]]; then
    probe_loxilb_rest "$dname" "$loxilb_spawn_t0"
  fi
}

## Get loxilb peer docker IP
get_llb_peerIP() {
   if [[ "$1" == "llb1" ]]; then
      # Try new format first (Networks map), then fall back to old format
      llb1IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' llb1 2>/dev/null)
      if [[ -z "$llb1IP" ]]; then
        llb1IP=$(docker inspect --format='{{.NetworkSettings.IPAddress}}' llb1 2>/dev/null)
      fi
      if [[ "lb$llb1IP" == "lb" ]] || [[ -z "$llb1IP" ]]; then
        llb1IP="172.17.0.2"
        llb2IP="172.17.0.3"
      else
        read A B C D <<<"${llb1IP//./ }"
        llb2IP="$A.$B.$C.$((D+1))"
      fi
      cluster_opts=" --cluster=$llb2IP --self=0"
      ka_opts=" --ka=$llb2IP:$llb1IP"
    elif [[ "$1" == "llb2" ]]; then
      # Try new format first (Networks map), then fall back to old format
      llb2IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' llb2 2>/dev/null)
      if [[ -z "$llb2IP" ]]; then
        llb2IP=$(docker inspect --format='{{.NetworkSettings.IPAddress}}' llb2 2>/dev/null)
      fi
      if [[ "lb$llb2IP" == "lb" ]] || [[ -z "$llb2IP" ]]; then
        llb1IP="172.17.0.2"
        llb2IP="172.17.0.3"
      else
        read A B C D <<<"${llb2IP//./ }"
        llb1IP="$A.$B.$C.$((D - 1))"
      fi
      cluster_opts=" --cluster=$llb1IP --self=1"
      ka_opts=" --ka=$llb1IP:$llb2IP"
    fi
}

## Deletes a docker host
## arg1 - hostname 
delete_docker_host() {
  local target_container_id ka_container_id
  target_container_id=$(loxi_exact_container_id "$1") || target_container_id=""
  dcmd="kill"
  if [[ $1 == "llb"* ]] || [[ $1 == "loxilb"* ]]; then
    dcmd="stop"
  fi
  # `cmd 2>&1 >> /dev/null` is the WRONG redirect order: it first points stderr at the
  # CURRENT stdout (the terminal / the caller's capture) and only THEN sends stdout to
  # /dev/null — so stderr leaks onto stdout and an outer `2>/dev/null` on the call site
  # cannot suppress it either. That is why an idempotent teardown printed
  #   Error response from daemon: cannot kill container: r1: No such container: r1
  # on every run where the optional (vrrp/HA) hosts were never spawned. `>/dev/null 2>&1`
  # is the intended order and keeps the same exit status the `if` below tests.
  if [[ -n "$target_container_id" ]] && docker "$dcmd" "$target_container_id" >/dev/null 2>&1
  then
    hd="true"
    loxilbs=( "${loxilbs[@]/$1}" )
    if ka_container_id=$(loxi_exact_container_id "ka_$1"); then
      docker kill "$ka_container_id" >/dev/null 2>&1
      docker rm "$ka_container_id" >/dev/null 2>&1
    fi
  fi
  if [ -f "$hexist/$1" ]; then
    $hns del $1 >/dev/null 2>&1 || true
    sudo rm -fr "$hexist/$1" >/dev/null 2>&1
  fi
  if [[ -n "$target_container_id" ]]; then
    docker rm "$target_container_id" >/dev/null 2>&1 || true
  fi
}

## Connects two docker hosts
## arg1 - hostname1 
## arg2 - hostname2 
## arg3 - mtu
connect_docker_hosts() {
  link1=e$1$2
  link2=e$2$1

  mtu="9000"
  if [[ $# -gt 2 ]]; then
    mtu=$3
  fi

  #echo $link1 $link2
  sudo ip -n $1 link add $link1 type veth peer name $link2 netns $2
  sudo ip -n $1 link set $link1 mtu $mtu up
  sudo ip -n $2 link set $link2 mtu $mtu up
}

## arg1 - hostname1 
## arg2 - hostname2 
disconnect_docker_hosts() {
  link1=e$1$2
  link2=e$2$1
  #  echo $link1 $link2
  if [ -f "$hexist/$1" ]; then
    ifexist1=`sudo ip -n $1 link show $link1 | grep -w $link1`
    if [ "chk$ifexist1" != "chk" ]; then
      sudo ip -n $1 link set $link1 down 2>&1 >> /dev/null
      sudo ip -n $1 link del $link1 2>&1 >> /dev/null
    fi
  fi

  if [ -f "$hexist/$2" ]; then
    ifexist2=`sudo ip -n $2 link show | grep -w $link2`
    if [ "chk$ifexist2" != "chk" ]; then
      sudo ip -n $2 link set $link2 down 2>&1 >> /dev/null
      sudo ip -n $2 link del $link2 2>&1 >> /dev/null
    fi
  fi
}

## arg1 - hostname1 
## arg2 - hostname2 
## arg3 - ip_addr
## arg4 - gw
config_docker_host() {
  POSITIONAL_ARGS=()
  while [[ $# -gt 0 ]]; do
    case $1 in
        --host1)
            local h1="$2"
            shift
            shift
            ;;
        --host2)
            local h2="$2"
            shift
            shift
            ;;
        --ptype)
            local ptype="$2"
            shift
            shift
            ;;
        --id)
            local xid="$2"
            shift
            shift
            ;;
        --addr)
            local addr="$2"
            shift
            shift
            ;;
        --gw)
            local gw="$2"
            shift
            shift
            ;;
        -*|--*)
            echo "Unknown option $1"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1") # save positional arg
            shift # past argument
            ;;
    esac
  done
  set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

  link1=e$h1$h2
  link2=e$h2$h1
  #echo "$h1:$link1->$h2:$link2"

  #if [[ -n "${loxilbs[$h1]}" && "$pick_config" == "yes" ]]; then
  if [[ ${loxilbs[*]} =~ (^|[[:space:]])$h1($|[[:space:]]) && "$pick_config" == "yes" ]]; then
    return
  fi

  if [[ "$ptype" == "phy" ]]; then
    sudo ip -n $h1 addr add $addr dev $link1
  elif [[ "$ptype" == "vlan" ]]; then
    sudo ip -n $h1 addr add $addr dev vlan$xid
  elif [[ "$ptype" == "vxlan" ]]; then
    sudo ip -n $h1 addr add $addr dev vxlan$xid
  elif [[ "$ptype" == "trunk" ]]; then
    trunk="bond$xid"
    sudo ip -n $h1 link set $link1 down
    sudo ip -n $h1 link add $trunk type bond
    sudo ip -n $h1 link set $link1 master $trunk
    sudo ip -n $h1 link set $link1 up
    sudo ip -n $h1 link set $trunk up

    sudo ip -n $h2 link set $link2 down
    sudo ip -n $h2 link add $trunk type bond
    sudo ip -n $h2 link set $link2 master $trunk
    sudo ip -n $h2 link set $link2 up
    sudo ip -n $h2 link set $trunk up

    sudo ip -n $h1 addr add $addr dev bond$xid
    if [[ "$gw" != "" ]]; then
      sudo ip -n $h2 addr add $gw/24 dev bond$xid
      sudo ip -n $h1 route add default via $gw proto static
    fi
  else
    echo "Check port-type"
  fi

  if [[ "$gw" != "" ]]; then
    sudo ip -n $h1 route del default 2>&1 >> /dev/null
    sudo ip -n $h1 route add default via $gw
  fi
}

## arg1 - hostname1 
## arg2 - hostname2 
## arg3 - vlan
## arg4 - tagged/untagged
create_docker_host_vlan() {
  local addr=""
  POSITIONAL_ARGS=()
  while [[ $# -gt 0 ]]; do
    case $1 in
        --host1)
            local h1="$2"
            shift
            shift
            ;;
        --host2)
            local h2="$2"
            shift
            shift
            ;;
        --ptype)
            local ptype="$2"
            shift
            shift
            ;;
        --id)
            local vid="$2"
            shift
            shift
            ;;
        --addr)
            addr="$2"
            shift
            shift
            ;;
        -*|--*)
            echo "Unknown option $1"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1") # save positional arg
            shift # past argument
            ;;
    esac
  done

  if [[ ${loxilbs[*]} =~ (^|[[:space:]])$h1($|[[:space:]]) && "$pick_config" == "yes" ]]; then
    return
  fi

  set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters
  link1=e$h1$h2
  link2=e$h2$h1

  #echo "$h1:$link1->$h2:$link2"

  if [[ "$ptype" == "tagged" ]]; then
      brport="$link1.$vid"
      sudo ip -n $h1 link add link $link1 name $brport type vlan id $vid
      sudo ip -n $h1 link set $brport up
  else
      brport=$link1
  fi
    
  sudo ip -n $h1 link add vlan$vid type bridge 2>&1 | true
  sudo ip -n $h1 link set $brport master vlan$vid
  sudo ip -n $h1 link set vlan$vid up
  if [[ "$addr" != "" ]]; then
    sudo ip -n $h1 addr add $addr dev vlan$vid
  fi
}

## arg1 - hostname1 
## arg2 - hostname2 
## arg3 - vxlan-id
## arg4 - phy/vlan
## arg5 - local ip if arg4 is phy/vlan-id if arg4 is vlan
## arg6 - local ip if arg4 is vlan
create_docker_host_vxlan() {
  POSITIONAL_ARGS=()
  while [[ $# -gt 0 ]]; do
    case $1 in
        --host1)
            local h1="$2"
            shift
            shift
            ;;
        --host2)
            local h2="$2"
            shift
            shift
            ;;
        --uif)
            local uifType="$2"
            shift
            shift
            ;;
        --vid)
            local vid="$2"
            shift
            shift
            ;;
        --pvid)
            local pvid="$2"
            shift
            shift
            ;;
        --id)
            local vxid="$2"
            shift
            shift
            ;;
        --ep)
            local ep="$2"
            shift
            shift
            ;;
        --lip)
            local lip="$2"
            shift
            shift
            ;;
        -*|--*)
            echo "Unknown option $1"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1") # save positional arg
            shift # past argument
            ;;
    esac
  done

  if [[ ${loxilbs[*]} =~ (^|[[:space:]])$h1($|[[:space:]]) && "$pick_config" == "yes" ]]; then
    return
  fi

  set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters
  link1=e$h1$h2
  link2=e$h2$h1

  #echo "$h1:$link1->$h2:$link2"

  if [[ "$uifType" == "phy" ]]; then
    sudo ip -n $h1 link add vxlan$vxid type vxlan id $vxid local $lip dev $link1 dstport 0
    sudo ip -n $h1 link set vxlan$vxid up
  elif [[ "$uifType" == "vlan" ]]; then
    sudo ip -n $h1 link add vxlan$vxid type vxlan id $vxid local $lip dev vlan$vid dstport 0
    sudo ip -n $h1 link set vxlan$vxid up
  fi

  if [[ "$pvid" != "" ]]; then
    sudo ip -n $h1 link add vlan$pvid type bridge 2>&1 | true
    sudo ip -n $h1 link set vxlan$vxid master vlan$pvid
    sudo ip -n $h1 link set vlan$pvid up
  fi

  if [[ "$ep" != "" ]]; then
    sudo bridge -n $h1 fdb append 00:00:00:00:00:00 dst $ep dev vxlan$vxid
  fi
  
}

## arg1 - hostname1 
## arg2 - hostname2 
create_docker_host_cnbridge() {
  POSITIONAL_ARGS=()
  while [[ $# -gt 0 ]]; do
    case $1 in
        --host1)
            local h1="$2"
            shift
            shift
            ;;
        --host2)
            local h2="$2"
            shift
            shift
            ;;
        -*|--*)
            echo "Unknown option $1"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1") # save positional arg
            shift # past argument
            ;;
    esac
  done

  if [[ ${loxilbs[*]} =~ (^|[[:space:]])$h1($|[[:space:]]) && "$pick_config" == "yes" ]]; then
    return
  fi

  set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters
  link1=e$h1$h2
  link2=e$h2$h1

  #echo "$h1:$link1->$h2:$link2"

  brport=$link1
    
  sudo ip -n $h1 link add br$h1 type bridge 2>&1 | true
  sudo ip -n $h1 link set $brport master br$h1
  sudo ip -n $h1 link set br$h1 up
}

# Register backend TLS material with the gateway's certificate registry, for a
# rule to refer to by ID (--backend-ca-cert-id, --backend-client-cert-id).
# Goes through loxicmd when backend_tls_cli_preflight found the arguments
# (BACKEND_TLS_CLI=1), over REST otherwise.
#Arg1: loxilb container
#Arg2: certificate ID
#Arg3: usage: ca | client
#Arg4: certificate (or CA bundle) PEM file
#Arg5: private key PEM file (usage client only)
function register_backend_cert() {
  local dock=$1 code
  shift
  if [[ "$BACKEND_TLS_CLI" == "1" ]]; then
    local args="--usage=$2 --cert-id=$1 --cert-file=/tmp/$1.crt"
    sudo docker cp "$3" $dock:/tmp/$1.crt || return 1
    if [[ -n "$4" ]]; then
      sudo docker cp "$4" $dock:/tmp/$1.key || return 1
      args="$args --key-file=/tmp/$1.key"
    fi
    echo "$dock: loxicmd create cert $args"
    $dexec $dock loxicmd create cert $args
    code=$?
    $dexec $dock rm -f /tmp/$1.crt /tmp/$1.key
    if [[ $code != 0 ]]; then
      echo "register_backend_cert $1 ($2): loxicmd create cert failed, rc=$code" >&2
      return 1
    fi
    echo "Registered backend certificate $1 (usage $2)"
    return 0
  fi
  code=$(python3 -c '
import json, sys
d = {"certId": sys.argv[1], "usage": sys.argv[2], "certPem": open(sys.argv[3]).read()}
d["keyPem"] = open(sys.argv[4]).read() if len(sys.argv) > 4 else ""
print(json.dumps(d))' "$@" | sudo docker exec -i $dock curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://localhost:11111/netlox/v1/config/cert -H "Content-Type: application/json" -d @-)
  if [[ "$code" != "201" ]]; then
    echo "register_backend_cert $1 ($2): expected 201, got '$code'" >&2
    return 1
  fi
  echo "Registered backend certificate $1 (usage $2)"
}

# backend_tls_cli_preflight <container>
# Returns 0 and sets BACKEND_TLS_CLI=1 when the packaged loxicmd can name backend
# certificates by ID (create cert --usage, create lb --backend-ca-cert-id);
# returns 1 and sets BACKEND_TLS_CLI=0 otherwise, so the caller configures over
# REST. CLI_TESTS=skip forces REST; CLI_TESTS=required makes a CLI without the
# arguments a failure instead of a fallback.
function backend_tls_cli_preflight() {
  local cont="${1:-llb1}"
  local mode="${CLI_TESTS:-auto}"
  BACKEND_TLS_CLI=0
  if [[ "$mode" == "skip" ]]; then
    echo "  Backend TLS CLI preflight: CLI_TESTS=skip -> REST"
    return 1
  fi
  if $dexec "$cont" loxicmd create lb --help 2>&1 | grep -q -- '--backend-ca-cert-id' \
     && $dexec "$cont" loxicmd create cert --help 2>&1 | grep -q -- '--usage'; then
    BACKEND_TLS_CLI=1
    echo "  Backend TLS CLI preflight: loxicmd names backend certificates by ID (CLI_TESTS=$mode) [OK]"
    return 0
  fi
  if [[ "$mode" == "required" ]]; then
    echo "  Backend TLS CLI preflight: CLI_TESTS=required but loxicmd lacks --backend-ca-cert-id [FAIL]"
    exit 1
  fi
  echo "  SKIP: loxicmd lacks --backend-ca-cert-id (image predates it) -> REST; set CLI_TESTS=required to enforce"
  return 1
}

# bands_cli_preflight <container>
# Returns 0 when the packaged loxicmd carries the priority-band surface of
# loxicmd-inference-gateway #83 (create lb --fc-wake-policy and the objective
# resource), so a scenario can drive the band knobs through the CLI; returns
# 1 when the caller should skip that CLI half (auto/skip paths).
# CLI_TESTS=skip forces the skip; CLI_TESTS=required makes a CLI without the
# flags a failure (exit 1) instead of a skip.
function bands_cli_preflight() {
  local cont="${1:-llb1}"
  local mode="${CLI_TESTS:-auto}"
  if [[ "$mode" == "skip" ]]; then
    echo "  Bands CLI preflight: CLI_TESTS=skip -> skipping CLI tests"
    return 1
  fi
  if $dexec "$cont" loxicmd create lb --help 2>&1 | grep -q -- '--fc-wake-policy' \
     && $dexec "$cont" loxicmd create objective --help >/dev/null 2>&1; then
    echo "  Bands CLI preflight: loxicmd carries the band flags and the objective resource (CLI_TESTS=$mode) [OK]"
    return 0
  fi
  if [[ "$mode" == "required" ]]; then
    echo "  Bands CLI preflight: CLI_TESTS=required but loxicmd lacks --fc-wake-policy / create objective [FAIL]"
    exit 1
  fi
  echo "  SKIP: loxicmd lacks --fc-wake-policy (image predates loxicmd #83); set CLI_TESTS=required to enforce"
  return 1
}

# jwtauth_cli_preflight <container>
# The same gate for the JWT auth profile resource of loxicmd-inference-gateway
# #83 (create jwtauthprofile with its --priority-class cap); semantics as
# bands_cli_preflight (CLI_TESTS=auto|required|skip).
function jwtauth_cli_preflight() {
  local cont="${1:-llb1}"
  local mode="${CLI_TESTS:-auto}"
  if [[ "$mode" == "skip" ]]; then
    echo "  JWT profile CLI preflight: CLI_TESTS=skip -> skipping CLI tests"
    return 1
  fi
  if $dexec "$cont" loxicmd create jwtauthprofile --help 2>&1 | grep -q -- '--priority-class'; then
    echo "  JWT profile CLI preflight: loxicmd carries the jwtauthprofile resource (CLI_TESTS=$mode) [OK]"
    return 0
  fi
  if [[ "$mode" == "required" ]]; then
    echo "  JWT profile CLI preflight: CLI_TESTS=required but loxicmd lacks create jwtauthprofile --priority-class [FAIL]"
    exit 1
  fi
  echo "  SKIP: loxicmd lacks create jwtauthprofile (image predates loxicmd #83); set CLI_TESTS=required to enforce"
  return 1
}

#Arg1: host name
#Arg2: --<proto>:<iport>:<oport>
#Arg3: --endpoints:<ip>:<weight>,..
function create_lb_rule() {
  if [[ ${loxilbs[*]} =~ (^|[[:space:]])$1($|[[:space:]]) && "$pick_config" == "yes" ]]; then
    return
  fi
  args=( "$@" )
  args=( "${args[@]/$1}" )
  echo "$1: loxicmd create lb ${args[*]}"
  $dexec $1 loxicmd create lb ${args[*]}

  if [[ ${args[*]} == *"--mode=fullproxy"* ]]; then
    return
  fi

  hook=$($dexec $1 tc filter show dev eth0 ingress | grep tc_packet_func)
  if [[ $hook != *"tc_packet_func"* ]]; then
    echo "ERROR : No hook point found";
    exit 1
  fi
}

# cli_preflight — decide whether the packaged loxicmd is the inference-gateway CLI
# (i.e. supports the AI subcommands) before a scenario drives it as the config path
# or subject-under-test.
#
# Env knob CLI_TESTS (default "auto"):
#   required -> loxicmd MUST exist & be AI-capable, else hard FAIL (exit 1)
#   auto     -> use the CLI if capable; otherwise caller SKIPs (function returns 1)
#   skip     -> always skip CLI testing (function returns 1)
#
# Arg1: container name (default llb1)
# Returns 0 when the CLI is AI-capable (caller proceeds with loxicmd);
#         1 when the caller should skip the CLI half (auto/skip paths).
# The capability probe: the inference-gateway CLI adds `create apikey` and the
# `--model-name` flag on `create lb` — both absent from the classic loxicmd.
function cli_preflight() {
  local cont="${1:-llb1}"
  local mode="${CLI_TESTS:-auto}"
  if [[ "$mode" == "skip" ]]; then
    echo "  CLI preflight: CLI_TESTS=skip -> skipping CLI tests"
    return 1
  fi
  if $dexec "$cont" loxicmd create apikey --help >/dev/null 2>&1 \
     && $dexec "$cont" loxicmd create lb --help 2>&1 | grep -q -- '--model-name'; then
    echo "  CLI preflight: loxicmd is AI-capable (CLI_TESTS=$mode) [OK]"
    return 0
  fi
  if [[ "$mode" == "required" ]]; then
    echo "  CLI preflight: CLI_TESTS=required but loxicmd lacks AI subcommands [FAIL]"
    exit 1
  fi
  echo "  SKIP: loxicmd lacks AI subcommands (image predates packaging swap); set CLI_TESTS=required to enforce"
  return 1
}

# require_host_tools <tool>... - refuse to score anything when a tool the
# assertions depend on is missing from the HOST.
#
# Scenarios reach the gateway through `hexec` ("ip netns exec"), which swaps
# the network namespace and keeps the host filesystem. A tool installed into
# the llb1 container with `dexec` ("docker exec") is therefore NOT on this
# PATH, however convincing the install looked.
#
# This matters because the usual extractors fail QUIETLY. An absent `jq`
# writes nothing to stdout, so an assertion reading its output sees an empty
# string - which is exactly what a gateway omitting the field would produce.
# Every such assertion then reports a product defect that was never measured,
# and a bed problem is read as a broken gateway.
#
# Hosted CI runners ship these tools preinstalled, so a bed that lacks one
# fails nowhere else, and fails here as a pile of invented product defects.
# A missing extractor is a lost measurement, not a verdict: refuse instead.
#
# Returns 0 when every tool is present, 1 otherwise. Call it as
# `require_host_tools jq || exit 1` before the first assertion.
function require_host_tools() {
  local missing="" t
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
  done
  if [[ -z "$missing" ]]; then
    return 0
  fi
  echo "  FATAL: this scenario's assertions need host tools that are absent:$missing"
  echo "         They run on the host, not inside llb1 - hexec is 'ip netns exec',"
  echo "         which keeps the host filesystem. Without them the assertions read"
  echo "         empty values and report gateway defects that were never measured."
  echo "         Install them:  sudo apt-get update && sudo apt-get install -y$missing"
  return 1
}

# require_host_python <module>... - refuse to run when a python module the
# scenario's mocks import is missing from the interpreter that RUNS them.
#
# The environment matters more than the module here. Mocks are launched with
# `hexec` ("sudo ip netns exec"), so they execute as root and import from
# root's sys.path. Probing with a bare `python3 -c "import x"` checks the
# CALLING user instead, and those two disagree the moment anyone runs
# `pip3 install --user`: the probe passes while the mock still cannot import,
# so the gate waves through exactly the bed it exists to catch.
#
# A scenario may bridge its own user-site by exporting PYTHONPATH into the
# hexec'd command (the KV-cache scenarios do). This check is for the ones that
# do not, which is every scenario that simply runs `hexec ... python3 x.py`.
#
# Returns 0 when root can import every module, 1 otherwise. Install them with
# cicd/preflight-deps.sh, which targets root-visible locations on purpose.
function require_host_python() {
  local missing="" m
  for m in "$@"; do
    sudo python3 -c "import $m" >/dev/null 2>&1 || missing="$missing $m"
  done
  if [[ -z "$missing" ]]; then
    return 0
  fi
  echo "  FATAL: this scenario's mocks need python modules that root cannot import:$missing"
  echo "         They run under hexec ('sudo ip netns exec'), so the interpreter that"
  echo "         matters is root's - a 'pip3 install --user' as your own user does not"
  echo "         satisfy them, however convincing 'python3 -c import' looks afterwards."
  echo "         Install them:  cd cicd && ./preflight-deps.sh"
  return 1
}

#Arg1: host name
#Arg2: <prefix/mask>
#Arg3: <nexthop-ip>
function add_route() {
  if [[ ${loxilbs[*]} =~ (^|[[:space:]])$1($|[[:space:]]) && "$pick_config" == "yes" ]]; then
    return
  fi
  echo "$1: ip route add $2 via $3 proto static"
  $hexec $1 ip route add $2 via $3 proto static
}
