#!/usr/bin/env bash
# End-to-end lab test in network namespaces (needs root, no hardware).
#
# 1. starts mahan-agent in lab mode (files under a temp root, no reloads)
# 2. loads tests/lab/lab.yaml with mrctl and commits it through the API
# 3. loads the rendered nftables ruleset into the router namespace
# 4. checks NAT, port forwarding, input firewall, address lists, counters
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN=$PWD/bin
LAB=$(mktemp -d /tmp/mahan-lab.XXXXXX)
NS_UP=mr-up NS_RT=mr-rt NS_CL=mr-cl
PASS=0 FAIL=0
AGENT_PID=""

cleanup() {
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
  for ns in $NS_UP $NS_RT $NS_CL; do
    ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del $ns 2>/dev/null || true
  done
  rm -rf "$LAB"
}
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
check_not() { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

go build -o "$BIN/" ./cmd/...

echo "== topology"
cleanup 2>/dev/null; LAB=$(mktemp -d /tmp/mahan-lab.XXXXXX)
for ns in $NS_UP $NS_RT $NS_CL; do ip netns add $ns; nsx $ns ip link set lo up; done
ip link add up0 netns $NS_UP type veth peer name wan0 netns $NS_RT
ip link add cl0 netns $NS_CL type veth peer name lan0 netns $NS_RT
nsx $NS_UP ip addr add 10.99.0.1/24 dev up0
nsx $NS_UP ip addr add 10.99.0.3/24 dev up0
nsx $NS_UP ip link set up0 up
# Addresses below mirror lab.yaml (networkd does this on a real device).
nsx $NS_RT ip addr add 10.99.0.2/24 dev wan0
nsx $NS_RT ip addr add 192.168.77.1/24 dev lan0
nsx $NS_RT ip link set wan0 up
nsx $NS_RT ip link set lan0 up
nsx $NS_CL ip addr add 192.168.77.10/24 dev cl0
nsx $NS_CL ip link set cl0 up
nsx $NS_CL ip route add default via 192.168.77.1
# The upstream has NO route to 192.168.77.0/24: replies only work through NAT.

echo "== agent: load + commit through the API"
"$BIN/mahan-agent" --no-reload --root "$LAB/root" --state "$LAB/state" --socket "$LAB/agent.sock" 2>"$LAB/agent.log" &
AGENT_PID=$!
for _ in $(seq 50); do [ -S "$LAB/agent.sock" ] && break; sleep 0.1; done
MR() { "$BIN/mrctl" --socket "$LAB/agent.sock" "$@"; }
check "factory default committed at first boot" bash -c "'$BIN/mrctl' --socket '$LAB/agent.sock' history | grep -q 'factory default'"
MR load tests/lab/lab.yaml >/dev/null
check "diff shows the change" bash -c "'$BIN/mrctl' --socket '$LAB/agent.sock' diff | grep -q 'lab-router'"
MR commit -m "lab config" >/dev/null
check "commit stored" bash -c "'$BIN/mrctl' --socket '$LAB/agent.sock' history | grep -q 'lab config'"
check "kea config rendered" grep -q '"192.168.77.0/24"' "$LAB/root/etc/kea/kea-dhcp4.conf"
check "networkd route rendered" grep -q 'Gateway=10.99.0.1' "$LAB/root/etc/systemd/network/30-mr-wan0.network"

echo "== dataplane"
nsx $NS_RT sysctl -qw net.ipv4.ip_forward=1
nsx $NS_RT ip route add default via 10.99.0.1
nsx $NS_RT nft -f "$LAB/root/etc/nftables.d/mahan-router.nft"

# servers
nsx $NS_UP python3 -m http.server 8000 --bind 10.99.0.1 >"$LAB/up-http.log" 2>&1 &
nsx $NS_CL python3 -m http.server 80 --bind 192.168.77.10 >/dev/null 2>&1 &
nsx $NS_RT python3 -m http.server 2222 --bind 0.0.0.0 >/dev/null 2>&1 &
nsx $NS_RT python3 -m http.server 22 --bind 0.0.0.0 >/dev/null 2>&1 &
sleep 1
CURL="curl -s -o /dev/null -m 3 -f"

check "client reaches upstream (masquerade)" nsx $NS_CL $CURL http://10.99.0.1:8000/
check "upstream sees router address, not client" grep -q '^10.99.0.2 ' "$LAB/up-http.log"
check "port forward WAN:8080 -> client:80" nsx $NS_UP $CURL http://10.99.0.2:8080/
check_not "blocked address list cannot use port forward" nsx $NS_UP $CURL --interface 10.99.0.3 http://10.99.0.2:8080/
check "LAN reaches router service" nsx $NS_CL $CURL http://192.168.77.1:2222/
check_not "WAN cannot reach router service" nsx $NS_UP $CURL http://10.99.0.2:2222/
check_not "WAN cannot reach LAN directly" nsx $NS_UP bash -c "ip route add 192.168.77.0/24 via 10.99.0.2 2>/dev/null; $CURL http://192.168.77.10:80/"
check "ping router from WAN (icmp allowed)" nsx $NS_UP ping -c1 -W2 10.99.0.2
nsx $NS_UP $CURL http://10.99.0.2:22/ || true
check "SSH attempt from WAN lands in dynamic list" bash -c "ip netns exec $NS_RT nft list set inet mahan al_scanners_v4 | grep -q 10.99.0.1"
check "rule counters count hits (n1 port forward)" bash -c "ip netns exec $NS_RT nft -j list table inet mahan | python3 -c '
import json,sys
d=json.load(sys.stdin)[\"nftables\"]
hits={r[\"rule\"][\"comment\"].split()[0]: [e[\"counter\"][\"packets\"] for e in r[\"rule\"][\"expr\"] if \"counter\" in e][0] for r in d if \"rule\" in r and \"comment\" in r[\"rule\"]}
sys.exit(0 if hits.get(\"n1\",0)>0 and hits.get(\"f5\",0)>0 else 1)'"

echo "== commit confirm + rollback"
sed 's/hostname: lab-router/hostname: lab-router2/' tests/lab/lab.yaml > "$LAB/lab2.yaml"
MR load "$LAB/lab2.yaml" >/dev/null
MR commit -m "risky" --confirm 2 >/dev/null
check "change applied while waiting for confirm" grep -q lab-router2 "$LAB/root/etc/hostname"
sleep 3
check "unconfirmed commit rolled back" grep -qx lab-router "$LAB/root/etc/hostname"
check "auto-rollback recorded" bash -c "'$BIN/mrctl' --socket '$LAB/agent.sock' history -n 1 | grep -q auto-rollback"
MR rollback HEAD~3 >/dev/null
check "manual rollback to factory default" grep -qx mahan-router "$LAB/root/etc/hostname"

echo
echo "lab: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
