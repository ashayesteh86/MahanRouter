#!/usr/bin/env bash
# Boots the ISO in QEMU and checks the real services (networkd, nftables,
# Kea, Unbound) from a LAN client. Works without KVM (slow TCG emulation).
#
#   sudo image/test-vm.sh [live|install|all]
#
# NICs: ether1 = e1000 on QEMU user-net (WAN, DHCP 10.0.2.15, internet via host)
#       ether2 = vmxnet3 (the VMware NIC) on a tap inside netns "mrvm" (LAN)
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIST=$ROOT/dist/iso
ISO=$(ls -t "$DIST"/mahan-router-*-amd64.iso | head -1)
MODE=${1:-all}
WORK=$(mktemp -d /var/tmp/mahan-vm.XXXXXX)
NS=mrvm TAP=mrtap0
ACCEL=tcg; [ -e /dev/kvm ] && ACCEL=kvm
PASS=0 FAIL=0
QPID=""

cleanup() {
  [ -n "$QPID" ] && kill "$QPID" 2>/dev/null
  ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del $NS 2>/dev/null
  ip link del $TAP 2>/dev/null
}
trap 'cleanup; rm -rf "$WORK"' EXIT
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
expect_log() { if grep -qE "$2" "$3"; then ok "$1"; else bad "$1"; fi; }

lan_up() {
  cleanup
  ip tuntap add $TAP mode tap
  ip link set $TAP up
}

# Move the tap into the client namespace once QEMU holds it open.
lan_client() {
  ip netns add $NS
  ip link set $TAP netns $NS
  ip netns exec $NS ip link set lo up
  ip netns exec $NS ip link set $TAP up
}

qemu() { # extra args...
  qemu-system-x86_64 -machine q35,accel=$ACCEL -cpu max -smp 4 -m 2048 \
    -display none -serial file:"$WORK/serial.log" \
    -netdev user,id=wan -device e1000,netdev=wan,mac=52:54:00:aa:00:01 \
    -netdev tap,id=lan,ifname=$TAP,script=no,downscript=no -device vmxnet3,netdev=lan,mac=52:54:00:aa:00:02 \
    "$@" &
  QPID=$!
}

wait_for() { # pattern timeout_seconds
  local end=$((SECONDS + $2))
  while [ $SECONDS -lt $end ]; do
    grep -qE "$1" "$WORK/serial.log" 2>/dev/null && return 0
    kill -0 "$QPID" 2>/dev/null || return 1
    sleep 5
  done
  return 1
}

check_lan() {
  echo "  .. LAN client: DHCP from Kea"
  ip netns exec $NS timeout 400 dhcpcd -4 -1 -t 390 -w --noipv4ll --nohook resolv.conf $TAP >"$WORK/dhcp.log" 2>&1
  local ip; ip=$(ip netns exec $NS ip -4 -br addr show $TAP | awk '{print $3}')
  if [[ "$ip" == 192.168.88.* ]]; then
    ok "LAN client got DHCP lease $ip"
  else
    bad "LAN client got no DHCP lease"; tail -5 "$WORK/dhcp.log"
  fi
  if ip netns exec $NS ping -c2 -W3 192.168.88.1 >/dev/null; then ok "ping router 192.168.88.1"; else bad "ping router"; fi
  if ip netns exec $NS dig +time=5 +tries=3 @192.168.88.1 deb.debian.org A +short | grep -qE '^[0-9.]+$'; then
    ok "Unbound on router resolves for LAN"
  else bad "DNS via router"; fi
  local web; web=$(getent ahostsv4 deb.debian.org | awk 'NR==1{print $1}')
  if ip netns exec $NS timeout 20 curl -s -o /dev/null -f --resolve deb.debian.org:80:$web http://deb.debian.org/debian/; then
    ok "LAN client reaches internet through NAT"
  else bad "LAN client internet via NAT"; fi
}

check_report() { # label
  local log="$WORK/serial.log"
  sed -n '/MAHAN SELFTEST BEGIN/,/MAHAN SELFTEST END/p' "$log" > "$WORK/report-$1.txt"
  expect_log "$1: agent active"            '^mahan-agent +active'      "$WORK/report-$1.txt"
  expect_log "$1: networkd active"         '^systemd-networkd +active' "$WORK/report-$1.txt"
  expect_log "$1: kea active"              '^kea-dhcp4-server +active' "$WORK/report-$1.txt"
  expect_log "$1: unbound active"          '^unbound +active'          "$WORK/report-$1.txt"
  expect_log "$1: ports renamed ether1/2"  '^ether2 '                  "$WORK/report-$1.txt"
  expect_log "$1: WAN DHCP address"        '^ether1 +UP +10\.0\.2\.15' "$WORK/report-$1.txt"
  expect_log "$1: LAN bridge 192.168.88.1" '^bridge-lan +UP +192\.168\.88\.1/24' "$WORK/report-$1.txt"
  expect_log "$1: firewall table loaded"   'table inet mahan'          "$WORK/report-$1.txt"
  expect_log "$1: factory default commit"  'factory default'          "$WORK/report-$1.txt"
  cp "$WORK/report-$1.txt" "$DIST/selftest-$1.txt"
}

echo "ISO: $ISO  (accel: $ACCEL)"

if [ "$MODE" = live ] || [ "$MODE" = all ]; then
  echo "== live boot (BIOS, from CD)"
  lan_up
  qemu -cdrom "$ISO" -kernel "$DIST/vmlinuz" -initrd "$DIST/initrd.img" \
    -append "boot=live components mahan.selftest console=tty0 console=ttyS0,115200"
  sleep 2; lan_client
  if wait_for 'Started.*mahan-agent|mahan-agent.service' 900; then ok "booted to mahan-agent"; else bad "boot"; fi
  check_lan
  wait_for 'MAHAN SELFTEST END' 600 && check_report live || bad "no selftest report (live)"
  kill $QPID; wait $QPID 2>/dev/null; QPID=""
  cp "$WORK/serial.log" "$DIST/serial-live.log"
fi

if [ "$MODE" = install ] || [ "$MODE" = all ]; then
  echo "== install to disk"
  qemu-img create -f qcow2 "$WORK/disk.qcow2" 8G >/dev/null
  lan_up
  qemu -cdrom "$ISO" -kernel "$DIST/vmlinuz" -initrd "$DIST/initrd.img" -no-reboot \
    -drive file="$WORK/disk.qcow2",if=none,id=d0 -device ahci,id=ahci -device ide-hd,drive=d0,bus=ahci.0 \
    -append "boot=live components mahan.autoinstall=/dev/sda mahan.selftest console=tty0 console=ttyS0,115200"
  # -no-reboot: QEMU exits when the installer reboots.
  ( sleep 3600; kill $QPID 2>/dev/null ) & guard=$!
  wait "$QPID"; kill $guard 2>/dev/null; QPID=""
  expect_log "installer finished" "is installed on /dev/sda" "$WORK/serial.log"
  cp "$WORK/serial.log" "$DIST/serial-install.log"

  for fw in bios uefi; do
    echo "== boot installed disk ($fw)"
    : > "$WORK/serial.log"; lan_up
    extra=()
    if [ $fw = uefi ]; then
      cp /usr/share/OVMF/OVMF_VARS_4M.fd "$WORK/vars.fd"
      extra=(-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd -drive if=pflash,format=raw,file="$WORK/vars.fd")
    fi
    qemu "${extra[@]}" -drive file="$WORK/disk.qcow2",if=none,id=d0 -device ahci,id=ahci -device ide-hd,drive=d0,bus=ahci.0
    sleep 2; lan_client
    if wait_for 'MAHAN SELFTEST END' 1200; then check_report "disk-$fw"; else bad "no selftest report (disk $fw)"; tail -20 "$WORK/serial.log"; fi
    [ $fw = bios ] && check_lan
    kill $QPID; wait $QPID 2>/dev/null; QPID=""
  done
fi

cp "$WORK/serial.log" "$DIST/serial-last.log" 2>/dev/null
echo
echo "vm test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
