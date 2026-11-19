# Runs inside the image chroot (bash -e) after packages are installed.
export DEBIAN_FRONTEND=noninteractive

echo mahan-router > /etc/hostname
cat > /etc/hosts <<'EOF'
127.0.0.1 localhost
127.0.1.1 mahan-router
::1 localhost ip6-localhost ip6-loopback
EOF
# The router resolves through its own Unbound cache.
rm -f /etc/resolv.conf
echo "nameserver 127.0.0.1" > /etc/resolv.conf

# Default login. The console banner tells the user to change it.
echo "root:mahan" | chpasswd

sed -i 's/^# *en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen && locale-gen >/dev/null

cat > /etc/issue <<'EOF'

  Mahan Router  \n  (\l)

  Login: root / mahan   (change it with: passwd)
  WAN  ether1     : \4{ether1}
  LAN  bridge-lan : \4{bridge-lan}   web panel: https://\4{bridge-lan}
  Default: ether1 = WAN (DHCP client), other ports = LAN bridge 192.168.88.1/24
  Port status: ip -br link
  Commands: mrctl help | mahan-install (install to disk) | mahan-selftest

EOF
cp /etc/issue /etc/issue.net

# mahan-agent decides which services run; start from a known state.
systemctl enable systemd-networkd mahan-agent nftables open-vm-tools ssh
for u in kea-dhcp4-server unbound frr xl2tpd strongswan strongswan-starter; do
  systemctl disable "$u" 2>/dev/null || true
done
systemctl mask systemd-networkd-wait-online.service
systemctl enable mahan-selftest mahan-installer mahan-timesync-bootstrap
systemctl set-default multi-user.target

# Empty machine-id: regenerated on first boot.
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id
# No SSH host keys in the image: each router makes its own on first start.
rm -f /etc/ssh/ssh_host_*

# Initramfs with live-boot hooks for the ISO.
update-initramfs -u -k all

apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /tmp/* /var/log/*.log
