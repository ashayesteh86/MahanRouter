#!/usr/bin/env bash
# Builds the Mahan Router live/installer ISO (Debian 12, amd64, BIOS+UEFI).
#
#   sudo image/build-iso.sh            -> dist/iso/mahan-router-<version>-amd64.iso
#
# The ISO boots a live system (runs from RAM, nothing written to disk) and
# offers "Install to disk", which runs mahan-install.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$ROOT/dist/iso}
MIRROR=${MIRROR:-http://deb.debian.org/debian}
VERSION=$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)
WORK=$(mktemp -d /var/tmp/mahan-iso.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

PACKAGES=(
  # base system
  systemd-sysv udev dbus kmod procps iproute2 iputils-ping less vim-tiny bash-completion
  ca-certificates curl openssh-server sudo locales
  linux-image-amd64 firmware-linux-free live-boot
  # router services
  nftables kea-dhcp4-server unbound dns-root-data chrony frr ppp wireguard-tools git
  # tools
  tcpdump ethtool pciutils conntrack dnsutils mtr-tiny
  # hypervisor guest tools
  open-vm-tools qemu-guest-agent
  # installer
  parted dosfstools e2fsprogs eject grub-pc-bin grub-efi-amd64-bin grub2-common efibootmgr
)

echo ">> building binaries ($VERSION)"
make -C "$ROOT" build rozaneh sing-box VERSION="$VERSION" >/dev/null

echo ">> bootstrapping Debian 12 (this takes a few minutes)"
mmdebstrap --variant=minbase --components=main,contrib,non-free-firmware \
  --include="$(IFS=,; echo "${PACKAGES[*]}")" \
  --customize-hook="cp -a '$ROOT/image/overlay/.' \"\$1/\"" \
  --customize-hook="install -m755 '$ROOT/bin/mahan-agent' '$ROOT/bin/mrctl' '$ROOT/bin/rozaneh' '$ROOT/bin/sing-box' \"\$1/usr/sbin/\"" \
  --customize-hook="install -m644 '$ROOT/packaging/systemd/'*.service \"\$1/etc/systemd/system/\"" \
  --customize-hook="mkdir -p \"\$1/etc/mahan-router\" && echo '$VERSION' > \"\$1/etc/mahan-router/version\"" \
  --customize-hook="cp '$ROOT/image/configure-rootfs.sh' \"\$1/tmp/configure.sh\" && chroot \"\$1\" /bin/bash -e /tmp/configure.sh" \
  bookworm "$WORK/rootfs" "$MIRROR" "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] $MIRROR-security bookworm-security main" "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] $MIRROR bookworm-updates main"

echo ">> assembling ISO tree"
ISO="$WORK/iso"
mkdir -p "$ISO/live" "$ISO/boot/grub"
cp "$WORK"/rootfs/boot/vmlinuz-* "$ISO/live/vmlinuz"
cp "$WORK"/rootfs/boot/initrd.img-* "$ISO/live/initrd.img"
mksquashfs "$WORK/rootfs" "$ISO/live/filesystem.squashfs" -comp xz -noappend -quiet -e boot/efi
cat > "$ISO/boot/grub/grub.cfg" <<EOF
set timeout=5
set default=0
insmod all_video
serial --speed=115200
terminal_input console serial
terminal_output console serial
menuentry "Install Mahan Router to disk" {
  linux /live/vmlinuz boot=live components nomodeset mahan.install console=ttyS0,115200 console=tty0
  initrd /live/initrd.img
}
EOF

mkdir -p "$OUT"
NAME="mahan-router-$VERSION-amd64.iso"
echo ">> writing $OUT/$NAME"
grub-mkrescue -o "$OUT/$NAME" "$ISO" -- -volid MAHAN_ROUTER >/dev/null 2>&1
# keep kernel+initrd next to the ISO for automated QEMU tests (-kernel/-append)
cp "$ISO/live/vmlinuz" "$ISO/live/initrd.img" "$OUT/"
(cd "$OUT" && sha256sum "$NAME" > "$NAME.sha256")
ls -lh "$OUT/$NAME"
