#!/usr/bin/env bash
# Builds accel-ppp (PPTP, L2TP and SSTP server) for Debian 12 inside a
# debian:12 container and packs the installed files into a tarball that
# image/build-iso.sh unpacks into the image.
#
#   packaging/accel-ppp/build.sh <source.tar.gz> <out.tar.gz>
set -euo pipefail
SRC=$(realpath "$1"); OUT=$(realpath -m "$2")
mkdir -p "$(dirname "$OUT")"
docker run --rm -v "$SRC:/src.tar.gz:ro" -v "$(dirname "$OUT"):/out" debian:12 bash -ec "
  apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential cmake libssl-dev libpcre2-dev >/dev/null
  mkdir /b && tar -xzf /src.tar.gz -C /b --strip-components=1 && cd /b && mkdir build && cd build
  cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DKDIR=/nonexistent \
    -DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE -DRADIUS=FALSE -DSHAPER=FALSE -DLUA=FALSE -DNETSNMP=FALSE \
    -DLOG_PGSQL=FALSE -DCPACK_TYPE=Debian12 .. >/dev/null
  make -j\$(nproc) >/dev/null && make install DESTDIR=/stage >/dev/null
  rm -rf /stage/usr/share/doc /stage/etc/accel-ppp.conf.dist /stage/usr/share/man
  tar -czf /out/$(basename "$OUT") -C /stage .
  chown $(id -u):$(id -g) /out/$(basename "$OUT")
"
echo "built $OUT"
