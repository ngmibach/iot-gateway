#!/usr/bin/env bash
# Download Chrome runtime .debs and extract into apps/desktop/.local-libs (no sudo).
# Needed on minimal Ubuntu images that lack libnspr4/libnss3/etc.
set -euo pipefail
DESKTOP="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="$DESKTOP/.local-libs"
mkdir -p "$PREFIX/debs"
cd "$PREFIX/debs"
pkgs=(
  libnspr4 libnss3 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3
  libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2t64
  libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libatspi2.0-0t64
  libx11-xcb1 libxcb-dri3-0 libxshmfence1
)
for p in "${pkgs[@]}"; do
  apt-get download "$p" 2>/dev/null || apt-get download "${p%t64}" 2>/dev/null || echo "skip $p"
done
for deb in *.deb; do
  [[ -f "$deb" ]] || continue
  dpkg-deb -x "$deb" "$PREFIX"
done
echo "Libs extracted to $PREFIX"
echo "LD_LIBRARY_PATH=$PREFIX/usr/lib/x86_64-linux-gnu"
