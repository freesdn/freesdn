#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
export LC_ALL=C
mkdir -p /out/usr/local/bin /out/usr/local/lib /out/usr/local/share/ffmpeg \
  /out/usr/share/licenses/ffmpeg /out/usr/share/freesdn-sources/ffmpeg
for binary in ffmpeg ffprobe ffplay qt-faststart; do
  cp "/staging/usr/local/bin/$binary" "/out/usr/local/bin/$binary"
done
for library in /staging/usr/local/lib/libav*.so* /staging/usr/local/lib/libsw*.so*; do
  cp -a "$library" /out/usr/local/lib/
done
cp -a /staging/usr/local/share/ffmpeg/. /out/usr/local/share/ffmpeg/
source_dir=/out/usr/share/freesdn-sources/ffmpeg
cp /build/ffmpeg-9.0.2.tar.xz /build/ffmpeg-9.0.2.tar.xz.asc /build/ffmpeg-devel.asc \
  /build/posix-ioctl.patch /build/source-lock.json /build/verified-inputs.sha256 \
  /build/build.sh /build/package.sh /build/install-runtime.sh /build/NOTICE \
  /build/build-packages.txt /build/signature-status.txt "$source_dir/"
cp /build/ffmpeg-9.0.2/COPYING.* /build/ffmpeg-9.0.2/LICENSE.md /build/NOTICE /out/usr/share/licenses/ffmpeg/
scanelf --needed --nobanner --format '%n#p' --recursive /out/usr/local/bin /out/usr/local/lib \
  | tr ',' '\n' | sort -u > /tmp/ffmpeg-needed.txt
: > "$source_dir/runtime-dependencies.txt"
while IFS= read -r library; do
  [ -n "$library" ] || continue
  case "$library" in *[!A-Za-z0-9_.+-]*) exit 93;; esac
  [ ! -e "/out/usr/local/lib/$library" ] || continue
  printf 'so:%s\n' "$library" >> "$source_dir/runtime-dependencies.txt"
done < /tmp/ffmpeg-needed.txt
LD_LIBRARY_PATH=/out/usr/local/lib /out/usr/local/bin/ffmpeg -buildconf > "$source_dir/build-configuration.txt" 2>&1
cd /out
find usr/local/bin usr/local/lib -type f -exec sha256sum {} + | sort > "$source_dir/runtime-files.sha256"
