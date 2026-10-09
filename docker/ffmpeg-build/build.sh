#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Build the verified stable release against the stable Alpine libraries.
set -eu
export LC_ALL=C
cd /build
case "$(cat /etc/alpine-release)" in 3.24.*) ;; *) exit 90;; esac
case "$(cat /etc/apk/repositories)" in *edge*) exit 91;; esac
apk upgrade --no-cache
apk add --no-cache alsa-lib-dev aom-dev bzip2-dev coreutils dav1d-dev fontconfig-dev freetype-dev fribidi-dev harfbuzz-dev ladspa-dev lame-dev libass-dev libbluray-dev libdrm-dev libdvdnav-dev libdvdread-dev libjxl-dev libopenmpt-dev libplacebo-dev librist-dev libsrt-dev libssh-dev libtheora-dev libva-dev libvdpau-dev libvorbis-dev libvpx-dev libwebp-dev libxfixes-dev libxml2-dev lilv-dev nasm openssl-dev opus-dev perl-dev pulseaudio-dev rav1e-dev shaderc-dev sdl2-dev soxr-dev v4l-utils-dev vidstab-dev vulkan-loader-dev x264-dev x265-dev xvidcore-dev zeromq-dev zimg-dev zlib-dev build-base pkgconf patch xz pax-utils binutils ca-certificates glslang spirv-headers curl gnupg tar
arch=$(apk --print-arch)
case "$arch" in
  x86_64) apk add --no-cache svt-av1-dev libvpl-dev; set -- --enable-libsvtav1 --enable-libvpl;;
  aarch64) apk add --no-cache svt-av1-dev; set -- --enable-libsvtav1;;
  *) printf '%s
' 'Only amd64 and arm64 media builds are supported' >&2; exit 92;;
esac
apk info -v > build-packages.txt
curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --max-time 180 \
  --output ffmpeg-9.0.2.tar.xz https://ffmpeg.org/releases/ffmpeg-9.0.2.tar.xz
sha256sum -c verified-inputs.sha256
mkdir -m 700 /tmp/ffmpeg-gpg
# This is the upstream PUBLIC verification key; no private signing key is used.
gpg --batch --homedir /tmp/ffmpeg-gpg --dearmor --output /tmp/ffmpeg-release.gpg ffmpeg-devel.asc
gpgv --keyring /tmp/ffmpeg-release.gpg --status-fd 1 \
  ffmpeg-9.0.2.tar.xz.asc ffmpeg-9.0.2.tar.xz > signature-status.txt
grep -q '^\[GNUPG:\] VALIDSIG FCF986EA15E6E293A5644F10B4322F04D67658D8 ' signature-status.txt
tar --no-same-owner -xJf ffmpeg-9.0.2.tar.xz
cd ffmpeg-9.0.2
patch -p1 --batch --fuzz=0 < ../posix-ioctl.patch
./configure --disable-librtmp \
  --disable-lzma \
  --disable-static \
  --enable-avfilter \
  --enable-gpl \
  --enable-ladspa \
  --enable-libaom \
  --enable-libass \
  --enable-libbluray \
  --enable-libdav1d \
  --enable-libdrm \
  --enable-libdvdnav \
  --enable-libdvdread \
  --enable-libfontconfig \
  --enable-libfreetype \
  --enable-libfribidi \
  --enable-libharfbuzz \
  --enable-libjxl \
  --enable-libmp3lame \
  --enable-libopenmpt \
  --enable-libopus \
  --enable-libplacebo \
  --enable-libpulse \
  --enable-librav1e \
  --enable-librist \
  --enable-libsoxr \
  --enable-libsrt \
  --enable-libssh \
  --enable-libtheora \
  --enable-libv4l2 \
  --enable-libvidstab \
  --enable-libvorbis \
  --enable-libvpx \
  --enable-libwebp \
  --enable-libx264 \
  --enable-libx265 \
  --enable-libxcb \
  --enable-libxml2 \
  --enable-libxvid \
  --enable-libzimg \
  --enable-libzmq \
  --enable-lto=auto \
  --enable-lv2 \
  --enable-openssl \
  --enable-pic \
  --enable-pthreads \
  --enable-shared \
  --enable-vaapi \
  --enable-vdpau \
  --enable-version3 \
  --enable-vulkan \
  --prefix=/usr/local \
  --disable-doc \
  --glslc=glslang \
  --extra-ldflags=-Wl,-rpath,/usr/local/lib "$@"
for capability in LIBX264_ENCODER LIBX265_ENCODER H264_VULKAN_ENCODER SCALE_VULKAN_FILTER H264_VAAPI_ENCODER; do
  grep -q "^#define CONFIG_${capability} 1$" config_components.h
done
if [ "$arch" = x86_64 ]; then grep -q '^#define CONFIG_H264_QSV_ENCODER 1$' config_components.h; fi
make -j2
make DESTDIR=/staging install
cc -O2 -o /staging/usr/local/bin/qt-faststart tools/qt-faststart.c
sh /build/package.sh
