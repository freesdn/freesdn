#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Build the verified stable release against the stable Alpine libraries.
#
# Only what FreeSDN gives FFmpeg is compiled: camera RTSP/RTSPS input with the
# video and audio codecs cameras send, and the snapshot (MJPEG), live and
# recorded HLS, clip export (libx264, AAC, MP4, drawtext) and ffprobe outputs.
# Every other decoder, encoder, demuxer, muxer, filter, bitstream filter,
# hardware accelerator and device is left out, so an advisory in one of them
# does not reach these images. The component sets are checked after configure.
set -eu
export LC_ALL=C
cd /build
case "$(cat /etc/alpine-release)" in 3.24.*) ;; *) exit 90;; esac
case "$(cat /etc/apk/repositories)" in *edge*) exit 91;; esac
apk upgrade --no-cache
apk add --no-cache coreutils dav1d-dev fontconfig-dev freetype-dev fribidi-dev harfbuzz-dev nasm openssl-dev opus-dev x264-dev zlib-dev build-base pkgconf patch xz pax-utils binutils ca-certificates curl gnupg tar
arch=$(apk --print-arch)
case "$arch" in
  x86_64|aarch64) ;;
  *) printf '%s
' 'Only amd64 and arm64 media builds are supported' >&2; exit 92;;
esac
apk info -v > build-packages.txt
# --retry alone does not retry a reset connection or a DNS failure, and ffmpeg.org
# gave both: 5 of 55 CI image builds died here. The archive is checked against
# verified-inputs.sha256 and its signature below, so retrying any error is safe.
curl --fail --location --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors --retry-delay 10 \
  --connect-timeout 30 --max-time 180 \
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
# Upstream FFmpeg fixes for advisories against 9.0.2, which no release carries
# yet: each file is the unmodified upstream commit (source-lock.json "backports").
patch -p1 --batch --fuzz=0 < ../cve-2026-107675-libssh-hostkey.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-107676-hdr10plus.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-107677-dash.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-107678-encryption-info.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-107696-rtsp-redirects.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-120243-g2m.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-120244-pcx.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-120245-sunrast-1.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-120245-sunrast-2.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-120246-cdxl.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-120247-huffyuv.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-125064-g726.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-125180-exif-1.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-125180-exif-2.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-125180-exif-3.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-125183-hevc-pps.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-125185-film-grain.patch
patch -p1 --batch --fuzz=0 < ../cve-2026-125225-aac-adtstoasc.patch
# Not an advisory: musl gives threads 128 KiB of stack, and the MPEG-TS PAT/PMT
# callbacks of 9.0.2 need ~131 KiB, so ffmpeg crashed on MPEG-TS in its demuxer thread.
patch -p1 --batch --fuzz=0 < ../mpegts-thread-stack.patch
# Cameras send H.264, H.265, MJPEG, MPEG-4, MPEG-1/2 or AV1 (libdav1d) video,
# and G.711, G.722, G.723.1, G.726, G.729, AMR, L16, L24, AAC, AC-3, MPEG audio
# or Opus: every decoder 26.11.1 had for an RTP payload a camera can send.
# The RTSP, MJPEG and WAV muxers and the Opus and PCM encoders are for go2rtc's
# own FFmpeg transcodes (ffmpeg: sources); only a command line selects them.
# The raw h264 and hevc demuxers read the keyframe go2rtc pipes in for its
# snapshot (/api/frame.jpeg): bytes the camera already sends to those parsers.
# go2rtc reads and writes "-", which FFmpeg 9 opens with the fd protocol.
./configure --prefix=/usr/local \
  --disable-autodetect \
  --disable-doc \
  --disable-everything \
  --disable-ffplay \
  --disable-static \
  --enable-gpl \
  --enable-libfontconfig \
  --enable-libfreetype \
  --enable-libfribidi \
  --enable-libdav1d \
  --enable-libharfbuzz \
  --enable-libopus \
  --enable-libx264 \
  --enable-lto=auto \
  --enable-openssl \
  --enable-pic \
  --enable-pthreads \
  --enable-shared \
  --enable-version3 \
  --enable-zlib \
  --enable-protocol=fd,file,http,https,pipe,rtp,tcp,tls,udp \
  --enable-demuxer=h264,hevc,rtsp \
  --enable-decoder=aac,aac_latm,ac3,adpcm_g722,adpcm_g726,adpcm_g726le,amrnb,amrwb,g723_1,g729,h264,hevc,libdav1d,mjpeg,mp2,mp3,mpeg1video,mpeg2video,mpeg4,opus,pcm_alaw,pcm_mulaw,pcm_s16be,pcm_s16le,pcm_s24be \
  --enable-parser=aac,aac_latm,ac3,amr,av1,g723_1,g729,h263,h264,hevc,mjpeg,mpegaudio,mpeg4video,mpegvideo,opus \
  --enable-encoder=aac,libopus,libx264,mjpeg,pcm_alaw,pcm_mulaw,pcm_s16be,pcm_s16le \
  --enable-muxer=hls,image2pipe,mjpeg,mp4,mpegts,rtsp,wav \
  --enable-bsf=h264_mp4toannexb,hevc_mp4toannexb \
  --enable-filter=aformat,anull,aresample,drawtext,format,null,scale \
  --extra-ldflags=-Wl,-rpath,/usr/local/lib
# What configure enabled, including what the components above select, must be
# exactly this; a new FFmpeg release that selects more fails here for review.
components() {
  sed -n "s/^#define CONFIG_\([A-Z0-9_]*\)_$1 1\$/\1/p" config_components.h | tr 'A-Z' 'a-z' | sort | paste -sd ' ' -
}
check() {
  actual=$(components "$1")
  if [ "$actual" != "$2" ]; then
    printf '%s components differ\n expected: %s\n   actual: %s\n' "$1" "$2" "$actual" >&2
    exit 95
  fi
}
check DECODER 'aac aac_latm ac3 adpcm_g722 adpcm_g726 adpcm_g726le amrnb amrwb g723_1 g729 h263 h264 hevc libdav1d mjpeg mp2 mp3 mpeg1video mpeg2video mpeg4 opus pcm_alaw pcm_mulaw pcm_s16be pcm_s16le pcm_s24be'
check ENCODER 'aac libopus libx264 mjpeg pcm_alaw pcm_mulaw pcm_s16be pcm_s16le'
check PARSER 'aac aac_latm ac3 amr av1 g723_1 g729 h263 h264 hevc mjpeg mpeg4video mpegaudio mpegvideo opus'
check DEMUXER 'asf h264 hevc mov mpegts rm rtsp'
check MUXER 'adts hls image2pipe latm mjpeg mov mp4 mpegts rtp rtsp wav webvtt'
check BSF 'aac_adtstoasc h264_mp4toannexb hevc_mp4toannexb vp9_superframe vvc_mp4toannexb'
check PROTOCOL 'fd file http https pipe rtp tcp tls udp'
check FILTER 'aformat anull aresample atrim crop drawtext format hflip null rotate scale transpose trim vflip'
check HWACCEL ''
check INDEV ''
check OUTDEV ''
make -j2
make DESTDIR=/staging install
cc -O2 -o /staging/usr/local/bin/qt-faststart tools/qt-faststart.c
sh /build/package.sh
