#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
export LC_ALL=C
metadata=/usr/share/freesdn-sources/ffmpeg
case "$(cat /etc/alpine-release)" in 3.24.*) ;; *) exit 90;; esac
case "$(cat /etc/apk/repositories)" in *edge*) exit 91;; esac
# Only the generated, validated soname constraints are expanded as arguments.
while IFS= read -r dependency; do
  case "$dependency" in so:*) ;; *) exit 93;; esac
  soname=${dependency#so:}
  case "$soname" in ''|*[!A-Za-z0-9_.+-]*) exit 93;; esac
done < "$metadata/runtime-dependencies.txt"
set -f
# shellcheck disable=SC2046
apk add --no-cache $(cat "$metadata/runtime-dependencies.txt")
cd /
sha256sum -c "$metadata/runtime-files.sha256"
ffmpeg -version > /tmp/ffmpeg-version.txt
ffprobe -version > /tmp/ffprobe-version.txt
ffplay -version > /tmp/ffplay-version.txt
for binary in ffmpeg ffprobe ffplay; do
  head -n 1 "/tmp/$binary-version.txt" | grep -q "^$binary version 9\.0\.2 "
done
if apk info | grep -Eq '^(ffmpeg($|-)|ffplay$)'; then
  printf '%s\n' 'Distribution FFmpeg packages must not coexist with this media build' >&2
  exit 94
fi
