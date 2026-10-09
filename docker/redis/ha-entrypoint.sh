#!/bin/sh
# Persist Sentinel epochs and data-node roles across restart/recreation. This
# runs through sh from Compose, then the upstream entrypoint drops to UID 999.
set -eu
umask 077
fail() { echo "Valkey HA startup refused: $*" >&2; exit 1; }
: "${REDIS_PASSWORD:?REDIS_PASSWORD is required}"
: "${HA_NODE_IP:?HA_NODE_IP is required}"
: "${HA_PRIMARY_IP:?HA_PRIMARY_IP is required}"
case "$REDIS_PASSWORD" in
  *'
'*|*"$(printf '\r')"*) fail 'password must not contain CR or LF' ;;
esac
for address in "$HA_NODE_IP" "$HA_PRIMARY_IP"; do
  # Numeric addresses deliberately avoid Sentinel's synchronous DNS resolver.
  printf '%s\n' "$address" | awk -F. 'NF!=4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1}' \
    || fail 'HA addresses must be numeric IPv4 addresses'
done
state=/data/ha
[ ! -L "$state" ] || fail 'state directory is a symlink'
mkdir -p "$state"
conf="$state/${1:?expected primary, replica or sentinel}.conf"
case "$1" in primary|replica|sentinel) ;; *) fail 'invalid role' ;; esac
[ ! -L "$conf" ] && [ ! -L "$state/password" ] && [ ! -L "$state/identity" ] || fail 'state file is a symlink'
if [ -f "$conf" ]; then
  [ -s "$conf" ] && [ -f "$state/password" ] && [ -f "$state/identity" ] || fail 'incomplete persisted state'
  [ "$(cat "$state/password")" = "$REDIS_PASSWORD" ] \
    || fail 'credential changed; use the coordinated rotation procedure'
  [ "$(cat "$state/identity")" = "$1 $HA_NODE_IP $HA_PRIMARY_IP" ] \
    || fail 'node identity changed; restore its original addressing and volume'
else
  # Never silently reinterpret a pre-existing data volume as a fresh primary.
  [ ! -e "$state/password" ] || fail 'configuration missing from existing state'
  [ ! -e /data/appendonlydir ] && [ ! -e /data/dump.rdb ] \
    || fail 'unmarked existing data; read docker/redis/HA-UPGRADING'
  pw=$(printf '%s' "$REDIS_PASSWORD" | sed 's/\\/\\\\/g; s/"/\\"/g')
  {
    printf 'bind 0.0.0.0\nprotected-mode yes\nrequirepass "%s"\n' "$pw"
    if [ "$1" = sentinel ]; then
      printf 'port 26379\nsentinel resolve-hostnames no\nsentinel announce-hostnames no\n'
      printf 'sentinel announce-ip %s\nsentinel announce-port 26379\n' "$HA_NODE_IP"
      printf 'sentinel monitor freesdn-master %s 6379 2\n' "$HA_PRIMARY_IP"
      printf 'sentinel auth-pass freesdn-master "%s"\n' "$pw"
      printf 'sentinel down-after-milliseconds freesdn-master 5000\n'
      printf 'sentinel failover-timeout freesdn-master 10000\n'
      printf 'sentinel parallel-syncs freesdn-master 1\n'
    else
      printf 'include /usr/local/etc/valkey/valkey-custom.conf\n'
      printf 'dir /data\nappendonly yes\nappendfsync everysec\n'
      printf 'maxmemory-policy volatile-lru\nmasterauth "%s"\n' "$pw"
      printf 'replica-announce-ip %s\nreplica-announce-port 6379\n' "$HA_NODE_IP"
      printf 'rename-command FLUSHDB ""\nrename-command FLUSHALL ""\nrename-command DEBUG ""\n'
      if [ "$1" = replica ]; then printf 'replicaof %s 6379\n' "$HA_PRIMARY_IP"; fi
    fi
  } > "$conf.tmp"
  printf '%s' "$REDIS_PASSWORD" > "$state/password"
  printf '%s' "$1 $HA_NODE_IP $HA_PRIMARY_IP" > "$state/identity"
  mv "$conf.tmp" "$conf"
fi
# Only this private configuration directory is owned here. The upstream image
# handles ownership of the data directory before dropping privileges.
chown -R valkey:valkey "$state"
unset REDIS_PASSWORD
if [ "$1" = sentinel ]; then
  exec /usr/local/bin/docker-entrypoint.sh valkey-server "$conf" --sentinel
fi
exec /usr/local/bin/docker-entrypoint.sh valkey-server "$conf"
