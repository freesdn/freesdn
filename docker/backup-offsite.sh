#!/bin/sh
# Both local archives stay read-only. Only this service's status volume is writable.
set -eu
STATE=/offsite-status
mkdir -p "$STATE"
LAST_SUCCESS=0
SOURCE_SUCCESS=0
RETENTION_FAILED=0
if [ -r "$STATE/offsite.prom" ]; then
  LAST_SUCCESS=$(awk '$1 == "freesdn_pg_backup_offsite_last_success_timestamp" {print $2}' "$STATE/offsite.prom")
  SOURCE_SUCCESS=$(awk '$1 == "freesdn_pg_backup_offsite_source_timestamp" {print $2}' "$STATE/offsite.prom")
fi
case "$LAST_SUCCESS" in ''|*[!0-9]*) LAST_SUCCESS=0;; esac
case "$SOURCE_SUCCESS" in ''|*[!0-9]*) SOURCE_SUCCESS=0;; esac
write_status() {
  printf 'freesdn_pg_backup_offsite_last_attempt_failed %s\nfreesdn_pg_backup_offsite_last_success_timestamp %s\nfreesdn_pg_backup_offsite_source_timestamp %s\nfreesdn_pg_backup_offsite_retention_failed %s\n' \
    "$1" "$LAST_SUCCESS" "$SOURCE_SUCCESS" "$RETENTION_FAILED" > "$STATE/offsite.prom.tmp"
  mv "$STATE/offsite.prom.tmp" "$STATE/offsite.prom"
}
on_exit() { result=$?; trap - EXIT; if [ "$result" != 0 ]; then write_status 1; fi; exit "$result"; }
trap on_exit EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
positive() { case "$1" in ''|*[!0-9]*|0|0*) return 1;; esac; [ "${#1}" -le 8 ]; }
positive "${BACKUP_OFFSITE_INTERVAL_HOURS:-}" && [ "$BACKUP_OFFSITE_INTERVAL_HOURS" -le 8760 ] || { echo 'ERROR: invalid copy interval'; exit 1; }
positive "${BACKUP_OFFSITE_RETENTION_DAYS:-}" && [ "$BACKUP_OFFSITE_RETENTION_DAYS" -le 36500 ] || { echo 'ERROR: invalid retention'; exit 1; }
case "${BACKUP_OFFSITE_REMOTE:-}" in ''|-*|*[!a-zA-Z0-9_-]*) echo 'ERROR: invalid remote name'; exit 1;; esac
[ -n "${BACKUP_OFFSITE_PATH:-}" ] || { echo 'ERROR: empty remote path'; exit 1; }
rc() { rclone --config /config/rclone/rclone.conf "$@"; }
rc listremotes | grep -qFx -- "${BACKUP_OFFSITE_REMOTE}:"
DEST="${BACKUP_OFFSITE_REMOTE}:${BACKUP_OFFSITE_PATH}"
INTERVAL_SECONDS=$((BACKUP_OFFSITE_INTERVAL_HOURS * 3600))

copy_and_verify() {
  # Snapshot the atomic completion pointer. Never acknowledge a directory scan
  # (including an empty one) as a completed backup.
  cp /backups/.metrics/pg_backup.last_success /tmp/offsite.pointer || return 1
  read -r success batch extension extra < /tmp/offsite.pointer || return 1
  case "$success" in ''|*[!0-9]*) return 1;; esac
  [ "${#success}" -le 12 ] && [ "$success" -gt 0 ] && [ "$success" -le "$(date +%s)" ] || return 1
  echo "$batch" | grep -Eq '^[0-9]{8}_[0-9]{6}$' || return 1
  case "$extension" in sql.gz|sql.gz.gpg) ;; *) return 1;; esac
  [ -z "$extra" ] || return 1
  for database in freesdn logdb; do
    file="/backups/${database}_${batch}.${extension}"
    [ -f "$file" ] && [ ! -L "$file" ] && [ -s "$file" ] || return 1
  done
  # Keep the previous behavior of copying retained history, but select only
  # complete, nonempty pairs with generated names. Partials and orphans stay local.
  : > /tmp/offsite.files
  for file in /backups/freesdn_*.sql.gz /backups/freesdn_*.sql.gz.gpg; do
    name=${file##*/}; suffix=${name#freesdn_}
    echo "$suffix" | grep -Eq '^[0-9]{8}_[0-9]{6}\.sql\.gz(\.gpg)?$' || continue
    companion="/backups/logdb_$suffix"
    if [ -f "$file" ] && [ ! -L "$file" ] && [ -s "$file" ] &&
       [ -f "$companion" ] && [ ! -L "$companion" ] && [ -s "$companion" ]; then
      printf '%s\n%s\n' "$name" "logdb_$suffix" >> /tmp/offsite.files
    fi
  done
  grep -qFx "freesdn_${batch}.${extension}" /tmp/offsite.files &&
    grep -qFx "logdb_${batch}.${extension}" /tmp/offsite.files || return 1
  rc copy /backups "$DEST" --immutable --no-update-modtime --files-from /tmp/offsite.files --transfers 2 --checkers 4 \
    --retries 3 --low-level-retries 10 --stats=0 --log-level=NOTICE || return 1
  # Download verification works even when the remote has no comparable hashes.
  # Compare the match list as well: sources deleted during transfer must not let
  # rclone's empty-source success acknowledge files that were never verified.
  rc check /backups "$DEST" --download --one-way --files-from /tmp/offsite.files \
    --match /tmp/offsite.matched --checkers 2 --log-level=NOTICE || return 1
  LC_ALL=C sort /tmp/offsite.files > /tmp/offsite.expected || return 1
  LC_ALL=C sort /tmp/offsite.matched > /tmp/offsite.actual || return 1
  cmp -s /tmp/offsite.expected /tmp/offsite.actual || return 1
  marker="_completed/${batch}.${extension}.txt"
  rc copyto /tmp/offsite.pointer "$DEST/$marker" --immutable --no-update-modtime --log-level=NOTICE || return 1
  rc cat "$DEST/$marker" > /tmp/offsite.remote-pointer || return 1
  cmp -s /tmp/offsite.pointer /tmp/offsite.remote-pointer || return 1
  LAST_SUCCESS=$(date +%s)
  SOURCE_SUCCESS=$success
  RETENTION_FAILED=0
  # Protect the newly verified pair even if it is old. Retention failure does
  # not erase copy evidence, but is separately visible and must be investigated.
  rc delete "$DEST" --min-age "${BACKUP_OFFSITE_RETENTION_DAYS}d" \
    --filter "- /freesdn_${batch}.${extension}" --filter "- /logdb_${batch}.${extension}" --filter "- /$marker" \
    --filter '+ /freesdn_*.sql.gz' --filter '+ /freesdn_*.sql.gz.gpg' \
    --filter '+ /logdb_*.sql.gz' --filter '+ /logdb_*.sql.gz.gpg' --filter '+ /_completed/*.txt' --filter '- **' \
    --log-level=NOTICE || RETENTION_FAILED=1
  write_status 0
}

while true; do
  if copy_and_verify; then
    echo 'Off-site backup pairs copied and content-verified; completion recorded.'
  else
    write_status 1
    echo 'ERROR: off-site completion not verified; previous success retained, retrying next cycle.'
  fi
  sleep "$INTERVAL_SECONDS"
done
