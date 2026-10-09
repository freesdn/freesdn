#!/bin/sh
set -eu
awk -v now="$(date +%s)" -v interval="${BACKUP_INTERVAL_SECONDS:-86400}" \
  -v hours="${BACKUP_OFFSITE_INTERVAL_HOURS:-24}" -v grace="${BACKUP_FRESHNESS_GRACE_SECONDS:-7200}" '
  $1 == "freesdn_pg_backup_offsite_last_attempt_failed" {failed=$2; fc++}
  $1 == "freesdn_pg_backup_offsite_last_success_timestamp" {verified=$2; vc++}
  $1 == "freesdn_pg_backup_offsite_source_timestamp" {source=$2; sc++}
  $1 == "freesdn_pg_backup_offsite_retention_failed" {retention=$2; rc++}
  END {exit !(fc==1 && vc==1 && sc==1 && rc==1 && failed==0 && retention==0 &&
     interval ~ /^[0-9]+$/ && interval>0 && hours ~ /^[0-9]+$/ && hours>0 &&
     grace ~ /^[0-9]+$/ && grace>0 && verified ~ /^[0-9]+$/ && source ~ /^[0-9]+$/ &&
     verified>0 && verified<=now && source>0 && source<=verified &&
     now-source<=interval+hours*3600+grace)}' /offsite-status/offsite.prom
