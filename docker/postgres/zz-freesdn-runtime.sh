# Sourced by the upstream entrypoint only while initializing a NEW cluster.
# pg_basebackup carries this regular file to compatible physical standbys.
umask 077
cat /usr/local/share/freesdn-database-runtime > "$PGDATA/FREESDN_RUNTIME"
