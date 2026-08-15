#!/usr/bin/env bash
# ============================================================================
# FreeSDN - encrypted-secret DR fidelity drill
# ============================================================================
# Companion to restore_drill.sh. That one proves the pg-backup PIPELINE is
# recoverable; THIS one proves the FreeSDN-specific property that matters for
# disaster recovery of an appliance full of secrets:
#
#   an at-rest-encrypted column (the app's Fernet ciphertext, e.g. a VPN
#   wireguard/openvpn config or a controller credential) survives a
#   pg_dump -> restore into a CLEAN database, still DECRYPTS with the
#   preserved SECRET_KEY, and REFUSES a different key.
#
# Self-contained: throwaway source + target Postgres + the backend image for
# the real app crypto, under a FIXED key. No running stack required.
#
#   ./scripts/dr_crypto_fidelity_drill.sh
#
# Override the backend image with BACKEND_IMAGE=... if yours is tagged
# differently (default freesdn-backend:dev).
set -uo pipefail

NET=sfdrill-net
PG_IMG="${POSTGRES_IMAGE:-postgres:18.6-trixie}"
APP_IMG="${BACKEND_IMAGE:-freesdn-backend:dev}"
PW=drillpw
# Fixed, reproducible key material (drill-only — never a real secret).
KEY="drill-secret-key-0123456789-fixed-len-40"
SALT="drill-encryption-salt-fixed"
WRONGKEY="different-key-0123456789-fixed-len-0001"
MARKER="DRILL-WG-SECRET-do-not-ship"

GREEN=$'\033[92m'; RED=$'\033[91m'; CYAN=$'\033[96m'; RST=$'\033[0m'
PASS=0; FAIL=0
ok(){ echo "${GREEN}[PASS]${RST} $*"; PASS=$((PASS+1)); }
bad(){ echo "${RED}[FAIL]${RST} $*"; FAIL=$((FAIL+1)); }
info(){ echo "${CYAN}[..]${RST}  $*"; }
sx(){ docker exec sfdrill-src "$@"; }
tx(){ docker exec sfdrill-tgt "$@"; }
# app crypto in the backend image, with a chosen SECRET_KEY (arg 1 = key, arg 2 = python expr)
crypto(){ docker run --rm -e "SECRET_KEY=$1" -e "ENCRYPTION_SALT=$SALT" -e ENVIRONMENT=development \
            -e PYTHONPATH=/app --entrypoint python "$APP_IMG" -c "$2" 2>/dev/null; }

cleanup(){ docker rm -f sfdrill-src sfdrill-tgt >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker image inspect "$APP_IMG" >/dev/null 2>&1 || { echo "backend image $APP_IMG not found - build the stack first (or set BACKEND_IMAGE)"; exit 1; }

info "Spinning up throwaway source + target Postgres…"
docker network create "$NET" >/dev/null
docker run -d --name sfdrill-src --network "$NET" -e POSTGRES_PASSWORD=$PW -e POSTGRES_DB=app "$PG_IMG" >/dev/null
docker run -d --name sfdrill-tgt --network "$NET" -e POSTGRES_PASSWORD=$PW -e POSTGRES_DB=app "$PG_IMG" >/dev/null
for c in sfdrill-src sfdrill-tgt; do
  for _ in $(seq 1 30); do docker exec "$c" pg_isready -U postgres -d app >/dev/null 2>&1 && break; sleep 1; done
done

info "Encrypting a marker with the REAL app crypto (Fernet, PBKDF2 over SECRET_KEY+SALT)…"
CT=$(crypto "$KEY" "from app.core.crypto import encrypt_credential; print(encrypt_credential('$MARKER'))" | tr -d '\r')
[ -n "$CT" ] && ok "ciphertext produced (${#CT} chars)" || { bad "encrypt failed (is $APP_IMG built?)"; exit 1; }
[ "$CT" != "$MARKER" ] && ok "ciphertext != plaintext (encrypted)" || bad "ciphertext == plaintext!"

info "Seeding source DB with the encrypted secret…"
PGPASSWORD=$PW sx psql -U postgres -d app -v ON_ERROR_STOP=1 -c \
  "CREATE TABLE vault(id serial primary key, name text, secret_enc text);
   INSERT INTO vault(name, secret_enc) VALUES ('vpn-wg', '$CT');" >/dev/null \
  && ok "row seeded" || bad "seed failed"
STORED=$(PGPASSWORD=$PW sx psql -U postgres -d app -tAc "SELECT secret_enc FROM vault WHERE name='vpn-wg'" | tr -d '\r')
echo "$STORED" | grep -q "$MARKER" && bad "PLAINTEXT at rest!" || ok "plaintext not present at rest"

info "Running the pg-backup dump and restoring into the CLEAN target DB…"
PGPASSWORD=$PW sx sh -c "pg_dump -U postgres -d app --no-owner --no-privileges" > /tmp/sfdrill.sql 2>/dev/null \
  && ok "pg_dump completed ($(wc -l </tmp/sfdrill.sql) lines)" || bad "pg_dump failed"
docker cp /tmp/sfdrill.sql sfdrill-tgt:/tmp/sfdrill.sql >/dev/null
PGPASSWORD=$PW tx sh -c "psql -U postgres -d app -q < /tmp/sfdrill.sql >/tmp/restore.log 2>&1" \
  && ok "restore ran" || bad "restore failed"

info "Verifying the restored secret…"
RCT=$(PGPASSWORD=$PW tx psql -U postgres -d app -tAc "SELECT secret_enc FROM vault WHERE name='vpn-wg'" 2>/dev/null | tr -d '\r')
[ -n "$RCT" ] && ok "row present after restore" || bad "row MISSING after restore"
[ "$RCT" = "$CT" ] && ok "ciphertext byte-identical across restore" || bad "ciphertext changed"

DEC=$(crypto "$KEY" "from app.core.crypto import decrypt_credential; print(decrypt_credential('$RCT'))" | tr -d '\r')
[ "$DEC" = "$MARKER" ] && ok "decrypt(restored) == marker  ← DR FIDELITY PROVEN" || bad "decrypt mismatch (got '$DEC')"

WRONG=$(crypto "$WRONGKEY" "
try:
    from app.core.crypto import decrypt_credential
    print('DECRYPTED:'+decrypt_credential('$RCT'))
except Exception as e:
    print('REFUSED:'+type(e).__name__)" | tr -d '\r')
echo "$WRONG" | grep -q '^REFUSED' && ok "wrong key refused → $WRONG  ← key-preservation enforced" || bad "wrong key decrypted: $WRONG"

echo
[ "$FAIL" = 0 ] && echo "${GREEN}SECRET FIDELITY DRILL PASSED ($PASS checks) - encrypted secrets survive DR restore and decrypt only with the preserved key.${RST}" \
                || { echo "${RED}SECRET FIDELITY DRILL FAILED ($FAIL of $((PASS+FAIL)))${RST}"; exit 1; }
