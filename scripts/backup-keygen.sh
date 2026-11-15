#!/usr/bin/env bash
# ============================================================================
# FreeSDN - create the database-backup encryption key pair
# ============================================================================
# pg-backup encrypts every database dump to an OpenPGP PUBLIC key and refuses
# to write plaintext without one, so a fresh install has no database backups
# until a key exists. This helper creates that key pair once:
#
#   * the PUBLIC key is written to BACKUP_GPG_PUBLIC_KEY_PATH (from the tier env
#     file). pg-backup re-checks that file every 60 seconds and starts backing
#     up on its own; no restart is needed.
#   * the PRIVATE key is handed to you ONCE, on standard output (or to the file
#     you name with --private-key-out). It is never written to this host's
#     FreeSDN tree, never stored in a container, and cannot be recovered here
#     later. Without it no backup can be restored, so put it somewhere safe and
#     OFF this host (password manager, offline USB stick, a second site).
#
# The key is generated inside a throwaway, network-less, read-only container of
# the stack's own PostgreSQL image (it carries gpg), in a tmpfs that disappears
# when the container exits.
#
# Usage:
#   ./scripts/backup-keygen.sh > /media/usb/freesdn-backup-private.asc
#   ./scripts/backup-keygen.sh --private-key-out /media/usb/freesdn-backup-private.asc
#   ./scripts/backup-keygen.sh --env-file .env.max --no-passphrase > key.asc
#
# Options:
#   --env-file FILE         Tier env file (default: the single .env.max/.env.pro/
#                           .env.lite present).
#   --private-key-out PATH  Write the private key to PATH (must not exist, mode
#                           0600) instead of standard output.
#   --no-passphrase         Do not protect the private key with a passphrase
#                           (default: ask twice on the terminal, or read one line
#                           from standard input when it is not a terminal).
#   --image IMAGE           Image with gpg (default: POSTGRES_IMAGE from the env
#                           file, else freesdn-postgres:local).
#   -h, --help              Show this message.
#
# Exit codes: 0 key installed, 2 docker/image missing, 3 refused (bad input or
# a key is already installed), 4 generation failed.
# ============================================================================

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

say() { printf '%s\n' "$*" >&2; }
die() { say "ERROR: $2"; exit "$1"; }
usage() { sed -n '2,/^# =====/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit "${1:-0}"; }

ENV_FILE=""
PRIVATE_OUT=""
PASSPHRASE_MODE=ask
IMAGE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file) [[ $# -ge 2 && -n "$2" ]] || die 3 "--env-file requires a value"; ENV_FILE="$2"; shift 2 ;;
        --private-key-out) [[ $# -ge 2 && -n "$2" ]] || die 3 "--private-key-out requires a value"; PRIVATE_OUT="$2"; shift 2 ;;
        --no-passphrase) PASSPHRASE_MODE=none; shift ;;
        --image) [[ $# -ge 2 && -n "$2" ]] || die 3 "--image requires a value"; IMAGE="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) say "unknown option"; usage 3 ;;
    esac
done

if [[ -z "$ENV_FILE" ]]; then
    found=()
    for candidate in .env.max .env.pro .env.lite; do
        [[ -f "$candidate" ]] && found+=("$candidate")
    done
    [[ ${#found[@]} -eq 1 ]] || die 3 "found ${#found[@]} tier env files; pass --env-file"
    ENV_FILE="${found[0]}"
fi
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || die 3 "env file $ENV_FILE is not a regular file"

# Last assignment wins, as with docker compose --env-file. Values are read, never
# evaluated.
env_value() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true; }
KEY_PATH="$(env_value BACKUP_GPG_PUBLIC_KEY_PATH)"
RECIPIENT="$(env_value BACKUP_GPG_RECIPIENT)"
[[ -n "$IMAGE" ]] || IMAGE="$(env_value POSTGRES_IMAGE)"
[[ -n "$IMAGE" ]] || IMAGE="freesdn-postgres:local"

[[ -n "$KEY_PATH" ]] || die 3 "BACKUP_GPG_PUBLIC_KEY_PATH is not set in $ENV_FILE (the tier templates set ./secrets/backup-public.asc)"
case "$KEY_PATH" in
    *$'\n'*|*..*) die 3 "BACKUP_GPG_PUBLIC_KEY_PATH must not contain '..' or newlines" ;;
esac
if [[ -L "$KEY_PATH" ]]; then
    die 3 "$KEY_PATH is a symbolic link; refusing to write through it"
fi
if [[ -d "$KEY_PATH" ]]; then
    die 3 "$KEY_PATH is a DIRECTORY. Docker created it because the file did not exist when the stack started. Remove it (sudo rmdir '$KEY_PATH'), run this helper again, then recreate pg-backup: docker compose --env-file $ENV_FILE up -d pg-backup"
fi
if [[ -e "$KEY_PATH" && ! -f "$KEY_PATH" ]]; then
    die 3 "$KEY_PATH exists and is not a regular file"
fi
if [[ -s "$KEY_PATH" ]]; then
    die 3 "a public key is already installed at $KEY_PATH. To rotate, move it aside first (dumps made so far still need the OLD private key)."
fi
key_dir="$(dirname "$KEY_PATH")"
[[ -d "$key_dir" && ! -L "$key_dir" ]] || die 3 "directory $key_dir does not exist"

if [[ -n "$PRIVATE_OUT" ]]; then
    [[ ! -e "$PRIVATE_OUT" && ! -L "$PRIVATE_OUT" ]] || die 3 "$PRIVATE_OUT already exists; refusing to overwrite"
    out_real="$(cd "$(dirname "$PRIVATE_OUT")" 2>/dev/null && pwd -P)" || die 3 "directory of $PRIVATE_OUT does not exist"
    case "$out_real/" in
        "$(pwd -P)/"*) say "WARNING: $PRIVATE_OUT is inside the FreeSDN tree on this host. Move it OFF this host after this run." ;;
    esac
elif [[ -t 1 ]]; then
    say "NOTE: the private key will be printed on this terminal. Prefer redirecting it:"
    say "      ./scripts/backup-keygen.sh > /path/off/this/host/freesdn-backup-private.asc"
fi

# A recipient that is an e-mail address becomes the key's user ID, so an env file
# that already names one (older templates used backup@example.com) needs no edit.
UID_EMAIL="freesdn-backup@localhost"
RECIPIENT_NOTE=""
if [[ -n "$RECIPIENT" ]]; then
    if [[ "$RECIPIENT" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]; then
        UID_EMAIL="$RECIPIENT"
    else
        RECIPIENT_NOTE="BACKUP_GPG_RECIPIENT in $ENV_FILE does not match the new key. Set it empty (BACKUP_GPG_RECIPIENT=) so pg-backup uses the key in the file, then recreate pg-backup: docker compose --env-file $ENV_FILE up -d pg-backup"
    fi
fi

command -v docker >/dev/null 2>&1 || die 2 "docker not found"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die 2 "image $IMAGE not found; build the stack first (./install.sh) or pass --image"

PASSPHRASE=""
if [[ "$PASSPHRASE_MODE" == ask ]]; then
    if [[ -t 0 ]]; then
        read -r -s -p "Passphrase for the PRIVATE key (min 12 characters): " PASSPHRASE </dev/tty; echo >&2
        read -r -s -p "Repeat passphrase: " again </dev/tty; echo >&2
        [[ "$PASSPHRASE" == "$again" ]] || die 3 "passphrases differ"
        unset again
    else
        IFS= read -r PASSPHRASE || true
    fi
    [[ ${#PASSPHRASE} -ge 12 ]] || die 3 "passphrase must be at least 12 characters (or pass --no-passphrase)"
fi

# Runs inside the throwaway container. Standard input carries the passphrase
# (possibly empty); standard output carries fingerprint, public and private key
# between marker lines and nothing else.
GENERATE='set -euo pipefail
export GNUPGHOME=/tmp/g
mkdir -m 700 "$GNUPGHOME"
IFS= read -r pass || true
protect=(--passphrase "")
if [ -n "$pass" ]; then protect=(--passphrase-fd 3); fi
gpg --batch --pinentry-mode loopback "${protect[@]}" \
    --quick-generate-key "FreeSDN database backup <$UID_EMAIL>" default default never \
    3<<<"$pass" >/dev/null 2>&1
fpr=$(gpg --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: "\$1 == \"fpr\" {print \$10; exit}")
[ -n "$fpr" ]
probe=$(printf probe | gpg --batch --trust-model always --encrypt --recipient "$fpr" 2>/dev/null | wc -c)
[ "$probe" -gt 0 ]
echo "-----FREESDN FINGERPRINT-----"
echo "$fpr"
echo "-----FREESDN PUBLIC-----"
gpg --batch --armor --export "$fpr"
echo "-----FREESDN PRIVATE-----"
gpg --batch --pinentry-mode loopback "${protect[@]}" --armor --export-secret-keys "$fpr" 3<<<"$pass"
echo "-----FREESDN END-----"'

say "Generating the backup key pair in a throwaway container ($IMAGE)..."
if ! OUTPUT="$(printf '%s\n' "$PASSPHRASE" | docker run --rm -i --network none --read-only \
        --tmpfs /tmp:rw,mode=1777,size=16m --user 65534:65534 --cap-drop ALL \
        --security-opt no-new-privileges -e HOME=/tmp -e UID_EMAIL="$UID_EMAIL" \
        --entrypoint /bin/bash "$IMAGE" -c "$GENERATE")"; then
    unset PASSPHRASE
    die 4 "key generation failed inside the container"
fi
unset PASSPHRASE

section() {
    printf '%s\n' "$OUTPUT" | awk -v start="-----FREESDN $1-----" '
        $0 == start {on = 1; next}
        /^-----FREESDN [A-Z]+-----$/ {on = 0}
        on {print}'
}
FPR="$(section FINGERPRINT)"
PUBLIC="$(section PUBLIC)"
PRIVATE="$(section PRIVATE)"
unset OUTPUT
[[ "$FPR" =~ ^[0-9A-F]{40,64}$ ]] || die 4 "generation returned no fingerprint"
[[ "$PUBLIC" == "-----BEGIN PGP PUBLIC KEY BLOCK-----"* ]] || die 4 "generation returned no public key"
[[ "$PRIVATE" == "-----BEGIN PGP PRIVATE KEY BLOCK-----"* ]] || die 4 "generation returned no private key"

# Hand over the private key FIRST: if that fails, nothing is installed and no
# backup is ever encrypted to a key nobody holds.
if [[ -n "$PRIVATE_OUT" ]]; then
    ( set -o noclobber; printf '%s\n' "$PRIVATE" > "$PRIVATE_OUT" ) || die 4 "could not write $PRIVATE_OUT"
    say "Private key written to $PRIVATE_OUT (mode 0600)."
else
    printf '%s\n' "$PRIVATE" || die 4 "could not write the private key to standard output"
fi
unset PRIVATE

# Write the public key in place. ">" keeps the inode of an existing placeholder,
# which is what the running pg-backup container has bind-mounted.
( umask 022; printf '%s\n' "$PUBLIC" > "$KEY_PATH" ) || die 4 "could not write $KEY_PATH"
chmod 0644 "$KEY_PATH"

say ""
say "Backup encryption key installed."
say "  Fingerprint:  $FPR"
say "  Public key:   $KEY_PATH"
say "  Private key:  ${PRIVATE_OUT:-printed on standard output}  <- keep it OFF this host; it is the only way to restore."
say ""
say "pg-backup re-checks the key every 60 seconds; the first encrypted dump follows."
say "Check:  docker compose --env-file $ENV_FILE logs --tail 20 pg-backup"
say "        (FreeSDN also shows the state on the Backups page.)"
if [[ -n "$RECIPIENT_NOTE" ]]; then
    say ""
    say "ACTION NEEDED: $RECIPIENT_NOTE"
fi
