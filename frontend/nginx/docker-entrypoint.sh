#!/bin/sh
# FreeSDN - Nginx Config Selector Entrypoint
# Selects the correct nginx config based on SSL_MODE environment variable.
# Runs before nginx starts.

set -e

SSL_MODE="${SSL_MODE:-off}"
TEMPLATES="/etc/nginx/templates"
TARGET="/etc/nginx/conf.d/default.conf"

case "$SSL_MODE" in
    off)
        echo "[entrypoint] SSL_MODE=off - using HTTP-only configuration"
        cp "$TEMPLATES/http-only.conf" "$TARGET"
        ;;
    self-signed|letsencrypt)
        echo "[entrypoint] SSL_MODE=$SSL_MODE - using SSL/TLS configuration"
        # Verify cert files exist before starting with SSL
        if [ ! -f /etc/nginx/ssl/fullchain.pem ] || [ ! -f /etc/nginx/ssl/privkey.pem ]; then
            echo "[entrypoint] WARNING: SSL certificates not found at /etc/nginx/ssl/"
            echo "[entrypoint]   Expected: fullchain.pem, privkey.pem"
            echo "[entrypoint]   Falling back to HTTP-only mode"
            cp "$TEMPLATES/http-only.conf" "$TARGET"
        else
            # Copy certs from read-only bind mount to /tmp/ssl/ (tmpfs, writable).
            # This ensures the non-root nginx user can read the private key
            # without weakening file permissions on the host.
            mkdir -p /tmp/ssl
            cp /etc/nginx/ssl/fullchain.pem /tmp/ssl/fullchain.pem
            cp /etc/nginx/ssl/privkey.pem /tmp/ssl/privkey.pem
            chmod 644 /tmp/ssl/fullchain.pem
            chmod 600 /tmp/ssl/privkey.pem

            cp "$TEMPLATES/ssl.conf" "$TARGET"

            # Check for DH params - not fatal but warn
            if [ ! -f /etc/nginx/ssl/dhparam.pem ]; then
                echo "[entrypoint] WARNING: DH parameters not found at /etc/nginx/ssl/dhparam.pem"
                echo "[entrypoint]   HTTPS will work but with reduced forward secrecy"
                echo "[entrypoint]   Generate with: openssl dhparam -out docker/ssl/dhparam.pem 2048"
                # Remove the dhparam directive so nginx doesn't fail
                sed -i '/ssl_dhparam/d' "$TARGET"
            else
                cp /etc/nginx/ssl/dhparam.pem /tmp/ssl/dhparam.pem
                chmod 644 /tmp/ssl/dhparam.pem
            fi
            # Disable OCSP stapling for self-signed certs (no issuer CA to validate)
            # This prevents the nginx [warn] "ssl_stapling ignored" message
            if [ "$SSL_MODE" = "self-signed" ]; then
                sed -i '/ssl_stapling/d' "$TARGET"
                sed -i '/ssl_stapling_verify/d' "$TARGET"
                echo "[entrypoint] OCSP stapling disabled (not supported for self-signed certs)"
            fi

            echo "[entrypoint] SSL certificates loaded into runtime directory"
        fi
        ;;
    *)
        echo "[entrypoint] ERROR: Unknown SSL_MODE='$SSL_MODE'"
        echo "[entrypoint]   Valid values: off, self-signed, letsencrypt"
        exit 1
        ;;
esac

echo "[entrypoint] Starting nginx..."
exec "$@"
