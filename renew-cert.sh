#!/bin/bash
# Renew the Tailscale TLS certificate for the vault server.
# Edit the three variables below to match your setup, then run with sudo.
set -e

VAULT_DIR="/path/to/vault"           # directory containing server.py
VAULT_USER="your_username"            # OS user that runs the vault service
TAILSCALE_HOST="node.tailnet.ts.net"  # your full Tailscale DNS name

tailscale cert \
  --cert-file "$VAULT_DIR/cert.pem" \
  --key-file  "$VAULT_DIR/key.pem" \
  "$TAILSCALE_HOST"

chown "$VAULT_USER:$VAULT_USER" "$VAULT_DIR/cert.pem" "$VAULT_DIR/key.pem"
chmod 644 "$VAULT_DIR/cert.pem"
chmod 600 "$VAULT_DIR/key.pem"
systemctl restart vault
