#!/bin/sh
set -eu

KEY_FILE="/etc/svc/audit-hmac.key"

if [ ! -s "$KEY_FILE" ]; then
  umask 077
  head -c 32 /dev/urandom > "$KEY_FILE"
fi

exec "/usr/local/bin/svc" \
  --audit-hmac-key-file "$KEY_FILE" \
  --audit-redact "devices=hmac,host=hmac" \
  "$@"
