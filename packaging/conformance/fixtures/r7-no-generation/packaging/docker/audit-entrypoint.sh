#!/bin/sh
set -eu

KEY_FILE="/etc/svc/audit-hmac.key"

exec "/usr/local/bin/svc" \
  --audit-hmac-key-file "$KEY_FILE" \
  --audit-redact "devices=hmac,host=hmac" \
  "$@"
