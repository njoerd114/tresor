#!/usr/bin/env bash
set -euo pipefail

VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}
export VAULT_ADDR VAULT_TOKEN

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf '%s\n' "missing required command: $1" >&2
    exit 1
  }
}

enable_secret_mount() {
  local output
  if output=$(vault secrets enable -path=secret kv-v2 2>&1); then
    return 0
  fi
  if [[ "${output}" == *"path is already in use at secret/"* ]] || [[ "${output}" == *"existing mount at secret/"* ]]; then
    return 0
  fi
  printf '%s\n' "${output}" >&2
  exit 1
}

require_command vault

enable_secret_mount
vault kv put secret/apps/web/db-creds user=alice password="$(openssl rand -hex 12)" >/dev/null
vault kv put secret/apps/web/api-key key=xyz-123 >/dev/null
vault kv put secret/infra/tls cert='-----BEGIN CERT-----short-----END CERT-----' key='-----BEGIN KEY-----short-----END KEY-----' >/dev/null
vault kv put secret/creds user=tom >/dev/null

printf '%s\n' 'Seeded KV2 paths:'
printf '%s\n' '  secret/apps/web/db-creds'
printf '%s\n' '  secret/apps/web/api-key'
printf '%s\n' '  secret/infra/tls'
printf '%s\n' '  secret/creds'
