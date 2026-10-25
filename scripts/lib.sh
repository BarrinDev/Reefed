# Reefed - funções comuns dos scripts (carregue com ". scripts/lib.sh" na raiz do repositório).
# shellcheck shell=bash

info() { printf '\033[1;34m[reefed]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[reefed]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[reefed]\033[0m %s\n' "$*" >&2; exit 1; }

[ -f .env ] || fail ".env não encontrado: rode ./setup.sh (ou make setup) primeiro"

# Valor de uma variável do .env, sem as aspas em volta
env_value() {
  local value
  value=$(grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true)
  value=${value%\"}; value=${value#\"}
  value=${value%\'}; value=${value#\'}
  printf '%s' "$value"
}
