#!/usr/bin/env bash
# Reefed - aplica as senhas e chaves do .env num Reefed que já está rodando.
#
# O setup.sh gera as senhas na instalação. Para trocar alguma depois:
#   1. mude o valor no .env
#   2. make passwords        (ou scripts/apply-passwords.sh)
#
# Só mudar o .env não basta: o indexer guarda os usuários dele (admin, kibanaserver
# e reefed_api) desde a primeira subida, e o dashboard grava a senha da API do Wazuh
# uma vez só. Este script:
#   1. refaz o config/wazuh_indexer/internal_users.yml com as senhas do .env
#      (./setup.sh --users) e aplica no indexer (securityadmin);
#   2. apaga a conexão com a API do Wazuh guardada pelo dashboard, que ele grava de
#      novo com a senha do .env quando inicia;
#   3. recria o manager, o dashboard e a API do Reefed com o .env novo. Ao iniciar,
#      o manager troca a senha do usuário da API do Wazuh e a senha de registro dos
#      agentes. Os agentes já registrados continuam conectados.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib.sh

DASHBOARD_APP_CONFIG=/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml

running() { docker compose ps --status running --services 2>/dev/null | grep -qx "$1"; }

running wazuh.indexer || fail "o indexer não está rodando (make up)"

# Confere as regras de cada valor antes de mexer em qualquer coisa
problems=()
for name in INDEXER_PASSWORD DASHBOARD_PASSWORD WAZUH_API_PASSWORD REEFED_API_INDEXER_PASSWORD \
            REEFED_API_KEY REEFED_ENROLLMENT_PASSWORD; do
  [ -n "$(env_value "$name")" ] || problems+=("$name está vazio")
done
api_password=$(env_value WAZUH_API_PASSWORD)
if [ -n "$api_password" ] && ! { [ ${#api_password} -ge 8 ] && [[ $api_password =~ [a-z] ]] &&
     [[ $api_password =~ [A-Z] ]] && [[ $api_password =~ [0-9] ]] && [[ $api_password =~ [^A-Za-z0-9] ]]; }; then
  problems+=("WAZUH_API_PASSWORD precisa de 8 ou mais caracteres, com maiúscula, minúscula, número e símbolo")
fi
api_key=$(env_value REEFED_API_KEY)
read_key=$(env_value REEFED_API_READ_KEY)
[ -z "$api_key" ] || [ ${#api_key} -ge 16 ] || problems+=("REEFED_API_KEY precisa de 16 ou mais caracteres")
[ -z "$read_key" ] || [ ${#read_key} -ge 16 ] || problems+=("REEFED_API_READ_KEY precisa de 16 ou mais caracteres")
if [ ${#problems[@]} -gt 0 ]; then
  for problem in "${problems[@]}"; do warn "$problem"; done
  fail "corrija o .env e rode de novo (nada foi alterado)"
fi

# 1. Usuários do indexer
./setup.sh --users >/dev/null
info "aplicando os usuários do indexer (admin, kibanaserver e reefed_api)"
if ! output=$(docker compose exec -T wazuh.indexer bash -c '
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
    dir=/usr/share/wazuh-indexer/config
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
      -f "$dir/opensearch-security/internal_users.yml" -t internalusers \
      -cacert "$dir/certs/root-ca.pem" -cert "$dir/certs/admin.pem" -key "$dir/certs/admin-key.pem" \
      -h 127.0.0.1 -p 9200 -icl -nhnv' 2>&1); then
  printf '%s\n' "$output" >&2
  fail "o indexer recusou os usuários (saída acima)"
fi

# 2. Conexão do dashboard com a API do Wazuh (o bloco "hosts" do wazuh.yml)
if running wazuh.dashboard; then
  docker compose exec -T wazuh.dashboard sed -i '/^hosts:/,$d' "$DASHBOARD_APP_CONFIG"
fi

# 3. Serviços que usam as senhas
info "recriando manager, dashboard e API do Reefed com o .env"
docker compose up -d --no-deps --force-recreate wazuh.manager wazuh.dashboard reefed-api
scripts/status.sh
