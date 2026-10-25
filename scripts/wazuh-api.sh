#!/usr/bin/env bash
# Reefed - chama a API do Wazuh de dentro do container do manager (a porta 55000
# fica fechada para fora da máquina; para o seu sistema, use a API do Reefed).
#
#   scripts/wazuh-api.sh GET '/agents?select=name,status'
#   scripts/wazuh-api.sh DELETE '/agents?agents_list=005&status=all&older_than=0s'
#   scripts/wazuh-api.sh PUT '/active-response?agents_list=001' '{"command":"!firewall-drop", ...}'
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib.sh

method=${1:?uso: scripts/wazuh-api.sh MÉTODO CAMINHO [JSON]}
path=${2:?uso: scripts/wazuh-api.sh MÉTODO CAMINHO [JSON]}
body=${3:-}
user=$(env_value WAZUH_API_USER)

docker compose exec -T -e U="${user:-wazuh-wui}" -e P="$(env_value WAZUH_API_PASSWORD)" \
    -e M="$method" -e A="$path" -e B="$body" wazuh.manager sh -c '
  token=$(curl -sk -u "$U:$P" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
  if [ -n "$B" ]; then
    curl -sk -X "$M" -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "$B" "https://localhost:55000$A"
  else
    curl -sk -X "$M" -H "Authorization: Bearer $token" "https://localhost:55000$A"
  fi'
echo
