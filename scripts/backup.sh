#!/usr/bin/env bash
# Reefed - backup completo: o .env, os certificados, os usuários do indexer e todos os
# volumes (alertas, agentes registrados, configuração do manager e do dashboard).
#
#   scripts/backup.sh [PASTA]       padrão: backups/AAAA-MM-DD_HHMMSS (make backup)
#
# Para a cópia ficar consistente, o Reefed fica parado enquanto os volumes são copiados
# (de segundos a alguns minutos, conforme o volume de alertas). Os agentes guardam os
# eventos e mandam quando o manager volta. Restaure com scripts/restore.sh.
#
# O backup tem todas as senhas e as chaves privadas dos certificados: os arquivos ficam
# só com permissão do seu usuário. Guarde uma cópia fora do servidor.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib.sh

project=$(docker compose config 2>/dev/null | sed -n 's/^name: //p')
project=${project:-reefed}
version=$(env_value WAZUH_VERSION)
image="wazuh/wazuh-manager:${version:-4.14.9}"   # tem o GNU tar e já está na máquina
dest=${1:-backups/$(date +%Y-%m-%d_%H%M%S)}

mapfile -t volumes < <(docker volume ls -q --filter "label=com.docker.compose.project=$project")
[ ${#volumes[@]} -gt 0 ] || fail "nenhum volume do Reefed encontrado (ele já subiu alguma vez?)"
mkdir -p "$dest"
dest=$(cd "$dest" && pwd -P)

mapfile -t running < <(docker compose ps --status running --services 2>/dev/null)
if [ ${#running[@]} -gt 0 ]; then
  info "parando o Reefed durante a cópia"
  docker compose stop
  # Volta mesmo se a cópia falhar no meio
  trap 'info "subindo o Reefed de novo"; docker compose start "${running[@]}"' EXIT
fi

for volume in "${volumes[@]}"; do
  name=${volume#"${project}_"}
  info "copiando o volume $name"
  # sockets do Wazuh não entram no tar (são recriados quando o manager inicia)
  docker run --rm -v "$volume:/volume:ro" -v "$dest:/backup" --entrypoint tar "$image" \
    --warning=no-file-ignored -czf "/backup/volume-$name.tar.gz" -C /volume .
done

info "copiando o .env, os certificados e os usuários do indexer"
docker run --rm -v "$PWD:/reefed:ro" -v "$dest:/backup" --entrypoint tar "$image" \
  -czf /backup/config.tar.gz -C /reefed .env config/wazuh_indexer_ssl_certs config/wazuh_indexer/internal_users.yml

docker run --rm -v "$dest:/backup" --entrypoint sh "$image" \
  -c "chown $(id -u):$(id -g) /backup/*.tar.gz && chmod 600 /backup/*.tar.gz"

info "backup em $dest ($(du -sh "$dest" | cut -f1))"
