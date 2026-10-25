#!/usr/bin/env bash
# Reefed - restaura um backup feito pelo scripts/backup.sh.
#
#   scripts/restore.sh PASTA_DO_BACKUP [--yes]
#
# APAGA os alertas, os agentes registrados e a configuração atuais e põe os do backup no
# lugar, junto com o .env, os certificados e os usuários do indexer daquele backup.
# Também serve para levar o Reefed para outra máquina: clone o repositório, copie a
# pasta do backup e rode este script (sem o setup.sh). --yes não pergunta nada.
set -euo pipefail
cd "$(dirname "$0")/.."

info() { printf '\033[1;34m[reefed]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[reefed]\033[0m %s\n' "$*" >&2; exit 1; }

src=${1:?uso: scripts/restore.sh PASTA_DO_BACKUP [--yes]}
[ -f "$src/config.tar.gz" ] || fail "$src/config.tar.gz não encontrado (a pasta veio do scripts/backup.sh?)"
src=$(cd "$src" && pwd -P)
ls "$src"/volume-*.tar.gz >/dev/null 2>&1 || fail "nenhum volume-*.tar.gz em $src"

if [ "${2:-}" != --yes ]; then
  printf 'Os dados atuais do Reefed serão apagados e trocados pelos de %s. Continuar? [s/N] ' "$src"
  read -r answer
  case "$answer" in s|S|sim|Sim|SIM) ;; *) fail "cancelado; nada foi alterado" ;; esac
fi

# Versão do Wazuh do backup (a imagem do manager tem o GNU tar que restaura donos e permissões)
version=$(tar -xzOf "$src/config.tar.gz" .env | sed -n 's/^WAZUH_VERSION=//p' | tail -1 | tr -d "\"'")
image="wazuh/wazuh-manager:${version:-4.14.9}"
docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null

if [ -f .env ]; then
  info "parando o Reefed"
  docker compose down
fi

info "restaurando o .env, os certificados e os usuários do indexer"
docker run --rm -v "$PWD:/reefed" -v "$src:/backup:ro" --entrypoint tar "$image" \
  -xzf /backup/config.tar.gz -C /reefed

project=$(docker compose config 2>/dev/null | sed -n 's/^name: //p')
project=${project:-reefed}
# Cria os volumes (e os containers, sem iniciar) como o docker compose espera encontrar
docker compose create >/dev/null

for archive in "$src"/volume-*.tar.gz; do
  name=$(basename "$archive" .tar.gz)
  name=${name#volume-}
  volume="${project}_$name"
  docker volume inspect "$volume" >/dev/null 2>&1 || fail "volume $volume não existe nesta versão do docker-compose.yml"
  info "restaurando o volume $name"
  docker run --rm -v "$volume:/volume" -v "$src:/backup:ro" --entrypoint sh "$image" \
    -c 'find /volume -mindepth 1 -delete && tar -xzf "/backup/$1" -C /volume' sh "$(basename "$archive")"
done

info "subindo o Reefed com os dados do backup"
docker compose up -d
scripts/status.sh
