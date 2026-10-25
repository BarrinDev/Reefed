#!/usr/bin/env bash
# Reefed - laboratório de ataques (veja lab/README.md). Usado pelo Makefile:
#
#   scripts/lab.sh run        tudo do zero: limpa, sobe, ataca e valida (make lab)
#   scripts/lab.sh up         Reefed no modo laboratório + bancos, agentes e receptor falso
#   scripts/lab.sh attack     tráfego normal do app e depois os ataques
#   scripts/lab.sh validate   confere se os ataques viraram alertas, bloqueio e notificações
#   scripts/lab.sh down       apaga o laboratório e volta o Reefed à configuração normal
#
# No modo laboratório o manager manda os alertas para um receptor falso (nada sai
# para Telegram, Slack ou e-mail de verdade) e usa as listas de lab/lists.
# NO_BUILD=1 usa as imagens já construídas (sem internet).
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib.sh

# Compose principal com o ajuste do laboratório. Um docker-compose.override.yml
# local (portas, limites da máquina...) entra junto, como no "docker compose" sem -f.
MAIN=(docker compose -f docker-compose.yml)
if [ -f docker-compose.override.yml ]; then MAIN+=(-f docker-compose.override.yml); fi
MAIN+=(-f lab/manager.override.yml)
LAB=(docker compose --project-directory lab -f lab/docker-compose.yml --env-file "$PWD/.env")
BUILD=--build
if [ -n "${NO_BUILD:-}" ]; then BUILD=""; fi
START_FILE=lab/.inicio-ataque
LAB_AGENTS_QUERY="q=name=lab-postgres,name=lab-mysql,name=lab-mariadb"

# Espera um comando dar certo, mostrando o que está esperando
wait_until() {  # wait_until SEGUNDOS "descrição" comando...
  local timeout=$1 what=$2 deadline
  shift 2
  deadline=$((SECONDS + timeout))
  info "esperando: $what"
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$deadline" ] || fail "tempo esgotado esperando: $what"
    sleep 3
  done
}

manager_api_ready() { scripts/wazuh-api.sh GET / | grep -q '"api_version"'; }

lab_agents_active() {
  scripts/wazuh-api.sh GET "/agents?status=active&select=name&$LAB_AGENTS_QUERY" |
    grep -Eq '"total_affected_items": *3[,}]'
}

# O agente do MySQL/MariaDB já mandou a primeira verificação de skip-grant-tables
# (referência "0"); sem ela, o skip-grant-tables gravado pelo ataque viraria a
# referência e não geraria alerta.
flags_baseline() {
  "${MAIN[@]}" exec -T wazuh.manager grep -qs "REEFED_SKIP_GRANT_TABLES=0" "/var/ossec/queue/diff/$1/110057/last-entry"
}

# A primeira varredura de integridade (FIM) terminou; antes disso, um arquivo
# alterado pelo ataque entraria como estado inicial, sem alerta.
fim_baseline() {
  "${LAB[@]}" exec -T "$1" grep -qs "File integrity monitoring scan ended" /var/ossec/logs/ossec.log
}

# Remove do manager os agentes do laboratório (cada subida registra agentes novos
# com os mesmos nomes).
remove_lab_agents() {
  scripts/wazuh-api.sh DELETE "/agents?agents_list=all&status=all&older_than=0s&purge=true&$LAB_AGENTS_QUERY" >/dev/null || true
}

lab_up() {
  info "subindo o Reefed no modo laboratório (alertas vão para o receptor falso)"
  "${MAIN[@]}" up -d ${BUILD:+"$BUILD"}
  wait_until 600 "API do Wazuh no manager" manager_api_ready
  if ! "${LAB[@]}" ps --status running --services 2>/dev/null | grep -q -- '-agent$'; then
    remove_lab_agents
  fi
  info "subindo os bancos, os agentes e o receptor falso"
  if [ -n "$BUILD" ]; then
    "${LAB[@]}" --profile attack --profile validate build
  fi
  "${LAB[@]}" up -d
  wait_until 300 "os 3 agentes do laboratório conectarem" lab_agents_active
  if [ -f "$START_FILE" ]; then
    # Bancos que já foram atacados: o skip-grant-tables gravado pelo ataque já é a
    # referência, então não há primeira verificação "limpa" para esperar
    warn "este laboratório já foi atacado; para atacar do zero: make lab-down && make lab-up (ou make lab)"
    return
  fi
  wait_until 300 "primeira verificação de skip-grant-tables (MySQL)" flags_baseline lab-mysql
  wait_until 300 "primeira verificação de skip-grant-tables (MariaDB)" flags_baseline lab-mariadb
  for service in pg-agent my-agent maria-agent; do
    wait_until 300 "primeira varredura de integridade ($service)" fim_baseline "$service"
  done
  info "laboratório pronto. Próximo passo: make lab-attack"
}

lab_attack() {
  if [ -f "$START_FILE" ]; then
    warn "este laboratório já foi atacado: skip-grant-tables (110056) e log apagado (110804)"
    warn "só aparecem de novo depois de recomeçar: make lab-down && make lab-up (ou make lab)"
  fi
  date -u +%Y-%m-%dT%H:%M:%SZ > "$START_FILE"
  "${LAB[@]}" --profile attack run --rm app
  "${LAB[@]}" --profile attack run --rm --no-deps attacker
  info "ataques feitos. Os alertas levam até 2 minutos para aparecer; confira com: make lab-validate"
}

lab_validate() {
  local since=""
  [ -f "$START_FILE" ] && since=$(cat "$START_FILE")
  REEFED_LAB_SINCE="$since" "${LAB[@]}" --profile validate run --rm validator "$@"
}

lab_clean() {
  "${LAB[@]}" --profile attack --profile validate down -v --remove-orphans
  if "${MAIN[@]}" ps --status running --services 2>/dev/null | grep -qx wazuh.manager; then
    remove_lab_agents
  fi
  rm -f "$START_FILE"
}

lab_down() {
  lab_clean
  info "voltando o Reefed à configuração normal (alertas para os canais do .env)"
  docker compose up -d
}

case "${1:-}" in
  up) lab_up ;;
  attack) lab_attack ;;
  validate) shift; lab_validate "$@" ;;
  down) lab_down ;;
  run)
    lab_clean
    lab_up
    lab_attack
    lab_validate
    ;;
  *) awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 1 ;;
esac
