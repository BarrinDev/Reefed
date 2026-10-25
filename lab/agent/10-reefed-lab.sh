#!/usr/bin/with-contenv bash
# shellcheck shell=bash
# Reefed lab - roda no start do container do agente, depois que o init oficial
# já preencheu o ossec.conf (endereço do manager, nome e grupo vindos das
# variáveis WAZUH_*). Aplica os mesmos ajustes do Reefed de um servidor real
# e deixa a varredura de integridade e a verificação de skip-grant-tables mais
# rápidas, para o laboratório não ter que esperar.
set -euo pipefail

# REEFED_LAB_DB = postgresql | mysql | mariadb (definido no compose do lab)
DB=${REEFED_LAB_DB:-}
FLAGS_INTERVAL=${REEFED_LAB_FLAGS_INTERVAL:-30}

args=(--configure-only --flags-interval "$FLAGS_INTERVAL")
[ -n "$DB" ] && args+=(--db "$DB")
/opt/reefed/install-agent.sh "${args[@]}"

# No laboratório a varredura de integridade roda a cada 60 s (em produção, 12 h)
# para os testes de FIM não demorarem. syscheck já vem do grupo; aqui só muda a
# frequência da varredura agendada, acrescentando um bloco local.
conf=/var/ossec/etc/ossec.conf
if ! grep -q "REEFED-LAB-SYSCHECK" "$conf"; then
  cat >> "$conf" <<'EOF'
<!-- REEFED-LAB-SYSCHECK -->
<ossec_config>
  <syscheck>
    <frequency>60</frequency>
    <scan_on_start>yes</scan_on_start>
  </syscheck>
</ossec_config>
EOF
fi
echo "[reefed-lab] ossec.conf ajustado para o laboratório (db=${DB:-nenhum}, flags=${FLAGS_INTERVAL}s)"
