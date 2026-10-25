#!/usr/bin/env bash
# Reefed - instala e registra o agente do Wazuh num servidor Linux.
#
# Servidor comum:
#   sudo ./install-agent.sh --manager 10.0.0.10 --password SENHA
#
# Servidor de banco (escolha o banco):
#   sudo ./install-agent.sh --manager 10.0.0.10 --password SENHA --db postgresql
#
# Opções:
#   --manager IP|NOME   endereço do servidor do Reefed (obrigatório, menos com --configure-only)
#   --password SENHA    REEFED_ENROLLMENT_PASSWORD do .env do servidor do Reefed
#   --name NOME         nome do agente (padrão: hostname)
#   --groups LISTA      grupos do agente (padrão: linux, ou linux,database,<banco> com --db)
#   --db BANCO          postgresql, mysql ou mariadb: servidor de banco
#   --version X.Y.Z     versão do agente (padrão: 4.14.9; não pode ser maior que a do manager)
#   --no-firewall       não instala o iptables (o Active Response precisa dele para bloquear IPs)
#   --flags-interval N  segundos entre as verificações de skip-grant-tables (padrão: 300)
#   --configure-only    não instala nem registra; só aplica os ajustes do Reefed no ossec.conf
#
# O que os ajustes do Reefed fazem no /var/ossec/etc/ossec.conf:
#   - tiram ".log$" da lista de arquivos ignorados pelo FIM, para o Reefed saber
#     quando alguém apaga um log do banco (regra 110804);
#   - em servidor MySQL/MariaDB, acrescentam o comando que procura skip-grant-tables
#     na linha de comando e na configuração do banco (regra 110056). Comandos não
#     podem vir da configuração centralizada do manager, por segurança.
set -euo pipefail

WAZUH_VERSION=4.14.9
MANAGER=""
PASSWORD=""
AGENT_NAME="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo wazuh-agent)"
AGENT_GROUPS=""
DB=""
FIREWALL=yes
FLAGS_INTERVAL=300
CONFIGURE_ONLY=no
OSSEC_CONF=/var/ossec/etc/ossec.conf

info() { printf '\033[1;34m[reefed]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[reefed]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[reefed]\033[0m %s\n' "$*" >&2; exit 1; }
usage() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --manager) MANAGER=${2:?}; shift 2 ;;
    --password) PASSWORD=${2:?}; shift 2 ;;
    --name) AGENT_NAME=${2:?}; shift 2 ;;
    --groups) AGENT_GROUPS=${2:?}; shift 2 ;;
    --db) DB=${2:?}; shift 2 ;;
    --version) WAZUH_VERSION=${2:?}; shift 2 ;;
    --no-firewall) FIREWALL=no; shift ;;
    --flags-interval) FLAGS_INTERVAL=${2:?}; shift 2 ;;
    --configure-only) CONFIGURE_ONLY=yes; shift ;;
    -h|--help) usage 0 ;;
    *) warn "opção desconhecida: $1"; usage 1 ;;
  esac
done

case "$DB" in
  ""|postgresql|mysql|mariadb) ;;
  *) fail "--db aceita postgresql, mysql ou mariadb" ;;
esac
case "$FLAGS_INTERVAL" in
  ''|*[!0-9]*) fail "--flags-interval precisa ser um número de segundos" ;;
esac
if [ -z "$AGENT_GROUPS" ]; then
  AGENT_GROUPS=linux
  [ -n "$DB" ] && AGENT_GROUPS="linux,database,$DB"
fi
[ "$(id -u)" = 0 ] || fail "rode como root (sudo)"

# ---------------------------------------------------------------------------
# Ajustes do Reefed no ossec.conf (idempotente: pode rodar de novo)
LOCAL_BEGIN="<!-- REEFED-LOCAL-BEGIN: gerado pelo install-agent.sh do Reefed -->"
LOCAL_END="<!-- REEFED-LOCAL-END -->"

configure_reefed() {
  [ -f "$OSSEC_CONF" ] || fail "$OSSEC_CONF não encontrado (o agente está instalado?)"
  cp -p "$OSSEC_CONF" "$OSSEC_CONF.reefed-bak"

  # FIM: deixa de ignorar *.log (continua ignorando *.swp)
  sed -i 's#<ignore type="sregex">\.log\$|\.swp\$</ignore>#<ignore type="sregex">.swp$</ignore>#' "$OSSEC_CONF"

  # Bloco local anterior do Reefed sai antes de escrever o novo
  sed -i "\#^${LOCAL_BEGIN}\$#,\#^${LOCAL_END}\$#d" "$OSSEC_CONF"

  if [ "$DB" = mysql ] || [ "$DB" = mariadb ]; then
    cat >> "$OSSEC_CONF" <<EOF
<!-- REEFED-LOCAL-BEGIN: gerado pelo install-agent.sh do Reefed -->
<ossec_config>
  <!-- A cada $FLAGS_INTERVAL segundos procura skip-grant-tables na linha de comando do
       mysqld/mariadbd e nos arquivos de configuração (regra 110056).
       O comando usa if/then/else de propósito: o Wazuh não decodifica entidades XML
       antes de executar, e um E lógico do shell escrito como entidade chegaria
       quebrado ao shell (erro de sintaxe e nenhuma saída). -->
  <localfile>
    <log_format>full_command</log_format>
    <alias>reefed-db-flags</alias>
    <frequency>$FLAGS_INTERVAL</frequency>
    <command>if ( ps -eo args= 2>/dev/null | grep -E 'mysqld|mariadbd' | grep -v grep ; cat /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/*.cnf /etc/mysql/*/*.cnf /etc/my.cnf.d/*.cnf 2>/dev/null | grep -vE '^[[:space:]]*[#;]' ) | grep -qiE -- '(^|[[:space:]]|--)skip[-_]grant[-_]tables' ; then echo REEFED_SKIP_GRANT_TABLES=1 ; else echo REEFED_SKIP_GRANT_TABLES=0 ; fi</command>
  </localfile>
</ossec_config>
<!-- REEFED-LOCAL-END -->
EOF
  fi
  info "ajustes do Reefed aplicados em $OSSEC_CONF (cópia anterior: $OSSEC_CONF.reefed-bak)"
}

install_firewall() {
  if command -v iptables >/dev/null 2>&1; then
    return
  fi
  info "instalando o iptables (usado pelo Active Response para bloquear IPs)"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y iptables-nft >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y iptables >/dev/null
  else
    warn "não sei instalar o iptables nesta distribuição; o bloqueio automático não vai funcionar"
  fi
}

if [ "$CONFIGURE_ONLY" = yes ]; then
  configure_reefed
  exit 0
fi

[ -n "$MANAGER" ] || fail "informe --manager"
[ -n "$PASSWORD" ] || warn "sem --password: só funciona se o manager não exigir senha de registro"

# ---------------------------------------------------------------------------
# Instalação do pacote (repositório oficial do Wazuh)
export WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUPS"
[ -n "$PASSWORD" ] && export WAZUH_REGISTRATION_PASSWORD="$PASSWORD"

if [ -x /var/ossec/bin/wazuh-control ]; then
  info "agente do Wazuh já instalado; registrando de novo com os grupos $AGENT_GROUPS"
  sed -i "s#<address>[^<]*</address>#<address>$MANAGER</address>#" "$OSSEC_CONF"
  /var/ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" -G "$AGENT_GROUPS" ${PASSWORD:+-P "$PASSWORD"}
elif command -v apt-get >/dev/null 2>&1; then
  info "instalando wazuh-agent $WAZUH_VERSION (apt)"
  apt-get install -y curl gnupg >/dev/null
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH |
    gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import >/dev/null 2>&1
  chmod 644 /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update >/dev/null
  apt-get install -y "wazuh-agent=$WAZUH_VERSION-1" >/dev/null
  apt-mark hold wazuh-agent >/dev/null   # atualizar o agente só junto com o manager
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  info "instalando wazuh-agent $WAZUH_VERSION (rpm)"
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
  cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
  if command -v dnf >/dev/null 2>&1; then dnf install -y "wazuh-agent-$WAZUH_VERSION-1" >/dev/null
  else yum install -y "wazuh-agent-$WAZUH_VERSION-1" >/dev/null; fi
  sed -i 's/^enabled=1/enabled=0/' /etc/yum.repos.d/wazuh.repo   # atualizar só junto com o manager
else
  fail "distribuição sem apt, dnf ou yum; instale o agente pelo manual do Wazuh e rode com --configure-only"
fi

configure_reefed
[ -n "$DB" ] && [ "$FIREWALL" = yes ] && install_firewall

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable wazuh-agent >/dev/null 2>&1
  systemctl restart wazuh-agent
else
  /var/ossec/bin/wazuh-control restart
fi

info "agente $AGENT_NAME instalado nos grupos $AGENT_GROUPS"
info "confira no servidor do Reefed: make agents   (ou no dashboard, em Agents)"
if [ -n "$DB" ]; then
  info "falta configurar o log do $DB: veja agents/database/$DB/ e docs/agentes.md"
fi
