#!/bin/bash
# Reefed - preparação do Wazuh manager.
#
# O container oficial roda os scripts de /entrypoint-scripts antes de iniciar o
# Wazuh. Este script:
#   1. instala decoders, regras, listas, integrações e configs de grupo do Reefed
#      (montados em /reefed/wazuh, somente leitura);
#   2. aplica o horário comercial do .env nas regras de horário;
#   3. gera /var/ossec/etc/ossec.conf a partir do modelo, preenchendo integrações,
#      Active Response, white_list, syslog e senha de registro de agentes.
#
# Também pode ser rodado com o manager no ar (make deploy-rules); nesse caso,
# reinicie o Wazuh depois: /var/ossec/bin/wazuh-control restart
set -euo pipefail

SRC=/reefed/wazuh
OSSEC=/var/ossec
# Modelo do ossec.conf. A pasta config/wazuh_manager é montada inteira: montar só o
# arquivo prenderia o container na versão antiga quando um editor salva por cima.
TEMPLATE=/reefed/manager/ossec.conf
PYTHON=$OSSEC/framework/python/bin/python3

log() { echo "[reefed] $*"; }

if [ ! -d "$SRC" ]; then
  log "pasta $SRC não montada, nada a fazer"
  exit 0
fi

# Copia os arquivos que casam com o padrão e apaga os que saíram do repositório.
sync_files() {
  local src_dir=$1 dst_dir=$2 pattern=$3 owner=$4 mode=$5
  mkdir -p "$dst_dir"
  local f
  for f in "$dst_dir"/$pattern; do
    [ -e "$f" ] || continue
    case "$f" in *.cdb) continue ;; esac
    if [ ! -e "$src_dir/$(basename "$f")" ]; then
      rm -f "$f" "$f.cdb"
      log "removido $(basename "$f")"
    fi
  done
  for f in "$src_dir"/$pattern; do
    [ -f "$f" ] || continue
    install -o "${owner%%:*}" -g "${owner##*:}" -m "$mode" "$f" "$dst_dir/"
  done
}

# 1. Conteúdo do Reefed
sync_files "$SRC/decoders" "$OSSEC/etc/decoders" '*reefed*.xml' wazuh:wazuh 660
sync_files "$SRC/rules" "$OSSEC/etc/rules" '*reefed*.xml' wazuh:wazuh 660
mkdir -p "$OSSEC/etc/lists/reefed"
for f in "$SRC"/lists/*; do
  case "$f" in *.md) continue ;; esac
  install -o wazuh -g wazuh -m 660 "$f" "$OSSEC/etc/lists/reefed/"
done
chown wazuh:wazuh "$OSSEC/etc/lists/reefed"
sync_files "$SRC/integrations" "$OSSEC/integrations" 'custom-reefed-*' root:wazuh 750

# Configuração centralizada dos agentes (um diretório por grupo)
for dir in "$SRC"/shared/*/; do
  [ -d "$dir" ] || continue
  group=$(basename "$dir")
  mkdir -p "$OSSEC/etc/shared/$group"
  install -o wazuh -g wazuh -m 660 "$dir/agent.conf" "$OSSEC/etc/shared/$group/agent.conf"
  chown wazuh:wazuh "$OSSEC/etc/shared/$group"
  chmod 770 "$OSSEC/etc/shared/$group"
done
log "decoders, regras, listas, integrações e grupos de agentes instalados"

# 2. Horário comercial (formato do Wazuh: "20:00 - 07:00"; dias: "weekends", "sat, sun")
hours_file="$OSSEC/etc/rules/reefed-0900-horario_rules.xml"
if [ -f "$hours_file" ]; then
  off_hours=${REEFED_OFF_HOURS:-20:00 - 07:00}
  off_days=${REEFED_OFF_DAYS:-weekends}
  if ! [[ "$off_hours" =~ ^[0-2][0-9]:[0-5][0-9]\ *-\ *[0-2][0-9]:[0-5][0-9]$ ]]; then
    log "REEFED_OFF_HOURS inválido ('$off_hours'), usando 20:00 - 07:00"
    off_hours="20:00 - 07:00"
  fi
  if ! [[ "$off_days" =~ ^!?[A-Za-z]+([\ ,]+[A-Za-z]+)*$ ]]; then
    log "REEFED_OFF_DAYS inválido ('$off_days'), usando weekends"
    off_days="weekends"
  fi
  sed -i -E "s|(<var name=\"REEFED_OFF_HOURS\">)[^<]*(</var>)|\1${off_hours}\2|; s|(<var name=\"REEFED_OFF_DAYS\">)[^<]*(</var>)|\1${off_days}\2|" "$hours_file"
  log "fora do expediente: $off_hours, dias: $off_days (TZ=${TZ:-UTC})"
fi

# Filebeat: o id de cada alerta no indexer passa a ser a impressão digital da linha do
# alerts.json. Se a mesma linha for mandada de novo (backup restaurado, registro do
# Filebeat perdido), o indexer recusa a cópia em vez de duplicar o alerta. Vale a
# partir do próximo início do Filebeat (quando o container sobe).
filebeat_conf=/etc/filebeat/filebeat.yml
if [ -f "$filebeat_conf" ] && ! grep -q '@metadata._id' "$filebeat_conf"; then
  if grep -q '^processors:' "$filebeat_conf"; then
    log "filebeat.yml já tem processors; id dos alertas não alterado"
  else
    cat >> "$filebeat_conf" <<'EOF'

# Reefed: id do alerta = impressão digital da linha (evita alerta duplicado no indexer)
processors:
  - fingerprint:
      fields: ["message"]
      target_field: "@metadata._id"
EOF
    log "filebeat: id dos alertas pela impressão digital da linha (sem duplicados)"
  fi
fi

# Senha de registro dos agentes
if [ -n "${REEFED_ENROLLMENT_PASSWORD:-}" ]; then
  printf '%s\n' "$REEFED_ENROLLMENT_PASSWORD" > "$OSSEC/etc/authd.pass"
  chown root:wazuh "$OSSEC/etc/authd.pass"
  chmod 640 "$OSSEC/etc/authd.pass"
else
  rm -f "$OSSEC/etc/authd.pass"
fi

# 3. ossec.conf
if [ ! -f "$TEMPLATE" ]; then
  log "modelo $TEMPLATE não encontrado; ossec.conf não foi alterado"
  exit 0
fi

"$PYTHON" - "$TEMPLATE" "$OSSEC/etc/ossec.conf" "$OSSEC/etc/lists/reefed/trusted-db-clients" <<'PY'
import ipaddress
import json
import os
import sys
from xml.sax.saxutils import escape

template, target, trusted_path = sys.argv[1:4]
env = os.environ.get
conf = open(template, encoding="utf-8").read()


def level(name, default):
    value = env(name, "") or str(default)
    return value if value.isdigit() and 1 <= int(value) <= 16 else str(default)


def integration(name, level_value, api_key=None, hook_url=None, options=None, group=None):
    lines = ["  <integration>", f"    <name>{escape(name)}</name>"]
    if hook_url:
        lines.append(f"    <hook_url>{escape(hook_url)}</hook_url>")
    if api_key:
        lines.append(f"    <api_key>{escape(api_key)}</api_key>")
    lines.append(f"    <level>{level_value}</level>")
    if group:
        lines.append(f"    <group>{escape(group)}</group>")
    lines.append("    <alert_format>json</alert_format>")
    if options:
        lines.append(f"    <options>{escape(json.dumps(options, ensure_ascii=False))}</options>")
    lines.append("  </integration>")
    return "\n".join(lines)


blocks, enabled = [], []
group = env("REEFED_NOTIFY_GROUP", "").strip() or None
dashboard = env("REEFED_DASHBOARD_URL", "").strip()
# Alertas iguais (mesma regra, servidor e origem) viram uma mensagem por janela
dedup = (env("REEFED_ALERT_DEDUP_SECONDS", "") or "600").strip()
dedup = int(dedup) if dedup.isdigit() else 600

if env("TELEGRAM_BOT_TOKEN") and env("TELEGRAM_CHAT_ID"):
    options = {"chat_id": env("TELEGRAM_CHAT_ID"), "dashboard_url": dashboard, "dedup_seconds": dedup}
    if env("TELEGRAM_API_URL"):  # outro endereço da API do Telegram (proxy ou testes)
        options["api_url"] = env("TELEGRAM_API_URL")
    blocks.append(integration("custom-reefed-telegram", level("REEFED_TELEGRAM_LEVEL", 10),
                              api_key=env("TELEGRAM_BOT_TOKEN"), group=group, options=options))
    enabled.append("Telegram")

if env("SLACK_WEBHOOK_URL"):
    blocks.append(integration("custom-reefed-slack", level("REEFED_SLACK_LEVEL", 10),
                              hook_url=env("SLACK_WEBHOOK_URL"), group=group,
                              options={"dashboard_url": dashboard, "dedup_seconds": dedup}))
    enabled.append("Slack")

if env("SMTP_HOST") and env("ALERT_EMAIL_TO"):
    options = {
        "host": env("SMTP_HOST"),
        "port": int(env("SMTP_PORT", "587") or 587),
        "security": (env("SMTP_SECURITY", "starttls") or "starttls").lower(),
        "user": env("SMTP_USER", ""),
        "from": env("SMTP_FROM", "") or env("SMTP_USER", "") or "reefed@localhost",
        "to": [addr.strip() for addr in env("ALERT_EMAIL_TO", "").split(",") if addr.strip()],
        "max_per_hour": int(env("REEFED_EMAIL_MAX_PER_HOUR", "30") or 30),
        "dedup_seconds": dedup,
        "dashboard_url": dashboard,
    }
    blocks.append(integration("custom-reefed-email", level("REEFED_EMAIL_LEVEL", 12),
                              api_key=env("SMTP_PASSWORD", "") or None, group=group, options=options))
    enabled.append("e-mail")

conf = conf.replace("<!-- REEFED_INTEGRATIONS -->", "\n".join(blocks) or "<!-- nenhuma integração configurada -->")

# white_list do Active Response: lista trusted-db-clients + REEFED_AR_WHITELIST
whitelist = []
try:
    for line in open(trusted_path, encoding="utf-8"):
        key = line.split(":", 1)[0].strip()
        if not key:
            continue
        if key.endswith("."):  # prefixo de rede no formato das listas CDB: "10.0.0."
            octets = key.rstrip(".").split(".")
            key = ".".join(octets + ["0"] * (4 - len(octets))) + f"/{8 * len(octets)}"
        whitelist.append(key)
except OSError:
    pass
whitelist += [item.strip() for item in env("REEFED_AR_WHITELIST", "").split(",") if item.strip()]
valid = []
for item in dict.fromkeys(whitelist):
    try:
        ipaddress.ip_network(item, strict=False)
        valid.append(item)
    except ValueError:
        print(f"[reefed] ignorando entrada inválida no white_list: {item}")
conf = conf.replace("<!-- REEFED_WHITELIST -->",
                    "\n    ".join(f"<white_list>{escape(item)}</white_list>" for item in valid) or "")

# syslog remoto (firewalls da rede)
allowed = [item.strip() for item in (env("REEFED_SYSLOG_ALLOWED_IPS", "") or
                                     "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",") if item.strip()]
conf = conf.replace("<!-- REEFED_SYSLOG_ALLOWED -->",
                    "\n    ".join(f"<allowed-ips>{escape(item)}</allowed-ips>" for item in allowed))

# Active Response
ar_enabled = (env("REEFED_AR_ENABLED", "yes") or "yes").lower() in ("yes", "true", "1", "sim")
timeout = env("REEFED_AR_TIMEOUT", "600") or "600"
conf = conf.replace("REEFED_AR_DISABLED", "no" if ar_enabled else "yes")
conf = conf.replace("REEFED_AR_TIMEOUT", timeout if timeout.isdigit() else "600")

# Senha de registro dos agentes
conf = conf.replace("REEFED_USE_PASSWORD", "yes" if env("REEFED_ENROLLMENT_PASSWORD") else "no")

# Detecção de vulnerabilidades (base de ~20 GB)
vulnerabilities = (env("REEFED_VULN_DETECTION", "no") or "no").lower() in ("yes", "true", "1", "sim")
conf = conf.replace("REEFED_VULN_DETECTION", "yes" if vulnerabilities else "no")

with open(target, "w", encoding="utf-8") as handle:
    handle.write(conf)

print(f"[reefed] ossec.conf gerado; alertas: {', '.join(enabled) or 'nenhuma integração'}; "
      f"Active Response: {'ligado' if ar_enabled else 'desligado'}; white_list: {', '.join(valid) or '-'}; "
      f"vulnerabilidades: {'ligado' if vulnerabilities else 'desligado'}")
PY

chown root:wazuh "$OSSEC/etc/ossec.conf"
chmod 640 "$OSSEC/etc/ossec.conf"
