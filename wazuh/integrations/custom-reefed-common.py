"""Reefed - funções comuns das integrações de alerta (Telegram, Slack e e-mail).

O integratord do Wazuh chama cada integração assim:

    custom-reefed-<canal> <arquivo do alerta> <api_key> <hook_url> [debug] [arquivo de options]

O alerta vem em JSON (alert_format json) e as opções do bloco <options> do
ossec.conf vêm num arquivo cujo nome termina em "options". Este módulo lê esses
argumentos e monta um resumo do alerta em português, usado pelos três canais.

Alertas repetidos (mesma regra, mesmo servidor e mesma origem) viram uma mensagem
só a cada "dedup_seconds" (REEFED_ALERT_DEDUP_SECONDS no .env, padrão 600): durante
um ataque, cada conexão do atacante gera um alerta, e sem isso o Telegram e o
Slack receberiam centenas de mensagens iguais. Todos os alertas continuam no
dashboard e na API; a mensagem seguinte diz quantos foram agrupados.
"""

import fcntl
import json
import os
import sys
import time
from datetime import datetime

WAZUH_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = os.path.join(WAZUH_PATH, "logs", "integrations.log")

MAX_QUERY = 600
MAX_LOG = 600

SEVERITIES = (
    (12, "CRÍTICO", "🔴"),
    (10, "ALTO", "🟠"),
    (7, "MÉDIO", "🟡"),
    (0, "BAIXO", "🔵"),
)

# Campos de "data" mostrados na mensagem, na ordem
DATA_FIELDS = (
    ("srcip", "Origem"),
    ("db.client", "Cliente"),
    ("dstuser", "Usuário"),
    ("db.name", "Banco"),
    ("db.app", "Aplicação"),
    ("reefed.app", "Sistema"),
    ("reefed.records", "Registros"),
    ("db.rows_sent", "Linhas devolvidas"),
)


class Integration:
    """Argumentos de uma chamada do integratord."""

    def __init__(self, name, argv):
        self.name = name
        if len(argv) < 4:
            self.log(f"argumentos insuficientes: {argv[1:]}")
            sys.exit(2)
        self.alert_file = argv[1]
        self.api_key = argv[2] if argv[2] not in ("", "None") else ""
        self.hook_url = argv[3] if argv[3] not in ("", "None") else ""
        extra = argv[4:]
        self.debug_enabled = "debug" in extra
        self.options = {}
        for arg in extra:
            if arg.endswith("options"):
                self.options = load_json(arg) or {}
                break
        self.alert = load_json(self.alert_file)
        if not isinstance(self.alert, dict):
            self.log(f"não consegui ler o alerta em {self.alert_file}")
            sys.exit(7)

    def log(self, message):
        line = f"{time.strftime('%Y/%m/%d %H:%M:%S')} {self.name}: {message}\n"
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError:
            sys.stderr.write(line)

    def debug(self, message):
        if self.debug_enabled:
            self.log(message)

    def should_send(self):
        """Aplica o agrupamento de repetidos deste canal.
        Devolve (enviar, quantos_repetidos_foram_agrupados_desde_a_última_mensagem)."""
        try:
            window = max(0, int(self.options.get("dedup_seconds", 0) or 0))
        except (TypeError, ValueError):
            window = 0
        channel = self.name.replace("custom-reefed-", "")
        state_file = os.path.join(WAZUH_PATH, "logs", f"reefed-{channel}-dedup.json")
        try:
            return throttle(state_file, dedup_key(self.alert), window)
        except OSError as exc:  # sem o arquivo de estado, melhor mandar do que perder o alerta
            self.log(f"agrupamento de repetidos indisponível ({exc}); enviando")
            return True, 0


def load_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def get(data, path, default=""):
    """Lê "a.b.c" de um dicionário. O Wazuh guarda campos com ponto (db.name)
    como dicionários aninhados ({"db": {"name": ...}})."""
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def truncate(text, limit):
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def severity(level):
    for minimum, label, icon in SEVERITIES:
        if level >= minimum:
            return label, icon
    return SEVERITIES[-1][1:]


def format_time(timestamp):
    """2026-10-22T14:55:00.123-0300 -> 22/10/2026 14:55:00 (-03:00)"""
    try:
        parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
    except (TypeError, ValueError):
        return str(timestamp or "")
    offset = parsed.strftime("%z")
    return parsed.strftime("%d/%m/%Y %H:%M:%S") + (f" ({offset[:3]}:{offset[3:]})" if offset else "")


def dedup_key(alert):
    """Alertas "iguais" para o agrupamento: mesma regra, mesmo servidor e mesma
    origem (IP de origem, ou o arquivo no caso do FIM, ou o usuário)."""
    data = alert.get("data", {}) or {}
    subject = get(data, "srcip") or get(alert, "syscheck.path") or get(data, "dstuser") or ""
    return "|".join((str(get(alert, "rule.id")), str(get(alert, "agent.id")), str(subject)))


def throttle(state_file, key, window, now=None):
    """Decide se um alerta vira mensagem, guardando o estado num arquivo JSON
    (com trava, porque o integratord pode rodar várias integrações juntas).

    A primeira ocorrência de uma chave é enviada; as repetições nos próximos
    `window` segundos só são contadas. A próxima mensagem da mesma chave, depois
    da janela, informa quantas repetições ficaram sem mensagem. window=0 desliga.
    Devolve (enviar, repetidos_agrupados)."""
    if not window:
        return True, 0
    now = time.time() if now is None else now
    with open(state_file, "a+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        try:
            state = json.loads(handle.read() or "{}")
        except ValueError:
            state = {}
        if not isinstance(state, dict):
            state = {}
        # Chaves sem mensagem há mais de um dia (ou de uma janela, se maior) saem do arquivo
        keep = max(window, 86400)
        state = {k: v for k, v in state.items() if isinstance(v, dict) and now - v.get("last", 0) < keep}
        entry = state.get(key) or {"last": 0, "grouped": 0}
        if now - entry.get("last", 0) < window:
            entry["grouped"] = int(entry.get("grouped", 0)) + 1
            send, grouped = False, 0
        else:
            send, grouped = True, int(entry.get("grouped", 0))
            entry = {"last": now, "grouped": 0}
        state[key] = entry
        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps(state))
    return send, grouped


def grouped_note(grouped):
    """Linha que avisa quantos alertas iguais ficaram sem mensagem."""
    if not grouped:
        return ""
    plural = "alertas iguais ficaram" if grouped > 1 else "alerta igual ficou"
    return (f"🔁 Desde a mensagem anterior, mais {grouped} {plural} sem mensagem "
            f"(mesma regra, servidor e origem). Todos estão no dashboard.")


def summarize(alert):
    """Resumo do alerta usado nas mensagens."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    level = int(rule.get("level", 0) or 0)
    label, icon = severity(level)
    mitre = rule.get("mitre", {}) or {}
    techniques = []
    for index, technique_id in enumerate(mitre.get("id", []) or []):
        names = mitre.get("technique", []) or []
        name = names[index] if index < len(names) else ""
        techniques.append(f"{technique_id} {name}".strip())
    fields = []
    seen = set()
    for path, title in DATA_FIELDS:
        value = get(data, path)
        if value in ("", None) or str(value) in seen:
            continue
        seen.add(str(value))
        fields.append((title, str(value)))
    query = get(data, "db.query") or get(data, "reefed.query")
    return {
        "id": alert.get("id", ""),
        "level": level,
        "severity": label,
        "icon": icon,
        "rule_id": str(rule.get("id", "")),
        "description": rule.get("description", ""),
        "groups": rule.get("groups", []),
        "firedtimes": rule.get("firedtimes"),
        "techniques": techniques,
        "tactics": mitre.get("tactic", []) or [],
        "agent": f"{agent.get('name', '')} ({agent.get('id', '')})".strip(),
        "agent_ip": agent.get("ip", ""),
        "when": format_time(alert.get("timestamp")),
        "fields": fields,
        "query": truncate(query, MAX_QUERY) if query else "",
        "full_log": truncate(alert.get("full_log", ""), MAX_LOG),
        "location": alert.get("location", ""),
    }


def post_json(integration, url, payload, timeout=10, retries=2, headers=None, secrets=()):
    """POST com novas tentativas em erro de rede, 429 e 5xx. Devolve a resposta.
    Os textos de "secrets" (token do bot, URL do webhook) nunca vão para o log."""
    import requests

    def redact(text):
        for secret in secrets:
            if secret:
                text = text.replace(secret, "***")
        return text

    last_error = None
    for attempt in range(retries + 1):
        try:
            response = requests.post(url, json=payload, timeout=timeout, headers=headers)
        except requests.RequestException as exc:
            last_error = str(exc)
        else:
            if response.status_code < 400:
                return response
            last_error = f"HTTP {response.status_code}: {truncate(response.text, 300)}"
            if response.status_code != 429 and response.status_code < 500:
                break
            retry_after = 0
            try:
                retry_after = int(response.json().get("parameters", {}).get("retry_after", 0))
            except (ValueError, AttributeError):
                pass
            if retry_after and attempt < retries:
                time.sleep(min(retry_after, 10))
                continue
        if attempt < retries:
            time.sleep(2 ** attempt)
    integration.log(f"falha ao enviar: {redact(last_error or '')}")
    return None
