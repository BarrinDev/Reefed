"""Reefed - alerta no Telegram.

Bloco gerado no ossec.conf a partir do .env (TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_ID):

    <integration>
      <name>custom-reefed-telegram</name>
      <api_key>TOKEN_DO_BOT</api_key>
      <level>10</level>
      <alert_format>json</alert_format>
      <options>{"chat_id": "-100123456", "dashboard_url": "https://reefed.exemplo", "dedup_seconds": 600}</options>
    </integration>
"""

import html
import importlib.util
import os
import sys

_spec = importlib.util.spec_from_file_location(
    "reefed_common", os.path.join(os.path.dirname(os.path.realpath(__file__)), "custom-reefed-common.py"))
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)

TELEGRAM_API = "https://api.telegram.org"
MAX_MESSAGE = 4000  # o Telegram aceita até 4096 caracteres


def build_message(summary, dashboard_url="", grouped=0):
    esc = html.escape
    lines = [
        f"{summary['icon']} <b>Reefed · {summary['severity']} (nível {summary['level']})</b>",
        f"<b>{esc(summary['description'])}</b>",
        "",
        f"<b>Regra:</b> {esc(summary['rule_id'])}",
    ]
    if summary["techniques"]:
        tactics = f" ({esc(', '.join(summary['tactics']))})" if summary["tactics"] else ""
        lines.append(f"<b>MITRE:</b> {esc(', '.join(summary['techniques']))}{tactics}")
    lines.append(f"<b>Servidor:</b> {esc(summary['agent'])}")
    for title, value in summary["fields"]:
        lines.append(f"<b>{esc(title)}:</b> {esc(value)}")
    if summary["query"]:
        lines.append("<b>Comando:</b>")
        lines.append(f"<pre>{esc(summary['query'])}</pre>")
    elif summary["full_log"]:
        lines.append("<b>Log:</b>")
        lines.append(f"<pre>{esc(summary['full_log'])}</pre>")
    lines.append(f"<b>Quando:</b> {esc(summary['when'])}")
    if grouped:
        lines.append(f"<i>{esc(common.grouped_note(grouped))}</i>")
    if dashboard_url:
        lines.append(f'<a href="{esc(dashboard_url, quote=True)}">Abrir o dashboard</a> · alerta {esc(summary["id"])}')
    message = "\n".join(lines)
    if len(message) > MAX_MESSAGE:
        # Corta o comando (o pedaço mais longo) sem quebrar as tags HTML
        overflow = len(message) - MAX_MESSAGE + 10
        short = esc(common.truncate(summary["query"] or summary["full_log"], max(50, len(summary["query"] or summary["full_log"]) - overflow)))
        message = message.replace(f"<pre>{esc(summary['query'] or summary['full_log'])}</pre>", f"<pre>{short}</pre>")
    return message


def main(argv):
    integration = common.Integration("custom-reefed-telegram", argv)
    token = integration.api_key
    chat_id = str(integration.options.get("chat_id", "")).strip()
    if not token or not chat_id:
        integration.log("TELEGRAM_BOT_TOKEN ou TELEGRAM_CHAT_ID vazio; nada enviado")
        return 2
    summary = common.summarize(integration.alert)
    notify, grouped = integration.should_send()
    if not notify:
        integration.debug(f"alerta {summary['id']} (regra {summary['rule_id']}) agrupado com um anterior")
        return 0
    payload = {
        "chat_id": chat_id,
        "text": build_message(summary, integration.options.get("dashboard_url", ""), grouped),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    api = integration.options.get("api_url", TELEGRAM_API).rstrip("/")
    response = common.post_json(integration, f"{api}/bot{token}/sendMessage", payload, secrets=(token,))
    if response is None:
        return 1
    integration.debug(f"alerta {summary['id']} (regra {summary['rule_id']}) enviado ao Telegram")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
