"""Reefed - alerta no Slack (Incoming Webhook).

Bloco gerado no ossec.conf a partir do .env (SLACK_WEBHOOK_URL):

    <integration>
      <name>custom-reefed-slack</name>
      <hook_url>https://hooks.slack.com/services/...</hook_url>
      <level>10</level>
      <alert_format>json</alert_format>
      <options>{"dashboard_url": "https://reefed.exemplo", "dedup_seconds": 600}</options>
    </integration>
"""

import importlib.util
import os
import sys

_spec = importlib.util.spec_from_file_location(
    "reefed_common", os.path.join(os.path.dirname(os.path.realpath(__file__)), "custom-reefed-common.py"))
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)

COLORS = {"CRÍTICO": "#d1242f", "ALTO": "#e16f24", "MÉDIO": "#d4a72c", "BAIXO": "#2f81f7"}


def esc(text):
    """Escapa o texto para o mrkdwn do Slack."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_payload(summary, dashboard_url="", grouped=0):
    title = f"{summary['icon']} Reefed · {summary['severity']} (nível {summary['level']})"
    fields = [{"type": "mrkdwn", "text": f"*Regra*\n{esc(summary['rule_id'])}"},
              {"type": "mrkdwn", "text": f"*Servidor*\n{esc(summary['agent'])}"}]
    for name, value in summary["fields"]:
        fields.append({"type": "mrkdwn", "text": f"*{esc(name)}*\n{esc(value)}"})
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": title[:150], "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{esc(summary['description'])}*"}},
        {"type": "section", "fields": fields[:10]},  # o Slack aceita até 10 campos por bloco
    ]
    code = summary["query"] or summary["full_log"]
    if code:
        label = "Comando" if summary["query"] else "Log"
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn", "text": f"*{label}*\n```{esc(code).replace('```', '` ` `')}```"}})
    if grouped:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"_{esc(common.grouped_note(grouped))}_"}})
    context = []
    if summary["techniques"]:
        tactics = f" ({', '.join(summary['tactics'])})" if summary["tactics"] else ""
        context.append(f"MITRE {esc(', '.join(summary['techniques']))}{esc(tactics)}")
    context.append(esc(summary["when"]))
    if dashboard_url:
        context.append(f"<{dashboard_url}|Abrir o dashboard> · alerta {esc(summary['id'])}")
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": " · ".join(context)}]})
    return {
        "text": f"{title}: {summary['description']}",  # aparece na notificação
        "attachments": [{"color": COLORS.get(summary["severity"], "#2f81f7"), "blocks": blocks}],
    }


def main(argv):
    integration = common.Integration("custom-reefed-slack", argv)
    if not integration.hook_url:
        integration.log("SLACK_WEBHOOK_URL vazio; nada enviado")
        return 2
    summary = common.summarize(integration.alert)
    notify, grouped = integration.should_send()
    if not notify:
        integration.debug(f"alerta {summary['id']} (regra {summary['rule_id']}) agrupado com um anterior")
        return 0
    payload = build_payload(summary, integration.options.get("dashboard_url", ""), grouped)
    response = common.post_json(integration, integration.hook_url, payload, secrets=(integration.hook_url,))
    if response is None:
        return 1
    integration.debug(f"alerta {summary['id']} (regra {summary['rule_id']}) enviado ao Slack")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
