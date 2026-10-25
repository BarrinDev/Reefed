"""Reefed - alerta por e-mail (SMTP com usuário e senha).

O envio nativo do Wazuh (wazuh-maild) não faz login no servidor SMTP, então o
Reefed manda e-mail por esta integração. Bloco gerado no ossec.conf a partir do
.env (SMTP_* e ALERT_EMAIL_TO); a senha do SMTP vai no api_key:

    <integration>
      <name>custom-reefed-email</name>
      <api_key>SENHA_DO_SMTP</api_key>
      <level>12</level>
      <alert_format>json</alert_format>
      <options>{"host": "smtp.gmail.com", "port": 587, "security": "starttls",
                "user": "alertas@exemplo.com", "from": "alertas@exemplo.com",
                "to": ["seguranca@exemplo.com"], "max_per_hour": 30, "dedup_seconds": 600}</options>
    </integration>

Duas proteções contra uma enxurrada de e-mails durante um ataque (os alertas
continuam todos no dashboard):
  - dedup_seconds: alertas iguais (mesma regra, servidor e origem) viram um
    e-mail só por janela, e o próximo e-mail diz quantos foram agrupados;
  - max_per_hour: passando do limite, nada sai por e-mail até a hora virar, e o
    próximo e-mail diz quantos ficaram de fora.
"""

import fcntl
import html
import importlib.util
import json
import os
import smtplib
import ssl
import sys
import time
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

_spec = importlib.util.spec_from_file_location(
    "reefed_common", os.path.join(os.path.dirname(os.path.realpath(__file__)), "custom-reefed-common.py"))
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)

STATE_FILE = os.path.join(common.WAZUH_PATH, "logs", "reefed-email-state.json")


def check_rate_limit(max_per_hour):
    """Registra o envio se ainda couber no limite da última hora.
    Devolve (pode_enviar, quantos_ficaram_de_fora_antes)."""
    now = time.time()
    with open(STATE_FILE, "a+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        try:
            state = json.loads(handle.read() or "{}")
        except ValueError:
            state = {}
        sent = [stamp for stamp in state.get("sent", []) if now - stamp < 3600]
        suppressed = int(state.get("suppressed", 0))
        if max_per_hour and len(sent) >= max_per_hour:
            allowed, previous = False, suppressed
            suppressed += 1
        else:
            allowed, previous = True, suppressed
            sent.append(now)
            suppressed = 0
        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps({"sent": sent, "suppressed": suppressed}))
    return allowed, previous


def build_message(summary, options, suppressed, grouped=0):
    subject = f"[Reefed] {summary['severity']} (nível {summary['level']}): {summary['description']}"
    rows = [("Regra", summary["rule_id"]), ("Servidor", summary["agent"])]
    if summary["techniques"]:
        tactics = f" ({', '.join(summary['tactics'])})" if summary["tactics"] else ""
        rows.append(("MITRE ATT&CK", ", ".join(summary["techniques"]) + tactics))
    rows += summary["fields"]
    rows.append(("Quando", summary["when"]))
    rows.append(("Alerta", summary["id"]))
    code = summary["query"] or summary["full_log"]
    code_label = "Comando" if summary["query"] else "Log"
    dashboard = options.get("dashboard_url", "")
    notes = [common.grouped_note(grouped)] if grouped else []
    if suppressed:
        notes.append(f"{suppressed} alerta(s) anteriores não foram enviados por e-mail por causa do limite "
                     f"de {options.get('max_per_hour')} por hora. Veja todos no dashboard.")

    text = [summary["description"], ""]
    text += [f"{name}: {value}" for name, value in rows]
    if code:
        text += ["", f"{code_label}:", code]
    if dashboard:
        text += ["", f"Dashboard: {dashboard}"]
    for note in notes:
        text += ["", note]

    esc = html.escape
    color = {"CRÍTICO": "#d1242f", "ALTO": "#e16f24", "MÉDIO": "#9a6700"}.get(summary["severity"], "#0969da")
    table = "".join(f'<tr><td style="padding:4px 12px 4px 0;color:#57606a">{esc(name)}</td>'
                    f'<td style="padding:4px 0">{esc(str(value))}</td></tr>' for name, value in rows)
    body = [
        '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1f2328;max-width:680px">',
        f'<p style="margin:0 0 4px;color:{color};font-weight:bold">Reefed · {esc(summary["severity"])} '
        f'(nível {summary["level"]})</p>',
        f'<h2 style="margin:0 0 16px;font-size:18px">{esc(summary["description"])}</h2>',
        f'<table style="border-collapse:collapse">{table}</table>',
    ]
    if code:
        body.append(f'<p style="margin:16px 0 4px;color:#57606a">{code_label}</p>'
                    f'<pre style="background:#f6f8fa;padding:12px;white-space:pre-wrap;word-break:break-all">'
                    f'{esc(code)}</pre>')
    if dashboard:
        body.append(f'<p><a href="{esc(dashboard, quote=True)}">Abrir o dashboard do Reefed</a></p>')
    for note in notes:
        body.append(f'<p style="color:#57606a">{esc(note)}</p>')
    body.append("</div>")

    # MIME "clássico" com Header: o EmailMessage do Python 3.10 junta palavras
    # acentuadas vizinhas ao dobrar assuntos longos ("vários usuários").
    message = MIMEMultipart("alternative")
    message["Subject"] = Header(subject[:200], "utf-8")
    message["From"] = options.get("from") or options.get("user") or "reefed@localhost"
    message["To"] = ", ".join(options.get("to", []))
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain="reefed")
    message.attach(MIMEText("\n".join(text), "plain", "utf-8"))
    message.attach(MIMEText("".join(body), "html", "utf-8"))
    return message


def send(message, options, password):
    host = options.get("host")
    port = int(options.get("port") or 587)
    security = (options.get("security") or "starttls").lower()
    timeout = int(options.get("timeout") or 20)
    context = ssl.create_default_context()
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    with server:
        server.ehlo()
        if security == "starttls":
            server.starttls(context=context)
            server.ehlo()
        if options.get("user") and password:
            server.login(options["user"], password)
        server.sendmail(message["From"], list(options.get("to", [])), message.as_string())


def main(argv):
    integration = common.Integration("custom-reefed-email", argv)
    options = integration.options
    if not options.get("host") or not options.get("to"):
        integration.log("SMTP_HOST ou ALERT_EMAIL_TO vazio; nada enviado")
        return 2
    summary = common.summarize(integration.alert)
    notify, grouped = integration.should_send()
    if not notify:
        integration.debug(f"alerta {summary['id']} (regra {summary['rule_id']}) agrupado com um anterior")
        return 0
    allowed, suppressed = check_rate_limit(int(options.get("max_per_hour") or 0))
    if not allowed:
        integration.log(f"limite de {options.get('max_per_hour')} e-mails por hora atingido; "
                        f"alerta {summary['id']} (regra {summary['rule_id']}) não enviado")
        return 0
    message = build_message(summary, options, suppressed, grouped)
    last_error = None
    for attempt in range(3):
        try:
            send(message, options, integration.api_key)
            integration.debug(f"alerta {summary['id']} (regra {summary['rule_id']}) enviado por e-mail")
            return 0
        except (OSError, smtplib.SMTPException) as exc:
            last_error = exc
            if isinstance(exc, smtplib.SMTPAuthenticationError):
                break
            time.sleep(2 ** attempt)
    integration.log(f"falha ao enviar e-mail por {options.get('host')}:{options.get('port')}: {last_error}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
