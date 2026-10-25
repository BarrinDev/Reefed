"""Testes das integrações de alerta (Telegram, Slack e e-mail).

Não mandam nada para fora: o envio (post_json / SMTP) é trocado por funções que
só guardam o que seria enviado. Rodam com pytest, sem o Wazuh:

    python -m pytest tests/integrations
"""

import importlib.util
import json
import pathlib

import pytest

INTEGRATIONS = pathlib.Path(__file__).resolve().parents[2] / "wazuh" / "integrations"


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), INTEGRATIONS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ALERT = {
    "id": "1792688430.1106",
    "timestamp": "2026-10-22T14:00:30.888-0300",
    "rule": {"id": "110210", "level": 10, "description": "Reefed: acesso ao banco a partir de IP desconhecido 203.0.113.66 (usuário app).",
             "groups": ["reefed", "reefed_unknown_ip"], "mitre": {"id": ["T1078"], "technique": ["Valid Accounts"], "tactic": ["Persistence"]}},
    "agent": {"id": "008", "name": "db-mysql"},
    "data": {"srcip": "203.0.113.66", "dstuser": "app", "db": {"name": "loja"}},
    "full_log": "2026-10-22T17:00:12Z\t 33 Connect\tapp@203.0.113.66 on loja using SSL/TLS",
    "location": "/var/log/mysql/general.log",
}


@pytest.fixture
def workdir(tmp_path):
    (tmp_path / "logs").mkdir()
    return tmp_path


def run_integration(module, workdir, monkeypatch, alert, options, api_key="TOKEN", hook_url="https://hooks.slack.com/services/T/B/x"):
    """Chama main() como o integratord chamaria e devolve (código, envios)."""
    monkeypatch.setattr(module.common, "WAZUH_PATH", str(workdir))
    monkeypatch.setattr(module.common, "LOG_FILE", str(workdir / "logs" / "integrations.log"))
    sent = []
    monkeypatch.setattr(module.common, "post_json", lambda integration, url, payload, **kw: sent.append((url, payload)) or object())
    alert_file = workdir / "alert.json"
    alert_file.write_text(json.dumps(alert), encoding="utf-8")
    options_file = workdir / "integration.options"
    options_file.write_text(json.dumps(options), encoding="utf-8")
    code = module.main(["script", str(alert_file), api_key, hook_url, str(options_file)])
    return code, sent


# ---------------------------------------------------------------- agrupamento
def test_throttle_agrupa_repeticoes_e_conta_na_mensagem_seguinte(tmp_path):
    common = load("custom-reefed-common")
    state = str(tmp_path / "state.json")
    assert common.throttle(state, "k", 600, now=1000) == (True, 0)
    assert common.throttle(state, "k", 600, now=1010) == (False, 0)
    assert common.throttle(state, "k", 600, now=1500) == (False, 0)
    # outra chave não é afetada
    assert common.throttle(state, "outra", 600, now=1500) == (True, 0)
    # passou a janela desde a última mensagem: envia e conta as duas agrupadas
    assert common.throttle(state, "k", 600, now=1601) == (True, 2)
    assert common.throttle(state, "k", 600, now=1602) == (False, 0)


def test_throttle_desligado_envia_tudo(tmp_path):
    common = load("custom-reefed-common")
    state = str(tmp_path / "state.json")
    assert all(common.throttle(state, "k", 0, now=1000 + i) == (True, 0) for i in range(5))


def test_throttle_aguenta_arquivo_corrompido(tmp_path):
    common = load("custom-reefed-common")
    state = tmp_path / "state.json"
    state.write_text("{nao é json", encoding="utf-8")
    assert common.throttle(str(state), "k", 600, now=1000) == (True, 0)


def test_chave_de_agrupamento():
    common = load("custom-reefed-common")
    assert common.dedup_key(ALERT) == "110210|008|203.0.113.66"
    fim = {"rule": {"id": "110801"}, "agent": {"id": "008"}, "syscheck": {"path": "/etc/mysql/conf.d/x.cnf"}}
    assert common.dedup_key(fim) == "110801|008|/etc/mysql/conf.d/x.cnf"
    sem_ip = {"rule": {"id": "110165"}, "agent": {"id": "000"}, "data": {"dstuser": "ana"}}
    assert common.dedup_key(sem_ip) == "110165|000|ana"


# ---------------------------------------------------------------- Telegram
def test_telegram_envia_uma_vez_e_agrupa_repetidos(workdir, monkeypatch):
    telegram = load("custom-reefed-telegram")
    options = {"chat_id": "-100123", "dashboard_url": "https://reefed.exemplo", "dedup_seconds": 600}
    code, sent = run_integration(telegram, workdir, monkeypatch, ALERT, options)
    assert code == 0 and len(sent) == 1
    url, payload = sent[0]
    assert url == "https://api.telegram.org/botTOKEN/sendMessage"
    assert payload["chat_id"] == "-100123" and payload["parse_mode"] == "HTML"
    assert "Reefed · ALTO (nível 10)" in payload["text"] and "T1078 Valid Accounts" in payload["text"]
    for _ in range(3):  # mesma regra, servidor e origem: não manda de novo
        code, again = run_integration(telegram, workdir, monkeypatch, ALERT, options)
        assert code == 0 and again == []
    other = dict(ALERT, data={"srcip": "198.51.100.9", "dstuser": "app"})
    code, sent = run_integration(telegram, workdir, monkeypatch, other, options)
    assert len(sent) == 1  # outra origem é outro alerta


def test_telegram_mostra_quantos_foram_agrupados(workdir, monkeypatch):
    telegram = load("custom-reefed-telegram")
    summary = telegram.common.summarize(ALERT)
    text = telegram.build_message(summary, "", grouped=7)
    assert "mais 7 alertas iguais ficaram sem mensagem" in text


def test_telegram_escapa_html(workdir, monkeypatch):
    telegram = load("custom-reefed-telegram")
    alert = json.loads(json.dumps(ALERT))
    alert["data"]["db"]["query"] = "SELECT * FROM t WHERE a < 1 AND b > 2 -- <script>"
    text = telegram.build_message(telegram.common.summarize(alert))
    assert "<script>" not in text and "&lt;script&gt;" in text


# ---------------------------------------------------------------- Slack
def test_slack_payload_e_agrupamento(workdir, monkeypatch):
    slack = load("custom-reefed-slack")
    options = {"dashboard_url": "https://reefed.exemplo", "dedup_seconds": 600}
    code, sent = run_integration(slack, workdir, monkeypatch, ALERT, options)
    assert code == 0 and len(sent) == 1
    url, payload = sent[0]
    assert url.startswith("https://hooks.slack.com/")
    assert payload["attachments"][0]["color"] == "#e16f24"
    code, again = run_integration(slack, workdir, monkeypatch, ALERT, options)
    assert again == []
    blocks = slack.build_payload(slack.common.summarize(ALERT), grouped=3)["attachments"][0]["blocks"]
    assert any("mais 3 alertas iguais" in json.dumps(block, ensure_ascii=False) for block in blocks)


def test_slack_sem_webhook_nao_envia(workdir, monkeypatch):
    slack = load("custom-reefed-slack")
    code, sent = run_integration(slack, workdir, monkeypatch, ALERT, {}, hook_url="")
    assert code == 2 and sent == []


# ---------------------------------------------------------------- E-mail
def test_email_agrupa_e_respeita_limite_por_hora(workdir, monkeypatch):
    email = load("custom-reefed-email")
    monkeypatch.setattr(email, "STATE_FILE", str(workdir / "logs" / "reefed-email-state.json"))
    sent = []
    monkeypatch.setattr(email, "send", lambda message, options, password: sent.append(message))
    options = {"host": "smtp.exemplo", "port": 587, "to": ["seguranca@exemplo.com"], "max_per_hour": 2, "dedup_seconds": 600}
    code, _ = run_integration(email, workdir, monkeypatch, ALERT, options)
    code, _ = run_integration(email, workdir, monkeypatch, ALERT, options)  # repetido: agrupado
    assert code == 0 and len(sent) == 1
    for ip in ("198.51.100.1", "198.51.100.2"):  # origens novas: a segunda passa do limite de 2/h
        run_integration(email, workdir, monkeypatch, dict(ALERT, data={"srcip": ip}), options)
    assert len(sent) == 2
    assert str(sent[0]["Subject"]).startswith("[Reefed] ALTO (nível 10): Reefed: acesso ao banco")
    assert sent[0]["To"] == "seguranca@exemplo.com"


def test_email_mensagem_traz_avisos():
    email = load("custom-reefed-email")
    summary = email.common.summarize(ALERT)
    message = email.build_message(summary, {"to": ["a@b.c"], "max_per_hour": 30}, suppressed=4, grouped=2)
    text, html = (part.get_payload(decode=True).decode() for part in message.get_payload())
    for body in (text, html):
        assert "4 alerta(s) anteriores" in body
        assert "mais 2 alertas iguais" in body
