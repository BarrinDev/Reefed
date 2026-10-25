"""Testes da API do Reefed com o indexer e a API do Wazuh simulados (respx).

    cd api && pip install -r requirements-dev.txt && pytest -q
"""

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app import alerts
from app.config import Settings
from app.main import create_app

INDEXER = "https://indexer.test:9200"
WAZUH = "https://wazuh.test:55000"
FULL_KEY = "k" * 32
READ_KEY = "r" * 32


@pytest.fixture
def settings():
    return Settings(api_key=FULL_KEY, read_key=READ_KEY, indexer_url=INDEXER, indexer_password="x",
                    indexer_verify_tls=False, wazuh_api_url=WAZUH, wazuh_api_password="y", ar_timeout=600)


@pytest.fixture
def mock():
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{WAZUH}/security/user/authenticate").mock(return_value=httpx.Response(200, text="TOKEN1"))
        yield router


@pytest.fixture
def client(settings, mock):
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


def full(**extra):
    return {"X-API-Key": FULL_KEY, **extra}


def read(**extra):
    return {"X-API-Key": READ_KEY, **extra}


def alert_hit(rule_id="110200", level=10, **data):
    return {
        "_index": "wazuh-alerts-4.x-2026.10.22",
        "_id": "abc",
        "_source": {
            "id": "1792681815.704361",
            "timestamp": "2026-10-22T14:55:00.123-0300",
            "rule": {"id": rule_id, "level": level, "description": "Reefed: força bruta", "groups": ["reefed"],
                     "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"], "technique": ["Password Guessing"]}},
            "agent": {"id": "001", "name": "db01", "ip": "10.0.0.5"},
            "data": {"srcip": "203.0.113.50", "dstuser": "app", "db": {"name": "loja", "client": "203.0.113.50"},
                     **data},
            "location": "/var/log/postgresql/postgresql-17-main.log",
            "full_log": "linha original",
        },
    }


def search_response(hits, total=None, aggregations=None):
    return httpx.Response(200, json={"hits": {"total": {"value": len(hits) if total is None else total},
                                              "hits": hits}, "aggregations": aggregations or {}})


# ---------------------------------------------------------------------------
# Autenticação

def test_sem_chave_recebe_401(client):
    assert client.get("/api/v1/alerts").status_code == 401


def test_chave_errada_recebe_401(client):
    assert client.get("/api/v1/alerts", headers={"X-API-Key": "errada" * 6}).status_code == 401


def test_chave_de_leitura_nao_envia_eventos(client):
    response = client.post("/api/v1/events", headers=read(), json={"app": "loja", "event": "login_failed"})
    assert response.status_code == 403


def test_chave_curta_e_recusada():
    with pytest.raises(RuntimeError):
        Settings.from_env({"REEFED_API_KEY": "curta"})


# ---------------------------------------------------------------------------
# Alertas

def test_lista_alertas_monta_a_consulta(client, mock):
    route = mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=search_response([alert_hit()]))
    response = client.get("/api/v1/alerts", headers=read(),
                          params={"since": "2h", "min_level": 10, "srcip": "203.0.113.50", "rule_id": ["110200", "110201"]})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["rule"]["id"] == "110200"
    assert item["severity"] == "alto"
    assert item["srcip"] == "203.0.113.50"
    assert item["database"]["name"] == "loja"
    assert item["rule"]["mitre"]["ids"] == ["T1110.001"]

    sent = json.loads(route.calls.last.request.content)
    filters = sent["query"]["bool"]["filter"]
    assert {"term": {"rule.groups": "reefed"}} in filters
    assert {"range": {"rule.level": {"gte": 10}}} in filters
    assert {"terms": {"rule.id": ["110200", "110201"]}} in filters
    assert {"term": {"data.srcip": "203.0.113.50"}} in filters
    assert sent["sort"] == [{"timestamp": {"order": "desc"}}]
    time_filter = next(f for f in filters if "range" in f and "timestamp" in f["range"])
    since = datetime.fromisoformat(time_filter["range"]["timestamp"]["gte"].replace("Z", "+00:00"))
    assert timedelta(hours=1, minutes=59) < datetime.now(timezone.utc) - since < timedelta(hours=2, minutes=1)


def test_filtro_por_severidade(client, mock):
    route = mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=search_response([]))
    client.get("/api/v1/alerts", headers=read(), params={"severity": "critico"})
    filters = json.loads(route.calls.last.request.content)["query"]["bool"]["filter"]
    assert {"range": {"rule.level": {"gte": 12, "lte": 16}}} in filters


def test_all_rules_tira_o_filtro_do_reefed(client, mock):
    route = mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=search_response([]))
    client.get("/api/v1/alerts", headers=read(), params={"all_rules": "true"})
    filters = json.loads(route.calls.last.request.content)["query"]["bool"]["filter"]
    assert {"term": {"rule.groups": "reefed"}} not in filters


def test_data_invalida_recebe_422(client, mock):
    mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=search_response([]))
    assert client.get("/api/v1/alerts", headers=read(), params={"since": "ontem"}).status_code == 422


def test_indexer_fora_do_ar_recebe_502(client, mock):
    mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(side_effect=httpx.ConnectError("recusado"))
    response = client.get("/api/v1/alerts", headers=read())
    assert response.status_code == 502
    assert "indexer" in response.json()["detail"]


def test_sem_indice_ainda_devolve_lista_vazia(client, mock):
    mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=httpx.Response(404, json={}))
    assert client.get("/api/v1/alerts", headers=read()).json()["total"] == 0


def test_alerta_por_id(client, mock):
    mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=search_response([alert_hit()]))
    response = client.get("/api/v1/alerts/1792681815.704361", headers=read())
    assert response.status_code == 200
    assert response.json()["raw"]["full_log"] == "linha original"


def test_alerta_inexistente(client, mock):
    mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=search_response([]))
    assert client.get("/api/v1/alerts/1.2", headers=read()).status_code == 404


def test_resumo(client, mock):
    aggregations = {
        "levels": {"buckets": [{"key": "baixo", "doc_count": 5}, {"key": "critico", "doc_count": 2}]},
        "rules": {"buckets": [{"key": "110200", "doc_count": 3, "max_level": {"value": 10},
                               "description": {"buckets": [{"key": "Reefed: força bruta", "doc_count": 3}]}}]},
        "srcips": {"buckets": [{"key": "203.0.113.50", "doc_count": 3}]},
        "users": {"buckets": []}, "agents": {"buckets": [{"key": "db01", "doc_count": 7}]},
        "mitre": {"buckets": [{"key": "T1110.001", "doc_count": 3,
                               "technique": {"buckets": [{"key": "Password Guessing", "doc_count": 3}]}}]},
        "tactics": {"buckets": [{"key": "Credential Access", "doc_count": 3}]},
    }
    mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(
        return_value=search_response([], total=7, aggregations=aggregations))
    body = client.get("/api/v1/alerts/summary", headers=read()).json()
    assert body["total"] == 7
    assert body["by_severity"] == {"baixo": 5, "critico": 2}
    assert body["top_rules"][0] == {"id": "110200", "count": 3, "description": "Reefed: força bruta", "level": 10}
    assert body["top_mitre"][0]["technique"] == "Password Guessing"


# ---------------------------------------------------------------------------
# Active Response

def ar_hit(rule_id, when, ip="203.0.113.50"):
    return {"_source": {"timestamp": alerts.iso(when), "rule": {"id": rule_id},
                        "agent": {"id": "001", "name": "db01"},
                        "data": {"parameters": {"alert": {"rule": {"id": "110200", "description": "força bruta"},
                                                          "data": {"srcip": ip}}}}}}


def test_ips_bloqueados():
    now = datetime(2026, 10, 22, 15, 0, tzinfo=timezone.utc)
    hits = [
        ar_hit("110260", now - timedelta(minutes=30), "198.51.100.1"),   # expirou sem aviso de desbloqueio
        ar_hit("110260", now - timedelta(minutes=20), "198.51.100.2"),
        ar_hit("110261", now - timedelta(minutes=10), "198.51.100.2"),   # desbloqueado
        ar_hit("110260", now - timedelta(minutes=2), "198.51.100.3"),    # ativo
    ]
    active, history = alerts.blocked_ips(hits, ar_timeout=600, now=now)
    assert [item["ip"] for item in active] == ["198.51.100.3"]
    assert {item["ip"] for item in history} == {"198.51.100.1", "198.51.100.2"}
    assert active[0]["rule"]["id"] == "110200"


def test_endpoint_blocked(client, mock):
    now = datetime.now(timezone.utc)
    mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(
        return_value=search_response([ar_hit("110260", now - timedelta(seconds=30))]))
    body = client.get("/api/v1/blocked", headers=read()).json()
    assert body["active"][0]["ip"] == "203.0.113.50"
    assert body["ar_timeout_seconds"] == 600


# ---------------------------------------------------------------------------
# Eventos da aplicação

def test_envia_um_evento(client, mock):
    route = mock.post(f"{WAZUH}/events").mock(return_value=httpx.Response(200, json={
        "data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}))
    response = client.post("/api/v1/events", headers=full(), json={
        "app": "loja", "event": "login_failed", "user": "ana", "srcip": "203.0.113.7", "message": "senha incorreta"})
    assert response.status_code == 202
    assert response.json() == {"accepted": 1, "failed": 0, "errors": []}
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer TOKEN1"
    sent = json.loads(json.loads(request.content)["events"][0])
    assert sent == {"reefed": {"source": "app", "app": "loja", "event": "login_failed", "message": "senha incorreta"},
                    "srcip": "203.0.113.7", "dstuser": "ana"}


@pytest.mark.parametrize("given, expected", [
    ("::ffff:203.0.113.7", "203.0.113.7"),  # req.ip do Express num servidor IPv6
    (" 2001:db8::1 ", "2001:db8::1"),
])
def test_srcip_normalizado(client, mock, given, expected):
    route = mock.post(f"{WAZUH}/events").mock(return_value=httpx.Response(200, json={
        "data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}))
    client.post("/api/v1/events", headers=full(), json={"app": "loja", "event": "login_failed", "srcip": given})
    assert json.loads(json.loads(route.calls.last.request.content)["events"][0])["srcip"] == expected


def test_envia_lote(client, mock):
    route = mock.post(f"{WAZUH}/events").mock(return_value=httpx.Response(200, json={
        "data": {"total_affected_items": 2, "total_failed_items": 0, "failed_items": []}}))
    response = client.post("/api/v1/events", headers=full(), json={"events": [
        {"app": "loja", "event": "data_export", "user": "bia", "records": 25000},
        {"app": "loja", "event": "pagamento_estornado", "severity": "high", "extra": {"pedido": 42}}]})
    assert response.status_code == 202
    events = [json.loads(item) for item in json.loads(route.calls.last.request.content)["events"]]
    assert events[0]["reefed"]["records"] == 25000
    assert events[1]["reefed"]["extra"] == {"pedido": 42}


@pytest.mark.parametrize("payload", [
    {"app": "loja", "event": "login_failed", "srcip": "não é ip"},
    {"app": "loja", "event": "Login Failed"},
    {"app": "loja", "event": "x", "campo_extra": 1},
    {"app": "loja", "event": "x", "severity": "urgente"},
    {"app": "loja", "event": "x", "extra": {"objeto": {"aninhado": 1}}},
    {"events": []},
    {"events": [{"app": "loja", "event": "x"}] * 101},
])
def test_evento_invalido_recebe_422(client, mock, payload):
    route = mock.post(f"{WAZUH}/events")
    assert client.post("/api/v1/events", headers=full(), json=payload).status_code == 422
    assert not route.called


def test_erro_de_evento_aponta_so_o_campo_errado(client, mock):
    # Um evento sozinho não pode receber erros do formato de lote ("events" faltando)
    detail = client.post("/api/v1/events", headers=full(),
                         json={"app": "minha loja", "event": "login_failed"}).json()["detail"]
    assert [error["loc"] for error in detail] == [["body", "evento", "app"]]
    detail = client.post("/api/v1/events", headers=full(),
                         json={"events": [{"app": "loja", "event": "x", "srcip": "abc"}]}).json()["detail"]
    assert [error["loc"] for error in detail] == [["body", "lote", "events", 0, "srcip"]]


def test_token_do_wazuh_e_renovado(client, mock):
    mock.post(f"{WAZUH}/security/user/authenticate").mock(
        side_effect=[httpx.Response(200, text="VELHO"), httpx.Response(200, text="NOVO")])
    route = mock.post(f"{WAZUH}/events").mock(side_effect=[
        httpx.Response(401, json={"title": "Unauthorized"}),
        httpx.Response(200, json={"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}})])
    response = client.post("/api/v1/events", headers=full(), json={"app": "loja", "event": "x"})
    assert response.status_code == 202
    assert route.calls[1].request.headers["Authorization"] == "Bearer NOVO"


# ---------------------------------------------------------------------------
# Status e agentes

def mock_status(mock, integratord="stopped", integrations=None):
    mock.get(f"{WAZUH}/manager/info").mock(return_value=httpx.Response(200, json={
        "data": {"affected_items": [{"version": "v4.14.9", "tz_offset": "-0300"}]}}))
    mock.get(f"{WAZUH}/manager/status").mock(return_value=httpx.Response(200, json={
        "data": {"affected_items": [{"wazuh-analysisd": "running", "wazuh-remoted": "running",
                                     "wazuh-integratord": integratord}]}}))
    mock.get(f"{WAZUH}/agents/summary/status").mock(return_value=httpx.Response(200, json={
        "data": {"connection": {"active": 3, "disconnected": 1, "total": 4}}}))
    if integrations is None:
        # Resposta real do Wazuh quando o ossec.conf não tem nenhum <integration>
        configuration = {"data": {"affected_items": [], "total_affected_items": 0, "total_failed_items": 1,
                                  "failed_items": [{"error": {"code": 1106}}]},
                         "message": "Could not read configuration", "error": 1}
    else:
        configuration = {"data": {"affected_items": [{"integration": integrations}], "total_affected_items": 1},
                         "error": 0}
    mock.get(f"{WAZUH}/manager/configuration").mock(return_value=httpx.Response(200, json=configuration))
    mock.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=search_response(
        [], total=12, aggregations={"levels": {"buckets": [{"key": "alto", "doc_count": 12}]}}))


def test_status_sem_canal_de_alerta(client, mock):
    # Sem Telegram, Slack ou e-mail no .env o integratord fica parado, e está tudo certo
    mock_status(mock)
    body = client.get("/api/v1/status", headers=read()).json()
    assert body["status"] == "ok"
    assert body["manager"]["stopped"] == []
    assert body["manager"]["alert_channels"] == []
    assert body["agents"]["connection"]["active"] == 3
    assert body["alerts_24h"] == {"total": 12, "by_severity": {"alto": 12}}


def test_status_com_canal_e_integratord_parado(client, mock):
    mock_status(mock, integrations=[{"name": "custom-reefed-telegram", "level": "10"},
                                    {"name": "custom-reefed-email", "level": "12"}])
    body = client.get("/api/v1/status", headers=read()).json()
    assert body["status"] == "degraded"
    assert body["manager"]["stopped"] == ["wazuh-integratord"]
    assert body["manager"]["alert_channels"] == ["telegram", "email"]


def test_status_com_canal_e_integratord_rodando(client, mock):
    mock_status(mock, integratord="running", integrations=[{"name": "custom-reefed-slack"}])
    body = client.get("/api/v1/status", headers=read()).json()
    assert body["status"] == "ok"
    assert body["manager"]["alert_channels"] == ["slack"]


def test_agentes(client, mock):
    route = mock.get(f"{WAZUH}/agents").mock(return_value=httpx.Response(200, json={"data": {"affected_items": [
        {"id": "001", "name": "db01", "ip": "10.0.0.5", "status": "active", "os": {"name": "Ubuntu", "version": "24.04"},
         "version": "Wazuh v4.14.9", "group": ["linux", "database", "postgresql"], "lastKeepAlive": "2026-10-22T15:00:00Z",
         "dateAdd": "2026-10-20T10:00:00Z"}]}}))
    body = client.get("/api/v1/agents", headers=read(), params={"group": "database"}).json()
    assert body["items"][0]["os"] == "Ubuntu 24.04"
    assert body["items"][0]["groups"] == ["linux", "database", "postgresql"]
    assert route.calls.last.request.url.params["group"] == "database"


def test_health_sem_autenticacao(client, mock):
    mock.get(f"{INDEXER}/wazuh-alerts-*/_count").mock(return_value=httpx.Response(200, json={"count": 3}))
    mock.get(f"{WAZUH}/").mock(return_value=httpx.Response(200, json={"data": {}}))
    assert client.get("/health").json()["status"] == "ok"
