"""API do Reefed.

Ponte entre o sistema que usa o banco e o SIEM: consulta alertas e status sem
expor o indexer nem a API do Wazuh, e recebe eventos da aplicação. Documentação
interativa em /docs; guia em docs/api.md.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import alerts as alert_queries
from .auth import require_read, require_write
from .clients import IndexerClient, UpstreamError, WazuhClient
from .config import Settings
from .events import EventBatch, EventPayload

VERSION = "1.0.0"


def create_app(settings=None, indexer=None, wazuh=None):
    """Fábrica da aplicação (uvicorn app.main:create_app --factory)."""
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = settings
        app.state.indexer = indexer or IndexerClient(settings)
        app.state.wazuh = wazuh or WazuhClient(settings)
        yield
        await app.state.indexer.close()
        await app.state.wazuh.close()

    app = FastAPI(
        title="Reefed API",
        version=VERSION,
        description="Alertas, status e eventos do Reefed (SIEM de banco de dados baseado no Wazuh). "
                    "Autentique com o cabeçalho X-API-Key.",
        lifespan=lifespan,
    )

    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST"],
                           allow_headers=["X-API-Key", "Content-Type"])

    @app.exception_handler(UpstreamError)
    async def upstream_error(request: Request, exc: UpstreamError):
        return JSONResponse(status_code=502, content={"detail": f"{exc.service} indisponível: {exc}"})

    @app.exception_handler(ValueError)
    async def value_error(request: Request, exc: ValueError):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    def indexer_client(request: Request) -> IndexerClient:
        return request.app.state.indexer

    def wazuh_client(request: Request) -> WazuhClient:
        return request.app.state.wazuh

    # -----------------------------------------------------------------------
    @app.get("/health", tags=["status"], summary="A API está no ar? (sem autenticação)")
    async def health(request: Request):
        indexer_ok = await request.app.state.indexer.ping()
        wazuh_ok = await request.app.state.wazuh.ping()
        return {"status": "ok" if indexer_ok and wazuh_ok else "degraded",
                "indexer": indexer_ok, "wazuh_api": wazuh_ok, "version": VERSION}

    @app.get("/api/v1/status", tags=["status"], summary="Situação do manager, dos agentes e dos alertas das últimas 24 h")
    async def status(_: str = Depends(require_read),
                     indexer: IndexerClient = Depends(indexer_client),
                     wazuh: WazuhClient = Depends(wazuh_client)):
        info = await wazuh.get("/manager/info")
        daemons = await wazuh.get("/manager/status")
        agents = await wazuh.get("/agents/summary/status")
        # Sem canal de alerta no .env não há <integration> no ossec.conf, e o Wazuh nem
        # inicia o wazuh-integratord (a API responde que a seção não existe)
        integrations = await wazuh.get("/manager/configuration", section="integration")
        channels = [str(item.get("name", "")).replace("custom-reefed-", "")
                    for section in (integrations.get("data", {}).get("affected_items") or [])
                    for item in (section.get("integration") or []) if isinstance(item, dict)]
        since = alert_queries.parse_time("24h")
        response = await indexer.search({
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"filter": alert_queries.build_filters(since=since)}},
            "aggs": {"levels": alert_queries.summary_aggregations()["levels"]},
        })
        daemon_state = (daemons.get("data", {}).get("affected_items") or [{}])[0]
        manager = (info.get("data", {}).get("affected_items") or [{}])[0]
        important = ["wazuh-analysisd", "wazuh-remoted", "wazuh-authd", "wazuh-execd", "wazuh-modulesd",
                     "wazuh-db", "wazuh-apid"]
        if channels:
            important.append("wazuh-integratord")
        stopped = [name for name in important if daemon_state.get(name) not in (None, "running")]
        summary = alert_queries.parse_summary(response)
        return {
            "status": "ok" if not stopped else "degraded",
            "checked_at": alert_queries.iso(datetime.now(timezone.utc)),
            "manager": {"version": manager.get("version"), "timezone": manager.get("tz_offset"),
                        "daemons": daemon_state, "stopped": stopped, "alert_channels": channels},
            "agents": agents.get("data", {}),
            "alerts_24h": {"total": summary["total"], "by_severity": summary["by_severity"]},
        }

    @app.get("/api/v1/alerts", tags=["alertas"], summary="Lista alertas (mais novos primeiro)")
    async def list_alerts(
        _: str = Depends(require_read),
        indexer: IndexerClient = Depends(indexer_client),
        since: str = Query("24h", description="início: 15m, 24h, 7d ou data ISO 8601"),
        until: Optional[str] = Query(None, description="fim (padrão: agora)"),
        min_level: int = Query(3, ge=0, le=16),
        max_level: Optional[int] = Query(None, ge=0, le=16),
        severity: Optional[str] = Query(None, pattern="^(baixo|medio|alto|critico)$"),
        rule_id: Annotated[Optional[list[str]], Query(description="pode repetir: rule_id=110200&rule_id=110201")] = None,
        group: Annotated[Optional[list[str]], Query(description="grupo de regra, ex.: reefed_sqli")] = None,
        agent: Optional[str] = Query(None, description="nome ou id do agente"),
        srcip: Optional[str] = None,
        user: Optional[str] = Query(None, description="usuário do banco ou do sistema"),
        mitre: Optional[str] = Query(None, description="técnica (T1110) ou tática (Credential Access)"),
        q: Optional[str] = Query(None, max_length=200, description="texto na descrição ou no log"),
        all_rules: bool = Query(False, description="inclui alertas que não são do Reefed"),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0, le=10000),
    ):
        if severity:
            min_level, max_level = alert_queries.SEVERITY_LEVELS[severity]
        filters = alert_queries.build_filters(
            since=alert_queries.parse_time(since), until=alert_queries.parse_time(until),
            min_level=min_level, max_level=max_level, rule_ids=rule_id, groups=group, agent=agent,
            srcip=srcip, user=user, mitre=mitre, only_reefed=not all_rules, text=q)
        response = await indexer.search({
            "query": {"bool": {"filter": filters}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "from": offset, "size": limit, "track_total_hits": True,
        })
        hits = response.get("hits", {})
        return {"total": hits.get("total", {}).get("value", 0), "offset": offset, "limit": limit,
                "items": [alert_queries.simplify(hit) for hit in hits.get("hits", [])]}

    @app.get("/api/v1/alerts/summary", tags=["alertas"], summary="Resumo: por severidade, regras, IPs, usuários e MITRE")
    async def alerts_summary(
        _: str = Depends(require_read),
        indexer: IndexerClient = Depends(indexer_client),
        since: str = Query("24h"),
        until: Optional[str] = None,
        min_level: int = Query(3, ge=0, le=16),
        agent: Optional[str] = None,
        all_rules: bool = False,
        top: int = Query(10, ge=1, le=50),
    ):
        filters = alert_queries.build_filters(since=alert_queries.parse_time(since),
                                              until=alert_queries.parse_time(until), min_level=min_level,
                                              agent=agent, only_reefed=not all_rules)
        response = await indexer.search({"size": 0, "track_total_hits": True,
                                         "query": {"bool": {"filter": filters}},
                                         "aggs": alert_queries.summary_aggregations(top)})
        return {"since": since, **alert_queries.parse_summary(response)}

    @app.get("/api/v1/alerts/{alert_id}", tags=["alertas"], summary="Um alerta, com o documento completo")
    async def get_alert(
        _: str = Depends(require_read),
        indexer: IndexerClient = Depends(indexer_client),
        alert_id: str = Path(pattern=r"^[0-9]+\.[0-9]+$", description="campo id do alerta, ex.: 1792681815.704361"),
        since: str = Query("30d", description="até onde procurar"),
    ):
        response = await indexer.search({
            "size": 1,
            "query": {"bool": {"filter": [{"term": {"id": alert_id}},
                                          {"range": {"timestamp": {"gte": alert_queries.iso(
                                              alert_queries.parse_time(since))}}}]}},
        })
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            raise HTTPException(404, "alerta não encontrado")
        return {**alert_queries.simplify(hits[0]), "raw": hits[0].get("_source")}

    @app.get("/api/v1/blocked", tags=["active response"], summary="IPs bloqueados agora pelo Active Response")
    async def blocked(
        _: str = Depends(require_read),
        indexer: IndexerClient = Depends(indexer_client),
        since: str = Query("24h", description="período do histórico"),
    ):
        response = await indexer.search({
            "size": 1000,
            "query": {"bool": {"filter": [
                {"terms": {"rule.id": [alert_queries.AR_BLOCK_RULE, alert_queries.AR_UNBLOCK_RULE]}},
                {"range": {"timestamp": {"gte": alert_queries.iso(alert_queries.parse_time(since))}}},
            ]}},
            "sort": [{"timestamp": {"order": "asc"}}],
        })
        active, history = alert_queries.blocked_ips(response.get("hits", {}).get("hits", []),
                                                    settings.ar_timeout)
        return {"active": active, "history": history, "ar_timeout_seconds": settings.ar_timeout}

    @app.get("/api/v1/agents", tags=["status"], summary="Agentes registrados")
    async def agents(
        _: str = Depends(require_read),
        wazuh: WazuhClient = Depends(wazuh_client),
        status: Optional[str] = Query(None, pattern="^(active|disconnected|never_connected|pending)$"),
        group: Optional[str] = None,
    ):
        params = {"limit": 500, "select": "id,name,ip,status,os.name,os.version,version,group,lastKeepAlive,"
                                          "dateAdd,node_name"}
        if status:
            params["status"] = status
        if group:
            params["group"] = group
        response = await wazuh.get("/agents", **params)
        items = response.get("data", {}).get("affected_items", [])
        return {"total": len(items), "items": [{
            "id": item.get("id"), "name": item.get("name"), "ip": item.get("ip"), "status": item.get("status"),
            "os": " ".join(filter(None, [alert_queries.get_path(item, "os.name"),
                                         alert_queries.get_path(item, "os.version")])) or None,
            "version": item.get("version"), "groups": item.get("group", []),
            "last_keepalive": item.get("lastKeepAlive"), "registered_at": item.get("dateAdd"),
        } for item in items]}

    @app.get("/api/v1/rules", tags=["regras"], summary="Regras do Reefed (catálogo com MITRE)")
    async def rules(_: str = Depends(require_read), wazuh: WazuhClient = Depends(wazuh_client)):
        response = await wazuh.get("/rules", group="reefed", limit=1000, sort="+id")
        items = response.get("data", {}).get("affected_items", [])
        return {"total": len(items), "items": [{
            "id": str(item.get("id")), "level": item.get("level"), "description": item.get("description"),
            "groups": item.get("groups", []), "mitre": item.get("mitre", []), "file": item.get("filename"),
        } for item in items]}

    @app.post("/api/v1/events", tags=["eventos"], status_code=202,
              summary="Envia eventos da aplicação (um ou até 100 em {\"events\": [...]})")
    async def send_events(
        # Body dentro do Annotated: como valor padrão, o FastAPI perderia o Discriminator
        payload: Annotated[EventPayload, Body(examples=[{
            "app": "loja", "event": "login_failed", "user": "ana", "srcip": "203.0.113.7",
            "message": "senha incorreta"}])],
        _: str = Depends(require_write),
        wazuh: WazuhClient = Depends(wazuh_client),
    ):
        events = payload.events if isinstance(payload, EventBatch) else [payload]
        response = await wazuh.request("POST", "/events", json={"events": [event.to_wazuh() for event in events]})
        data = response.get("data", {})
        failed = data.get("total_failed_items", 0)
        return {"accepted": data.get("total_affected_items", len(events)), "failed": failed,
                "errors": [item.get("error", {}).get("message") for item in data.get("failed_items", [])]}

    return app
