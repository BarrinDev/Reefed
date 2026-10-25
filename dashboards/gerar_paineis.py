"""Gera dashboards/reefed.ndjson: os painéis do Reefed no Wazuh dashboard.

O arquivo .ndjson tem os objetos salvos do OpenSearch Dashboards (padrão de índice,
visualizações, pesquisa salva e o painel). Para mudar um painel, edite este script
e rode de novo, em vez de editar o .ndjson à mão:

    python3 dashboards/gerar_paineis.py      # regrava dashboards/reefed.ndjson
    make dashboards                          # importa no dashboard (atualiza os painéis)

Mudanças feitas direto na tela do dashboard ficam só no dashboard; para trazê-las
para o repositório, exporte em Dashboards Management > Saved objects.
"""
import json
import os
import sys

INDEX = "wazuh-alerts-*"
BASE_QUERY = "rule.groups:reefed"
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "reefed.ndjson")

objects = []


def search_source(query=BASE_QUERY, filters=None):
    return json.dumps({
        "query": {"query": query, "language": "kuery"},
        "filter": filters or [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }, ensure_ascii=False)


COLORS = {"Crítico (12 a 15)": "#BD271E", "Alto (10 e 11)": "#E7664C",
          "Médio (7 a 9)": "#D6BF57", "Baixo (até 6)": "#6092C0"}


def vis(vid, title, vis_type, params, aggs, query=BASE_QUERY, description="", ui_state=None):
    objects.append({
        "id": vid,
        "type": "visualization",
        "attributes": {
            "title": title,
            "description": description,
            "visState": json.dumps({"title": title, "type": vis_type, "params": params, "aggs": aggs}, ensure_ascii=False),
            "uiStateJSON": json.dumps(ui_state or {}, ensure_ascii=False),
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX}],
    })
    return vid


def count(aid="1", label=None):
    agg = {"id": aid, "enabled": True, "type": "count", "schema": "metric", "params": {}}
    if label:
        agg["params"]["customLabel"] = label
    return agg


def terms(aid, field, size, schema="bucket", label=None, order_by="1", other=False):
    params = {"field": field, "size": size, "order": "desc", "orderBy": order_by,
              "otherBucket": other, "otherBucketLabel": "Outros", "missingBucket": False,
              "missingBucketLabel": "Sem valor"}
    if label:
        params["customLabel"] = label
    return {"id": aid, "enabled": True, "type": "terms", "schema": schema, "params": params}


def metric_agg(aid, agg_type, field, label):
    return {"id": aid, "enabled": True, "type": agg_type, "schema": "metric",
            "params": {"field": field, "customLabel": label}}


def table(per_page):
    return dict(TABLE, perPage=per_page)


TABLE = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
         "sort": {"columnIndex": None, "direction": None}, "showTotal": False,
         "totalFunc": "sum", "percentageCol": ""}
PIE = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True,
       "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}

LEVELS = [
    ("rule.level >= 12", "Crítico (12 a 15)"),
    ("rule.level >= 10 and rule.level < 12", "Alto (10 e 11)"),
    ("rule.level >= 7 and rule.level < 10", "Médio (7 a 9)"),
    ("rule.level < 7", "Baixo (até 6)"),
]


def level_filters(aid, schema):
    return {"id": aid, "enabled": True, "type": "filters", "schema": schema,
            "params": {"filters": [{"input": {"query": q, "language": "kuery"}, "label": label}
                                   for q, label in LEVELS]}}


# ------------------------------------------------------------------ visualizações
panels = []  # (vid, x, y, w, h)

v = vis("reefed-vis-sobre", "Reefed - Sobre este painel", "markdown", {
    "fontSize": 11, "openLinksInNewTab": True,
    "markdown": (
        "**Reefed**: alertas de segurança dos bancos de dados e do sistema que usa o banco.\n\n"
        "Severidade: **12 a 15 crítico**, **10 e 11 alto**, **7 a 9 médio**, até 6 baixo. "
        "Clique num valor para filtrar o painel inteiro.\n\n"
        "Cada alerta em detalhe: Discover, pesquisa salva *Reefed - alertas*."),
}, [])
panels.append((v, 0, 0, 16, 9))

v = vis("reefed-vis-severidade", "Reefed - Alertas por severidade", "metric", {
    "addTooltip": True, "addLegend": False, "type": "metric",
    "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
               "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
               "labels": {"show": True}, "invertColors": False,
               "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 36}},
}, [count("1", "Alertas"), level_filters("2", "group")])
panels.append((v, 16, 0, 32, 9))

v = vis("reefed-vis-linha-do-tempo", "Reefed - Alertas ao longo do tempo", "histogram", {
    "type": "histogram", "grid": {"categoryLines": False},
    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {},
                      "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100},
                      "title": {}}],
    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
                   "style": {}, "scale": {"type": "linear", "mode": "normal"},
                   "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                   "title": {"text": "Alertas"}}],
    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                      "data": {"label": "Alertas", "id": "1"}, "valueAxis": "ValueAxis-1",
                      "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
    "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [], "addTimeMarker": False,
    "labels": {"show": False},
    "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
}, [count("1", "Alertas"),
    {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
     "params": {"field": "timestamp", "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {},
                "customLabel": "Horário"}},
    level_filters("3", "group")], ui_state={"vis": {"colors": COLORS}})
panels.append((v, 0, 9, 48, 12))

v = vis("reefed-vis-regras", "Reefed - Regras que mais dispararam", "table", table(10), [
    count("1", "Alertas"),
    metric_agg("4", "max", "rule.level", "Nível"),
    terms("2", "rule.id", 20, label="Regra"),
    terms("3", "rule.description", 1, label="Descrição"),
])
panels.append((v, 0, 21, 30, 19))

v = vis("reefed-vis-origens", "Reefed - IPs de origem", "table", table(10), [
    count("1", "Alertas"),
    metric_agg("3", "max", "rule.level", "Nível máximo"),
    metric_agg("4", "cardinality", "rule.id", "Regras diferentes"),
    terms("2", "data.srcip", 15, label="IP de origem"),
], query=BASE_QUERY + " and data.srcip:*")
panels.append((v, 30, 21, 18, 19))

v = vis("reefed-vis-mitre-taticas", "Reefed - Táticas MITRE ATT&CK", "pie", PIE, [
    count("1", "Alertas"), terms("2", "rule.mitre.tactic", 12, schema="segment", label="Tática"),
], query=BASE_QUERY + " and rule.mitre.tactic:*")
panels.append((v, 0, 40, 16, 15))

v = vis("reefed-vis-mitre-tecnicas", "Reefed - Técnicas MITRE ATT&CK", "table", table(7), [
    count("1", "Alertas"),
    terms("2", "rule.mitre.id", 15, label="Técnica"),
    terms("3", "rule.mitre.technique", 1, label="Nome"),
], query=BASE_QUERY + " and rule.mitre.id:*")
panels.append((v, 16, 40, 16, 15))

v = vis("reefed-vis-servidores", "Reefed - Alertas por servidor", "pie", PIE, [
    count("1", "Alertas"), terms("2", "agent.name", 10, schema="segment", label="Servidor"),
])
panels.append((v, 32, 40, 16, 15))

v = vis("reefed-vis-usuarios", "Reefed - Usuários do banco envolvidos", "table", table(7), [
    count("1", "Alertas"),
    metric_agg("3", "cardinality", "data.srcip", "IPs diferentes"),
    terms("2", "data.dstuser", 10, label="Usuário"),
], query=BASE_QUERY + " and data.dstuser:*")
panels.append((v, 0, 55, 16, 15))

v = vis("reefed-vis-bloqueios", "Reefed - IPs bloqueados pelo Active Response", "table", table(7), [
    count("1", "Bloqueios"),
    {"id": "3", "enabled": True, "type": "max", "schema": "metric",
     "params": {"field": "timestamp", "customLabel": "Último bloqueio"}},
    terms("2", "data.srcip", 10, label="IP bloqueado"),
], query="rule.id:110260")
panels.append((v, 16, 55, 16, 15))

v = vis("reefed-vis-comandos", "Reefed - Comandos SQL nos alertas", "table", table(7), [
    count("1", "Alertas"),
    terms("2", "data.db.query", 10, label="Comando"),
], query=BASE_QUERY + " and data.db.query:* and rule.level >= 7")
panels.append((v, 32, 55, 16, 15))

# ------------------------------------------------------------------ pesquisa salva
objects.append({
    "id": "reefed-search-alertas",
    "type": "search",
    "attributes": {
        "title": "Reefed - alertas",
        "description": "Alertas do Reefed com as colunas principais",
        "hits": 0,
        "columns": ["rule.level", "rule.description", "agent.name", "data.srcip", "data.dstuser", "rule.mitre.id"],
        "sort": [["timestamp", "desc"]],
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
    },
    "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX}],
})

# ------------------------------------------------------------------ painel
panels_json, references = [], []
for number, (vid, x, y, w, h) in enumerate(panels):
    panels_json.append({"version": "2.19.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(number + 1)},
                        "panelIndex": str(number + 1), "embeddableConfig": {}, "panelRefName": f"panel_{number}"})
    references.append({"name": f"panel_{number}", "type": "visualization", "id": vid})
objects.append({
    "id": "reefed-dashboard",
    "type": "dashboard",
    "attributes": {
        "title": "Reefed - Segurança do banco de dados",
        "description": "Visão geral dos alertas do Reefed: severidade, regras, origens, MITRE ATT&CK e bloqueios.",
        "hits": 0,
        "panelsJSON": json.dumps(panels_json, ensure_ascii=False),
        "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
        "version": 1,
        "timeRestore": True,
        "timeFrom": "now-24h",
        "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 60000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "references": references,
})

# O padrão de índice vem primeiro (o reefed_init.py só o cria se ainda não existir)
index_pattern = {
    "id": INDEX,
    "type": "index-pattern",
    "attributes": {"title": INDEX, "timeFieldName": "timestamp"},
    "references": [],
}
with open(OUT, "w", encoding="utf-8") as handle:
    for obj in [index_pattern] + objects:
        handle.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
print(f"{len(objects) + 1} objetos gravados em {OUT}")
