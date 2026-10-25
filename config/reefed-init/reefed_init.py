"""Reefed - preparação do indexer e do dashboard.

Roda como o serviço "reefed-init" a cada "docker compose up" e termina:

  1. instala o modelo de índice "reefed" (reefed-template.json) no indexer e aplica
     os mesmos limites nos índices de alertas que já existem (o do primeiro dia de
     uma instalação nova é criado antes do modelo). Sem isso, um comando SQL, um
     diff do FIM ou um histórico de correlação com mais de 32 KB faria o indexer
     recusar o alerta inteiro; com isso, textos longos continuam guardados e o
     comando SQL e a mensagem do banco continuam pesquisáveis;
  2. aplica a retenção dos alertas (REEFED_RETENTION_DAYS): uma política do Index
     State Management do indexer apaga os índices diários de alertas mais velhos que
     isso. 0 ou vazio desliga (nada é apagado);
  3. importa os painéis do Reefed (dashboards/reefed.ndjson) no Wazuh dashboard.
     Por padrão só cria o que ainda não existe, para não desfazer mudanças feitas
     na tela. Com --overwrite (make dashboards) atualiza os painéis do Reefed.
     O padrão de índice wazuh-alerts-* só é criado se ainda não existir.

Variáveis: INDEXER_URL, DASHBOARD_URL, REEFED_ADMIN_USER, REEFED_ADMIN_PASSWORD,
REEFED_CA (CA dos certificados gerados pelo setup.sh), REEFED_RETENTION_DAYS e
REEFED_INIT_TIMEOUT.
"""

import argparse
import json
import os
import ssl
import sys
import time

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_FILE = os.path.join(HERE, "reefed-template.json")
DASHBOARDS_FILE = os.environ.get("REEFED_DASHBOARDS_FILE", "/reefed/dashboards/reefed.ndjson")
INDEX_PATTERN = "wazuh-alerts-*"
RETENTION_POLICY = "reefed-retencao"


def log(message):
    print(f"[reefed-init] {message}", flush=True)


def client():
    ca = os.environ.get("REEFED_CA", "")
    verify = ssl.create_default_context(cafile=ca) if ca else True
    return httpx.Client(
        auth=(os.environ.get("REEFED_ADMIN_USER", "admin"), os.environ["REEFED_ADMIN_PASSWORD"]),
        verify=verify,
        timeout=30,
        headers={"osd-xsrf": "true"},  # exigido pela API do dashboard em POST/PUT
    )


def wait_for(http, url, ready, what, timeout):
    """Espera o serviço responder (o indexer e o dashboard levam alguns minutos para subir)."""
    deadline = time.time() + timeout
    last = "sem resposta"
    while time.time() < deadline:
        try:
            response = http.get(url)
            if ready(response):
                return response
            last = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last = str(exc) or exc.__class__.__name__
        time.sleep(5)
    raise SystemExit(f"[reefed-init] {what} não ficou pronto em {timeout}s ({last})")


def install_template(http, indexer, timeout):
    wait_for(http, f"{indexer}/_cluster/health",
             lambda r: r.status_code == 200 and r.json().get("status") in ("green", "yellow"),
             "indexer", timeout)
    with open(TEMPLATE_FILE, encoding="utf-8") as handle:
        template = json.load(handle)
    response = http.put(f"{indexer}/_template/reefed", json=template)
    if response.status_code >= 400:
        raise SystemExit(f"[reefed-init] modelo de índice recusado: HTTP {response.status_code} {response.text[:300]}")
    log("modelo de índice 'reefed' instalado")
    update_existing_indices(http, indexer, template)


def update_existing_indices(http, indexer, template):
    """Leva os limites do modelo para os índices que já existem. O ignore_above e os
    subcampos de texto podem ser acrescentados a um campo keyword de um índice existente;
    um índice em que o campo tenha outro tipo fica como está."""
    mapping = {key: template["mappings"][key] for key in ("dynamic_templates", "properties")}
    response = http.get(f"{indexer}/_cat/indices/{','.join(template['index_patterns'])}",
                        params={"h": "index", "format": "json", "expand_wildcards": "open"})
    if response.status_code >= 400:
        log(f"não consegui listar os índices de alertas: HTTP {response.status_code}")
        return
    indices = sorted(item["index"] for item in response.json())
    if not indices:
        return
    # Um pedido só para todos; se algum índice recusar, um por um
    response = http.put(f"{indexer}/{','.join(template['index_patterns'])}/_mapping", json=mapping,
                        params={"allow_no_indices": "true", "ignore_unavailable": "true"})
    if response.status_code < 400:
        log(f"limites do modelo aplicados também em {len(indices)} índice(s) que já existiam")
        return
    refused = [index for index in indices
               if http.put(f"{indexer}/{index}/_mapping", json=mapping).status_code >= 400]
    log(f"limites do modelo aplicados em {len(indices) - len(refused)} índice(s) que já existiam"
        + (f"; {len(refused)} recusaram (ficam como estão): {', '.join(refused[:5])}" if refused else ""))


def apply_retention(http, indexer, days, patterns):
    """Política de retenção do Index State Management: cada índice diário de alertas é
    apagado quando passa de `days` dias. Vale para os índices novos (ism_template) e para
    os que já existem. days <= 0 tira a política."""
    url = f"{indexer}/_plugins/_ism/policies/{RETENTION_POLICY}"
    targets = ",".join(patterns)
    current = http.get(url)
    exists = current.status_code == 200
    if days <= 0:
        if exists:
            http.post(f"{indexer}/_plugins/_ism/remove/{targets}")
            http.delete(url)
            log("retenção desligada: os índices de alertas não são mais apagados")
        return
    description = f"Reefed: apaga os índices de alertas com mais de {days} dias (REEFED_RETENTION_DAYS)"
    if exists and current.json().get("policy", {}).get("description") == description:
        log(f"retenção: índices de alertas com mais de {days} dias são apagados")
        return
    policy = {"policy": {
        "description": description,
        "default_state": "guardar",
        "states": [
            {"name": "guardar", "actions": [],
             "transitions": [{"state_name": "apagar", "conditions": {"min_index_age": f"{days}d"}}]},
            {"name": "apagar", "actions": [{"delete": {}}], "transitions": []},
        ],
        "ism_template": [{"index_patterns": patterns, "priority": 100}],
    }}
    params = {}
    if exists:  # o ISM só aceita a troca com o número de versão atual da política
        params = {"if_seq_no": current.json()["_seq_no"], "if_primary_term": current.json()["_primary_term"]}
    response = http.put(url, json=policy, params=params)
    if response.status_code >= 400:
        log(f"política de retenção recusada: HTTP {response.status_code} {response.text[:300]}")
        return
    # Índices que já existem: os sem política recebem esta; os que tinham a versão antiga mudam
    http.post(f"{indexer}/_plugins/_ism/add/{targets}", json={"policy_id": RETENTION_POLICY})
    if exists:
        http.post(f"{indexer}/_plugins/_ism/change_policy/{targets}", json={"policy_id": RETENTION_POLICY})
    log(f"retenção: índices de alertas com mais de {days} dias são apagados")


def import_dashboards(http, dashboard, timeout, overwrite):
    wait_for(http, f"{dashboard}/api/status",
             lambda r: r.status_code == 200
             and r.json().get("status", {}).get("overall", {}).get("state") == "green",
             "dashboard", timeout)

    with open(DASHBOARDS_FILE, encoding="utf-8") as handle:
        objects = [json.loads(line) for line in handle if line.strip()]

    # O padrão de índice é do Wazuh também: só cria se não existir, nunca sobrescreve
    exists = http.get(f"{dashboard}/api/saved_objects/index-pattern/{INDEX_PATTERN}").status_code == 200
    if exists:
        objects = [obj for obj in objects if obj["type"] != "index-pattern"]
    payload = "".join(json.dumps(obj, ensure_ascii=False) + "\n" for obj in objects)

    response = http.post(
        f"{dashboard}/api/saved_objects/_import",
        params={"overwrite": "true" if overwrite else "false"},
        files={"file": ("reefed.ndjson", payload.encode("utf-8"), "application/ndjson")},
    )
    if response.status_code >= 400:
        raise SystemExit(f"[reefed-init] importação recusada: HTTP {response.status_code} {response.text[:300]}")
    result = response.json()
    errors = result.get("errors", []) or []
    conflicts = [e for e in errors if e.get("error", {}).get("type") == "conflict"]
    failures = [e for e in errors if e not in conflicts]
    for error in failures:
        log(f"falha ao importar {error.get('type')} '{error.get('title') or error.get('id')}': {error.get('error')}")
    log(f"painéis: {result.get('successCount', 0)} objeto(s) importado(s)"
        + (f", {len(conflicts)} já existia(m) (use 'make dashboards' para atualizar)" if conflicts else ""))

    # Discover abre direto nos alertas se ninguém escolheu outro padrão de índice
    settings = http.get(f"{dashboard}/api/opensearch-dashboards/settings")
    if settings.status_code == 200 and not settings.json().get("settings", {}).get("defaultIndex", {}).get("userValue"):
        http.post(f"{dashboard}/api/opensearch-dashboards/settings", json={"changes": {"defaultIndex": INDEX_PATTERN}})
    return not failures


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--overwrite", action="store_true", help="atualiza os painéis do Reefed que já existem")
    parser.add_argument("--skip-template", action="store_true")
    parser.add_argument("--skip-dashboards", action="store_true")
    args = parser.parse_args()

    timeout = int(os.environ.get("REEFED_INIT_TIMEOUT", "600"))
    indexer = os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200").rstrip("/")
    dashboard = os.environ.get("DASHBOARD_URL", "https://wazuh.dashboard:5601").rstrip("/")
    ok = True
    days = os.environ.get("REEFED_RETENTION_DAYS", "").strip() or "0"
    if not days.isdigit():
        log(f"REEFED_RETENTION_DAYS inválido ({days!r}); a retenção não foi alterada")
        days = None
    with client() as http:
        if not args.skip_template:
            install_template(http, indexer, timeout)
            if days is not None:
                with open(TEMPLATE_FILE, encoding="utf-8") as handle:
                    patterns = json.load(handle)["index_patterns"]
                apply_retention(http, indexer, int(days), patterns)
        if not args.skip_dashboards:
            ok = import_dashboards(http, dashboard, timeout, args.overwrite)
    log("pronto" if ok else "terminado com erros")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
