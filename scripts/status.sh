#!/usr/bin/env bash
# Reefed - espera o Reefed ficar pronto e mostra o estado (make status / make up).
#
#   scripts/status.sh [segundos]    tempo máximo de espera (padrão: 300)
#
# A consulta roda dentro do container da API do Reefed: no host não precisa de
# curl nem de Python.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib.sh

timeout=${1:-300}
docker compose ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'
echo

deadline=$((SECONDS + timeout))
until docker compose ps --status running --services 2>/dev/null | grep -qx reefed-api; do
  [ "$SECONDS" -lt "$deadline" ] || fail "o container reefed-api não está rodando (veja: make logs S=reefed-api)"
  sleep 3
done

docker compose exec -T reefed-api python - "$((deadline - SECONDS))" <<'PY' || exit 1
import json, os, sys, time, urllib.error, urllib.request

timeout = max(int(sys.argv[1]), 10)
request = urllib.request.Request("http://127.0.0.1:8000/api/v1/status",
                                 headers={"X-API-Key": os.environ["REEFED_API_KEY"]})
deadline = time.time() + timeout
last, shown = "", False
while True:
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.load(response)
        if data.get("status") == "ok":
            break
        last = "serviços do manager parados: " + ", ".join(data["manager"]["stopped"])
    except urllib.error.HTTPError as exc:
        last = f"HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}"
    except (OSError, ValueError) as exc:
        last = str(getattr(exc, "reason", exc))
    if time.time() > deadline:
        print(f"[reefed] o Reefed não ficou pronto em {timeout}s ({last})")
        print("[reefed] o indexer e o manager levam alguns minutos na primeira vez; veja: make logs")
        sys.exit(1)
    if not shown:
        print("[reefed] esperando o indexer e o manager responderem...", flush=True)
        shown = True
    time.sleep(5)

manager, agents, alerts = data["manager"], data["agents"].get("connection", {}), data["alerts_24h"]
severity = alerts["by_severity"]
print(f"[reefed] Wazuh {manager['version']}: manager, indexer e API no ar")
print(f"[reefed] agentes: {agents.get('active', 0)} ativo(s), {agents.get('disconnected', 0)} desconectado(s), "
      f"{agents.get('never_connected', 0)} nunca conectado(s)")
print(f"[reefed] alertas nas últimas 24 h: {alerts['total']} (crítico {severity.get('critico', 0)}, "
      f"alto {severity.get('alto', 0)}, médio {severity.get('medio', 0)}, baixo {severity.get('baixo', 0)})")
names = {"telegram": "Telegram", "slack": "Slack", "email": "e-mail"}
channels = [names.get(channel, channel) for channel in manager.get("alert_channels") or []]
if channels:
    print(f"[reefed] notificações: {', '.join(channels)}")
else:
    print("[reefed] notificações: nenhum canal configurado (Telegram, Slack ou e-mail: docs/alertas.md)")
PY

dashboard_port=$(env_value REEFED_DASHBOARD_PORT)
api_port=$(env_value REEFED_API_PORT)
info "dashboard: https://localhost:${dashboard_port:-443}  (usuário admin, senha INDEXER_PASSWORD do .env)"
info "API do Reefed: http://localhost:${api_port:-8000}/docs  (cabeçalho X-API-Key com a REEFED_API_KEY do .env)"
