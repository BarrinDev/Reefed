"""Cliente Python da API do Reefed (só biblioteca padrão).

Copie este arquivo para o seu projeto:

    from reefed_client import ReefedClient

    reefed = ReefedClient("http://reefed.exemplo:8000", api_key="...")
    reefed.notify("loja", "login_failed", user="ana", srcip="203.0.113.7",
                  message="senha incorreta")
    for alerta in reefed.alerts(since="1h", min_level=10)["items"]:
        print(alerta["level"], alerta["rule"]["description"])

Também funciona na linha de comando:

    export REEFED_URL=http://localhost:8000 REEFED_API_KEY=...
    python reefed_client.py status
    python reefed_client.py alerts --since 2h --min-level 10
    python reefed_client.py event loja login_failed --user ana --srcip 203.0.113.7
"""

import json
import logging
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request


class ReefedError(Exception):
    def __init__(self, status, detail):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class ReefedClient:
    def __init__(self, base_url, api_key, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    # ------------------------------------------------------------------
    def _request(self, method, path, params=None, body=None):
        url = self.base_url + path
        if params:
            query = []
            for key, value in params.items():
                if value is None:
                    continue
                for item in value if isinstance(value, (list, tuple)) else [value]:
                    query.append((key, str(item).lower() if isinstance(item, bool) else str(item)))
            if query:
                url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("X-API-Key", self.api_key)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read()).get("detail")
            except (ValueError, AttributeError):
                detail = exc.reason
            raise ReefedError(exc.code, detail) from None

    # ------------------------------------------------------------------
    def health(self):
        return self._request("GET", "/health")

    def status(self):
        return self._request("GET", "/api/v1/status")

    def alerts(self, since="24h", until=None, min_level=3, max_level=None, severity=None, rule_id=None,
               group=None, agent=None, srcip=None, user=None, mitre=None, q=None, all_rules=False,
               limit=50, offset=0):
        """Alertas mais novos primeiro. severity: baixo, medio, alto ou critico."""
        return self._request("GET", "/api/v1/alerts", params={
            "since": since, "until": until, "min_level": min_level, "max_level": max_level,
            "severity": severity, "rule_id": rule_id, "group": group, "agent": agent, "srcip": srcip,
            "user": user, "mitre": mitre, "q": q, "all_rules": all_rules or None, "limit": limit,
            "offset": offset})

    def alert(self, alert_id):
        return self._request("GET", f"/api/v1/alerts/{urllib.parse.quote(alert_id)}")

    def summary(self, since="24h", min_level=3, agent=None, top=10):
        return self._request("GET", "/api/v1/alerts/summary",
                             params={"since": since, "min_level": min_level, "agent": agent, "top": top})

    def blocked(self, since="24h"):
        return self._request("GET", "/api/v1/blocked", params={"since": since})

    def agents(self, status=None, group=None):
        return self._request("GET", "/api/v1/agents", params={"status": status, "group": group})

    def rules(self):
        return self._request("GET", "/api/v1/rules")

    def send_event(self, app, event, user=None, srcip=None, message=None, records=None, role=None,
                   severity=None, request_id=None, extra=None):
        """Eventos conhecidos: login_success, login_failed, access_denied, permission_change,
        user_created, data_export, bulk_delete, sql_injection_blocked, config_change.
        Outros nomes usam severity (low, medium, high, critical)."""
        event_body = {"app": app, "event": event, "user": user, "srcip": srcip, "message": message,
                      "records": records, "role": role, "severity": severity, "request_id": request_id,
                      "extra": extra}
        return self._request("POST", "/api/v1/events",
                             body={key: value for key, value in event_body.items() if value is not None})

    def send_events(self, events):
        """Lote de até 100 eventos (dicionários no formato de send_event)."""
        return self._request("POST", "/api/v1/events", body={"events": events})

    def notify(self, app, event, **fields):
        """Envia o evento numa thread, sem esperar nem lançar exceção: não atrasa a
        resposta ao usuário, e um Reefed fora do ar não derruba o seu sistema. Problemas
        vão para o logging (logger "reefed")."""
        def send():
            try:
                self.send_event(app, event, **fields)
            except (ReefedError, OSError, ValueError) as exc:
                logging.getLogger("reefed").warning("evento %s não enviado: %s", event, exc)

        thread = threading.Thread(target=send, name="reefed-notify", daemon=True)
        thread.start()
        return thread


def _main(argv):
    import argparse

    parser = argparse.ArgumentParser(description="Cliente da API do Reefed")
    parser.add_argument("--url", default=os.environ.get("REEFED_URL", "http://localhost:8000"))
    parser.add_argument("--key", default=os.environ.get("REEFED_API_KEY", ""))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health")
    sub.add_parser("status")
    sub.add_parser("agents")
    sub.add_parser("blocked")
    sub.add_parser("rules")
    alerts = sub.add_parser("alerts")
    alerts.add_argument("--since", default="24h")
    alerts.add_argument("--min-level", type=int, default=3)
    alerts.add_argument("--rule-id", action="append")
    alerts.add_argument("--srcip")
    alerts.add_argument("--limit", type=int, default=20)
    summary = sub.add_parser("summary")
    summary.add_argument("--since", default="24h")
    event = sub.add_parser("event")
    event.add_argument("app")
    event.add_argument("event")
    event.add_argument("--user")
    event.add_argument("--srcip")
    event.add_argument("--message")
    event.add_argument("--records", type=int)
    event.add_argument("--role")
    event.add_argument("--severity")
    args = parser.parse_args(argv)

    if not args.key:
        parser.error("informe a chave com --key ou REEFED_API_KEY")
    client = ReefedClient(args.url, args.key)
    try:
        if args.command == "alerts":
            result = client.alerts(since=args.since, min_level=args.min_level, rule_id=args.rule_id,
                                   srcip=args.srcip, limit=args.limit)
            for item in result["items"]:
                print(f"{item['timestamp']}  nível {item['level']:>2}  {item['rule']['id']}  "
                      f"{item['rule']['description']}")
            print(f"({len(result['items'])} de {result['total']})")
            return 0
        if args.command == "event":
            result = client.send_event(args.app, args.event, user=args.user, srcip=args.srcip,
                                       message=args.message, records=args.records, role=args.role,
                                       severity=args.severity)
        elif args.command == "summary":
            result = client.summary(since=args.since)
        else:
            result = getattr(client, args.command)()
    except ReefedError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"erro de conexão: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
