"""Consultas de alertas no Wazuh indexer e o formato simplificado devolvido pela API."""

import re
from datetime import datetime, timedelta, timezone

RELATIVE = re.compile(r"^(\d{1,5})\s*([smhdw])$")
UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}

SEVERITIES = ((12, "critico"), (10, "alto"), (7, "medio"), (0, "baixo"))
SEVERITY_LEVELS = {"critico": (12, 16), "alto": (10, 11), "medio": (7, 9), "baixo": (0, 6)}

# Regras de Active Response do Reefed (reefed-0250-firewall_rules.xml)
AR_BLOCK_RULE = "110260"
AR_UNBLOCK_RULE = "110261"


def parse_time(value, now=None):
    """Aceita "24h", "15m", "7d", "2w" ou data ISO 8601. Devolve datetime com fuso."""
    now = now or datetime.now(timezone.utc)
    if value is None or value == "":
        return None
    match = RELATIVE.match(value.strip().lower())
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        return now - timedelta(**{UNITS[unit]: amount})
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"data inválida: {value!r} (use 24h, 7d ou ISO 8601)") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def severity(level):
    for minimum, label in SEVERITIES:
        if level >= minimum:
            return label
    return "baixo"


def build_filters(since=None, until=None, min_level=None, max_level=None, rule_ids=None, groups=None,
                  agent=None, srcip=None, user=None, mitre=None, only_reefed=True, text=None):
    filters = []
    time_range = {}
    if since:
        time_range["gte"] = iso(since)
    if until:
        time_range["lte"] = iso(until)
    if time_range:
        filters.append({"range": {"timestamp": time_range}})
    level_range = {}
    if min_level is not None:
        level_range["gte"] = min_level
    if max_level is not None:
        level_range["lte"] = max_level
    if level_range:
        filters.append({"range": {"rule.level": level_range}})
    if only_reefed:
        filters.append({"term": {"rule.groups": "reefed"}})
    if rule_ids:
        filters.append({"terms": {"rule.id": list(rule_ids)}})
    for group in groups or []:
        filters.append({"term": {"rule.groups": group}})
    if agent:
        filters.append({"bool": {"should": [{"term": {"agent.name": agent}}, {"term": {"agent.id": agent}}],
                                 "minimum_should_match": 1}})
    if srcip:
        filters.append({"term": {"data.srcip": srcip}})
    if user:
        filters.append({"term": {"data.dstuser": user}})
    if mitre:
        filters.append({"bool": {"should": [{"term": {"rule.mitre.id": mitre}},
                                            {"term": {"rule.mitre.tactic": mitre}}],
                                 "minimum_should_match": 1}})
    if text:
        filters.append({"simple_query_string": {"query": text, "fields": ["rule.description", "full_log"],
                                                "default_operator": "and"}})
    return filters


def get_path(data, path, default=None):
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def simplify(hit):
    """Converte um documento do indexer no formato da API do Reefed."""
    source = hit.get("_source", hit)
    rule = source.get("rule", {})
    data = source.get("data", {})
    mitre = rule.get("mitre", {}) or {}
    level = int(rule.get("level", 0) or 0)
    return {
        "id": source.get("id") or hit.get("_id"),
        "timestamp": source.get("timestamp"),
        "level": level,
        "severity": severity(level),
        "rule": {
            "id": str(rule.get("id", "")),
            "description": rule.get("description", ""),
            "groups": rule.get("groups", []),
            "firedtimes": rule.get("firedtimes"),
            "mitre": {
                "ids": mitre.get("id", []),
                "tactics": mitre.get("tactic", []),
                "techniques": mitre.get("technique", []),
            },
        },
        "agent": {"id": get_path(source, "agent.id"), "name": get_path(source, "agent.name"),
                  "ip": get_path(source, "agent.ip")},
        "srcip": data.get("srcip"),
        "user": data.get("dstuser"),
        "database": {
            "name": get_path(data, "db.name"),
            "client": get_path(data, "db.client"),
            "app": get_path(data, "db.app"),
            "query": get_path(data, "db.query"),
            "operation": get_path(data, "db.operation"),
        },
        "app_event": data.get("reefed") if isinstance(data.get("reefed"), dict) else None,
        "location": source.get("location"),
        "full_log": source.get("full_log"),
        "index": hit.get("_index"),
    }


def summary_aggregations(top=10):
    return {
        "levels": {"range": {"field": "rule.level", "ranges": [
            {"key": "baixo", "to": 7}, {"key": "medio", "from": 7, "to": 10},
            {"key": "alto", "from": 10, "to": 12}, {"key": "critico", "from": 12}]}},
        "rules": {"terms": {"field": "rule.id", "size": top},
                  "aggs": {"description": {"terms": {"field": "rule.description", "size": 1}},
                           "max_level": {"max": {"field": "rule.level"}}}},
        "srcips": {"terms": {"field": "data.srcip", "size": top}},
        "users": {"terms": {"field": "data.dstuser", "size": top}},
        "agents": {"terms": {"field": "agent.name", "size": top}},
        "mitre": {"terms": {"field": "rule.mitre.id", "size": top},
                  "aggs": {"technique": {"terms": {"field": "rule.mitre.technique", "size": 1}}}},
        "tactics": {"terms": {"field": "rule.mitre.tactic", "size": top}},
    }


def parse_summary(response):
    aggs = response.get("aggregations", {}) or {}

    def buckets(name):
        return (aggs.get(name) or {}).get("buckets", [])

    def first_key(bucket, name):
        inner = (bucket.get(name) or {}).get("buckets", [])
        return inner[0]["key"] if inner else None

    total = get_path(response, "hits.total.value", 0)
    return {
        "total": total,
        "by_severity": {bucket["key"]: bucket["doc_count"] for bucket in buckets("levels")},
        "top_rules": [{"id": bucket["key"], "count": bucket["doc_count"],
                       "description": first_key(bucket, "description"),
                       "level": int((bucket.get("max_level") or {}).get("value") or 0)}
                      for bucket in buckets("rules")],
        "top_srcips": [{"ip": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets("srcips")],
        "top_users": [{"user": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets("users")],
        "top_agents": [{"agent": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets("agents")],
        "top_mitre": [{"id": bucket["key"], "count": bucket["doc_count"],
                       "technique": first_key(bucket, "technique")} for bucket in buckets("mitre")],
        "tactics": [{"tactic": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets("tactics")],
    }


def blocked_ips(hits, ar_timeout, now=None):
    """Estado de bloqueio por (agente, IP) a partir dos alertas 110260/110261, do mais
    antigo para o mais novo. Bloqueado = último evento foi bloqueio e o tempo não acabou."""
    now = now or datetime.now(timezone.utc)
    state = {}
    for hit in hits:
        source = hit.get("_source", hit)
        rule_id = str(get_path(source, "rule.id", ""))
        ip = get_path(source, "data.parameters.alert.data.srcip")
        agent = get_path(source, "agent.name")
        if not ip:
            continue
        key = (agent, ip)
        when = parse_time(source.get("timestamp"))
        entry = state.setdefault(key, {"ip": ip, "agent": agent, "agent_id": get_path(source, "agent.id"),
                                       "blocked_at": None, "unblocked_at": None, "rule": None,
                                       "times_blocked": 0})
        if rule_id == AR_BLOCK_RULE:
            entry["blocked_at"] = when
            entry["unblocked_at"] = None
            entry["rule"] = {"id": str(get_path(source, "data.parameters.alert.rule.id", "")),
                             "description": get_path(source, "data.parameters.alert.rule.description")}
            entry["times_blocked"] += 1
        elif rule_id == AR_UNBLOCK_RULE:
            entry["unblocked_at"] = when
    active, history = [], []
    for entry in state.values():
        blocked_at = entry["blocked_at"]
        if blocked_at is None:
            continue
        expires = blocked_at + timedelta(seconds=ar_timeout)
        is_active = entry["unblocked_at"] is None and expires > now
        item = {**entry, "blocked_at": iso(blocked_at), "expires_at": iso(expires),
                "unblocked_at": iso(entry["unblocked_at"]) if entry["unblocked_at"] else None,
                "active": is_active}
        (active if is_active else history).append(item)
    active.sort(key=lambda item: item["blocked_at"], reverse=True)
    history.sort(key=lambda item: item["blocked_at"], reverse=True)
    return active, history
