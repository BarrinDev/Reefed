"""Reefed lab - utilidades compartilhadas pelo app, pelo atacante e pelo validador.

Conexões com os três bancos (pg8000 para PostgreSQL, PyMySQL para MySQL e
MariaDB) e um cliente pequeno da API do Reefed e do receptor falso de alertas.
Tudo lê os endereços das variáveis de ambiente definidas no compose do lab.
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

import pg8000.dbapi
import pymysql

PG_HOST = os.environ.get("PG_HOST", "postgres")
MYSQL_HOST = os.environ.get("MYSQL_HOST", "mysql")
MARIADB_HOST = os.environ.get("MARIADB_HOST", "mariadb")
REEFED_API = os.environ.get("REEFED_API", "http://reefed-api:8000").rstrip("/")
REEFED_API_KEY = os.environ.get("REEFED_API_KEY", "")
MOCK_URL = os.environ.get("MOCK_URL", "http://mock-alerts:8080").rstrip("/")

# TLS sem verificação: o laboratório usa os certificados autoassinados que o
# MySQL cria sozinho. Serve só para o PyMySQL falar caching_sha2 sem a
# biblioteca cryptography (o MySQL 8.4 não traz mais o mysql_native_password).
_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE


def log(*parts):
    print(*parts, flush=True)


# ---------------------------------------------------------------------------
# Conexões com os bancos

def pg(user="app", password="app-senha-forte", database="loja", application_name="loja-app"):
    conn = pg8000.dbapi.connect(user=user, password=password, host=PG_HOST, database=database,
                                application_name=application_name, timeout=10)
    conn.autocommit = True
    return conn


def mysql(user="app", password="app-senha-forte", database="loja", host=None):
    return pymysql.connect(user=user, password=password, host=host or MYSQL_HOST, database=database,
                           ssl=_TLS, autocommit=True, connect_timeout=10)


def mariadb(user="app", password="app-senha-forte", database="loja"):
    # MariaDB usa mysql_native_password por padrão: não precisa de TLS.
    return pymysql.connect(user=user, password=password, host=MARIADB_HOST, database=database,
                           autocommit=True, connect_timeout=10)


ENGINES = {"postgresql": pg, "mysql": mysql, "mariadb": mariadb}


def run(engine, sql, user=None, password=None, database="loja", application_name=None, fetch=False):
    """Abre uma conexão, roda um comando (ou lista de comandos) e fecha.

    Devolve as linhas do último comando quando fetch=True. Erros de SQL são
    deixados subir (vários testes esperam o erro), mas a conexão é sempre fechada.
    """
    connect = ENGINES[engine]
    kwargs = {}
    if user is not None:
        kwargs["user"] = user
    if password is not None:
        kwargs["password"] = password
    if database is not None:
        kwargs["database"] = database
    if engine == "postgresql" and application_name:
        kwargs["application_name"] = application_name
    conn = connect(**kwargs)
    rows = None
    try:
        cur = conn.cursor()
        for statement in [sql] if isinstance(sql, str) else sql:
            cur.execute(statement)
            if fetch:
                try:
                    rows = cur.fetchall()
                except Exception:  # noqa: BLE001 - comando sem resultado
                    rows = None
    finally:
        conn.close()
    return rows


def try_login(engine, user, password, database="loja"):
    """Tenta conectar. Devolve True no sucesso, False quando o banco recusa."""
    try:
        conn = ENGINES[engine](user=user, password=password, database=database)
        conn.close()
        return True
    except Exception as exc:  # noqa: BLE001 - a falha é o resultado esperado
        log(f"    login recusado ({user}): {type(exc).__name__}")
        return False


# ---------------------------------------------------------------------------
# API do Reefed e receptor falso

def _request(method, url, body=None, headers=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {detail[:300]}") from None


def reefed(method, path, body=None):
    return _request(method, REEFED_API + path, body=body, headers={"X-API-Key": REEFED_API_KEY})


def send_event(**event):
    return reefed("POST", "/api/v1/events", body={k: v for k, v in event.items() if v is not None})


def mock_messages():
    return _request("GET", MOCK_URL + "/messages")


def mock_clear():
    return _request("DELETE", MOCK_URL + "/messages")


def wait_for(description, predicate, timeout=90, interval=3):
    """Espera uma condição ficar verdadeira (os alertas levam ~15 s para indexar)."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    log(f"    TEMPO ESGOTADO esperando: {description}")
    return last if last else None


if __name__ == "__main__":
    # Teste rápido de conectividade: python common.py postgresql|mysql|mariadb
    engine = sys.argv[1] if len(sys.argv) > 1 else "postgresql"
    rows = run(engine, "SELECT 1", fetch=True)
    log(f"{engine}: {rows}")
