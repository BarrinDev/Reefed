"""Caminhos que as regras de integridade (FIM) do Reefed reconhecem.

Os alertas do FIM não passam pelo wazuh-logtest, então as expressões das regras
110800-110805 são conferidas aqui com caminhos reais do Linux e do Windows. As
expressões são PCRE2 simples, que o módulo re do Python lê do mesmo jeito.
"""

import os
import re
import xml.etree.ElementTree as ET

import pytest

RULES = os.path.join(os.path.dirname(__file__), "..", "..", "wazuh", "rules", "reefed-0800-fim_rules.xml")


def _patterns():
    with open(RULES, encoding="utf-8") as handle:
        root = ET.fromstring(f"<r>{handle.read()}</r>")
    return {rule.get("id"): re.compile(rule.find("field").text) for rule in root.iter("rule")}


PATTERNS = _patterns()

CASES = [
    # 110800: autenticação do PostgreSQL
    ("110800", "/etc/postgresql/17/main/pg_hba.conf", True),
    ("110800", "c:\\program files\\postgresql\\17\\data\\pg_hba.conf", True),
    ("110800", "/var/lib/pgsql/17/data/pg_ident.conf", True),
    ("110800", "/etc/postgresql/17/main/pg_hba.conf.bak", False),
    # 110801: configuração do banco
    ("110801", "/etc/postgresql/17/main/postgresql.conf", True),
    ("110801", "/etc/postgresql/17/main/conf.d/reefed.conf", True),
    ("110801", "/var/lib/pgsql/17/data/postgresql.auto.conf", True),
    ("110801", "/var/lib/pgsql/17/data/reefed.conf", True),
    ("110801", "c:\\program files\\postgresql\\17\\data\\reefed.conf", True),
    ("110801", "/etc/mysql/mysql.conf.d/mysqld.cnf", True),
    ("110801", "/etc/my.cnf.d/server.cnf", True),
    ("110801", "/etc/mysql/mariadb.conf.d/90-reefed.cnf", True),
    ("110801", "C:\\ProgramData\\MySQL\\MySQL Server 8.4\\my.ini", True),
    ("110801", "/var/lib/pgsql/17/data/base/1/1259", False),
    # 110802: bibliotecas e plugins
    ("110802", "/usr/lib/mysql/plugin/udf_evil.so", True),
    ("110802", "/usr/lib/postgresql/17/lib/evil.so", True),
    ("110802", "/usr/share/postgresql/17/extension/evil.control", True),
    ("110802", "/usr/pgsql-17/lib/evil.so", True),
    ("110802", "C:\\Program Files\\MySQL\\MySQL Server 8.4\\lib\\plugin\\evil.dll", True),
    ("110802", "c:\\program files\\postgresql\\17\\lib\\evil.dll", True),
    ("110802", "c:\\program files\\postgresql\\17\\share\\extension\\evil.control", True),
    ("110802", "C:\\Program Files\\MariaDB 11.4\\lib\\plugin\\evil.dll", True),
    ("110802", "/usr/lib/x86_64-linux-gnu/libc.so.6", False),
    # 110803: chaves e certificados TLS
    ("110803", "/var/lib/mysql/server-key.pem", True),
    ("110803", "/var/lib/pgsql/17/data/server.key", True),
    ("110803", "C:\\ProgramData\\MySQL\\MySQL Server 8.4\\Data\\private_key.pem", True),
    # 110804: configuração ou log apagado
    ("110804", "/var/log/postgresql/postgresql-17-main.log", True),
    ("110804", "/var/lib/pgsql/17/data/log/postgresql-Thu.log", True),
    ("110804", "/var/log/mysql/slow.log", True),
    ("110804", "/var/log/mysqld.log", True),
    ("110804", "/etc/mysql/my.cnf", True),
    ("110804", "/var/lib/pgsql/17/data/reefed.conf", True),
    ("110804", "c:\\program files\\postgresql\\17\\data\\log\\postgresql-2026-10-22_000000.log", True),
    ("110804", "c:\\program files\\postgresql\\17\\data\\pg_hba.conf", True),
    ("110804", "C:\\ProgramData\\MySQL\\MySQL Server 8.4\\Data\\DBSRV01.err", True),
    ("110804", "C:\\ProgramData\\MySQL\\MySQL Server 8.4\\Data\\DBSRV01-slow.log", True),
    ("110804", "c:\\program files\\mariadb 11.4\\data\\server_audit.log", True),
    ("110804", "/var/log/postgresql/postgresql-17-main.log.1", False),
    ("110804", "/var/log/mysql/slow.log.2.gz", False),
    ("110804", "C:\\ProgramData\\MySQL\\MySQL Installer for Windows\\Logs\\setup.log", False),
    ("110804", "C:\\ProgramData\\MySQL\\MySQL Server 8.4\\Data\\ibdata1", False),
    ("110804", "C:\\Windows\\System32\\drivers\\etc\\hosts", False),
    # 110805: configuração do próprio agente
    ("110805", "/var/ossec/etc/ossec.conf", True),
    ("110805", "/var/ossec/etc/client.keys", True),
    ("110805", "c:\\program files (x86)\\ossec-agent\\ossec.conf", True),
    ("110805", "c:\\program files (x86)\\ossec-agent\\ossec.log", False),
]


@pytest.mark.parametrize("rule, path, expected", CASES)
def test_caminho(rule, path, expected):
    assert bool(PATTERNS[rule].search(path)) is expected


def test_todas_as_regras_de_fim_tem_casos():
    assert set(PATTERNS) == {rule for rule, _, _ in CASES}
