"""Reefed lab - atividade normal da aplicação (roda a partir do IP confiável .20).

Faz o que um sistema de verdade faria: logins certos, consultas e inserções, e
alguns eventos da aplicação pela API do Reefed. Serve de linha de base, para
mostrar que o dia a dia não vira alerta e que os eventos da aplicação chegam.
"""

import random
import sys
import time

import common

ENGINES = ["postgresql", "mysql", "mariadb"]


def trafego_normal(engine):
    common.log(f"[app] {engine}: login e consultas normais")
    conn = common.ENGINES[engine]()
    try:
        cur = conn.cursor()
        for _ in range(5):
            cur.execute("SELECT id, nome, email FROM clientes WHERE id = %s"
                        if engine != "postgresql" else
                        "SELECT id, nome, email FROM clientes WHERE id = %s", (random.randint(1, 500),))
            cur.fetchall()
        total = round(random.uniform(10, 900), 2)
        if engine == "postgresql":
            cur.execute("INSERT INTO pedidos (cliente_id, total) VALUES (%s, %s)",
                        (random.randint(1, 500), total))
        else:
            cur.execute("INSERT INTO pedidos (cliente_id, total) VALUES (%s, %s)",
                        (random.randint(1, 500), total))
    finally:
        conn.close()


def eventos_da_aplicacao():
    """Eventos que o sistema manda pela API do Reefed (como faria em produção)."""
    common.log("[app] enviando eventos da aplicação pela API do Reefed")
    lote = [
        {"app": "loja", "event": "login_success", "user": "ana", "srcip": "203.0.113.10",
         "message": "login do painel"},
        {"app": "loja", "event": "login_success", "user": "bruno", "srcip": "203.0.113.11"},
        {"app": "loja", "event": "data_export", "user": "ana", "srcip": "203.0.113.10",
         "records": 42, "message": "relatório diário de vendas"},
        {"app": "loja", "event": "config_change", "user": "ana", "srcip": "203.0.113.10",
         "message": "limite de desconto alterado para 15%"},
    ]
    resultado = common.reefed("POST", "/api/v1/events", body={"events": lote})
    common.log(f"[app] eventos aceitos: {resultado}")


def main():
    engines = [sys.argv[1]] if len(sys.argv) > 1 and sys.argv[1] in ENGINES else ENGINES
    # Começa uma rodada nova: o validate.py só conta as mensagens que chegarem daqui em diante
    try:
        common.mock_clear()
    except Exception as exc:  # noqa: BLE001 - sem o mock, só a validação das notificações falha
        common.log(f"[app] não consegui limpar o receptor falso: {exc}")
    for engine in engines:
        for tentativa in range(30):
            try:
                trafego_normal(engine)
                break
            except Exception as exc:  # noqa: BLE001 - banco ainda subindo
                common.log(f"[app] {engine} ainda não respondeu ({type(exc).__name__}); tentativa {tentativa+1}")
                time.sleep(5)
        else:
            common.log(f"[app] desisti de {engine}")
    eventos_da_aplicacao()
    common.log("[app] pronto")


if __name__ == "__main__":
    main()
