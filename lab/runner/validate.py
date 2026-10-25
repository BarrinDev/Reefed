"""Reefed lab - confere que os ataques viraram alertas no Reefed.

Consulta a API do Reefed (os alertas levam ~15 s para indexar), o endereço
bloqueado pelo Active Response e as mensagens que chegaram ao receptor falso.
Imprime uma tabela com cada verificação e termina com código 1 se algo falhou,
para servir de teste automatizado (make lab-validate).
"""

import collections
import os
import sys
import time
import urllib.parse

import common

ATACANTE = "10.250.77.66"

# Estas só disparam no primeiro ataque depois do "make lab-up": o ataque deixa o
# skip-grant-tables gravado e o log apagado, e uma segunda rodada não muda mais nada.
UMA_VEZ = ("skip-grant-tables detectado (110056)", "FIM: log do banco apagado (110804)")

# Cada verificação: (descrição, função que recebe o "estado" e devolve True/False).
VERIFICACOES = [
    ("Força bruta detectada (110200)",
     lambda e: "110200" in e["rules"]),
    (f"IP do atacante ({ATACANTE}) bloqueado pelo Active Response",
     lambda e: ATACANTE in e["blocked"] or "110260" in e["rules"]),
    ("Acesso de IP desconhecido (110210/110211)",
     lambda e: e["rules"] & {"110210", "110211"}),
    ("SQL injection (grupo reefed_sqli)",
     lambda e: "reefed_sqli" in e["groups"]),
    ("Comando destrutivo por usuário comum (110420-110423, ou correlação 110950/110953)",
     lambda e: e["rules"] & {"110420", "110421", "110422", "110423", "110950", "110953"}),
    ("Criação de usuário/privilégio por usuário comum (110520/110521, ou correlação 110952)",
     lambda e: e["rules"] & {"110520", "110521", "110952"}),
    ("Leitura de hashes de senha (110715/110716)",
     lambda e: e["rules"] & {"110715", "110716"}),
    ("Exfiltração: dump/leitura em massa ou correlação (110603/110604/110610/110611/110612/110951)",
     lambda e: e["rules"] & {"110603", "110604", "110610", "110611", "110612", "110951"}),
    ("FIM: backdoor no pg_hba.conf (110800)",
     lambda e: "110800" in e["rules"]),
    (UMA_VEZ[0],
     lambda e: "110056" in e["rules"]),
    (UMA_VEZ[1],
     lambda e: "110804" in e["rules"]),
    ("Evento da aplicação pela API (exportação 110159/110160)",
     lambda e: e["rules"] & {"110159", "110160", "110161"}),
    ("Alerta enviado ao Telegram (mock)",
     lambda e: "telegram" in e["canais"]),
    ("Alerta enviado ao Slack (mock)",
     lambda e: "slack" in e["canais"]),
    ("Alerta enviado por e-mail (mock)",
     lambda e: "email" in e["canais"]),
]


def coleta_estado(since="40m"):
    """Junta regras vistas, grupos, IPs bloqueados e canais que receberam alerta."""
    estado = {"rules": set(), "groups": set(), "blocked": set(), "canais": set(),
              "mensagens": collections.Counter(), "alertas_10": 0}
    since = urllib.parse.quote(since)
    try:
        alertas = common.reefed("GET", f"/api/v1/alerts?since={since}&min_level=1&limit=500")
        for item in alertas.get("items", []):
            estado["rules"].add(str(item.get("rule", {}).get("id")))
            estado["groups"].update(item.get("rule", {}).get("groups", []))
            estado["alertas_10"] += int(item.get("level") or 0) >= 10
    except Exception as exc:  # noqa: BLE001
        common.log(f"  (aviso) não consegui ler alertas: {exc}")
    try:
        bloqueados = common.reefed("GET", f"/api/v1/blocked?since={since}")
        estado["blocked"].update(item.get("srcip") for item in bloqueados.get("active", []))
    except Exception as exc:  # noqa: BLE001
        common.log(f"  (aviso) não consegui ler /blocked: {exc}")
    try:
        for msg in common.mock_messages():
            estado["canais"].add(msg.get("channel"))
            estado["mensagens"][msg.get("channel")] += 1
    except Exception as exc:  # noqa: BLE001
        common.log(f"  (aviso) não consegui ler o mock: {exc}")
    return estado


def main():
    timeout = int(sys.argv[1]) if len(sys.argv) > 1 else 240
    # Início da rodada (o "make lab-attack" grava a hora em que começou); sem ele,
    # olha os últimos 40 minutos.
    since = os.environ.get("REEFED_LAB_SINCE", "").strip() or "40m"
    common.log(f"[validate] alertas desde {since}; aguardando indexarem (até {timeout}s)...\n")
    deadline = time.time() + timeout
    estado = {}
    faltando = list(VERIFICACOES)
    while time.time() < deadline and faltando:
        estado = coleta_estado(since)
        faltando = [v for v in VERIFICACOES if not v[1](estado)]
        feitos = len(VERIFICACOES) - len(faltando)
        common.log(f"  {feitos}/{len(VERIFICACOES)} verificações ok "
                   f"({len(estado['rules'])} regras vistas)        ", )
        if faltando:
            time.sleep(6)

    common.log("\n===== Resultado do laboratório Reefed =====")
    ok = 0
    for descricao, teste in VERIFICACOES:
        passou = bool(teste(estado))
        ok += passou
        common.log(f"  [{'OK ' if passou else 'XX '}] {descricao}")
    total = len(VERIFICACOES)
    if estado.get("mensagens"):
        canais = ", ".join(f"{canal} {n}" for canal, n in sorted(estado["mensagens"].items()))
        common.log(f"\nMensagens recebidas pelo receptor falso: {canais} "
                   f"(para {estado['alertas_10']} alertas de nível 10 ou mais; os repetidos são agrupados)")
    common.log(f"\n{ok}/{total} verificações passaram.")
    if ok < total:
        regras = ", ".join(sorted(estado.get("rules", []))) or "nenhuma"
        common.log(f"Regras que chegaram a indexar: {regras}")
        if {descricao for descricao, teste in VERIFICACOES if not teste(estado)} <= set(UMA_VEZ):
            common.log("As que falharam só disparam no primeiro ataque depois de subir o laboratório. "
                       "Para recomeçar do zero: make lab-down && make lab-up && make lab-attack (ou make lab).")
        sys.exit(1)
    common.log("Laboratório validado: ataques viram alertas, bloqueio e notificações.")


if __name__ == "__main__":
    main()
