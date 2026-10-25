# Laboratório de ataques

O laboratório prova que o Reefed funciona de ponta a ponta: sobe três bancos com agentes,
gera o tráfego normal de uma aplicação, ataca os três bancos de um IP desconhecido e
confere se cada ataque virou alerta, se o IP foi bloqueado e se as notificações saíram.

```bash
make lab
```

Leva uns 10 minutos na primeira vez (imagens dos bancos e do agente) e uns 5 nas
seguintes. Termina com a tabela de conferência e sai com erro se algum item falhar, então
também serve de teste automatizado (o CI do GitHub roda o mesmo, sob demanda).

Precisa do Reefed configurado (`./setup.sh`) e de uns 2 GB de RAM livres além do que o
Reefed já usa.

## O que sobe

Tudo numa rede própria, `10.250.77.0/24`, ao lado do Reefed:

| Serviço | Endereço | O que é |
|---|---|---|
| `postgres` | 10.250.77.10 | PostgreSQL 17 com o log no formato do Reefed |
| `mysql` | 10.250.77.11 | MySQL 8.4 com `agents/database/mysql/reefed.cnf` |
| `mariadb` | 10.250.77.12 | MariaDB 11.4 com o `server_audit` de `agents/database/mariadb/reefed.cnf` |
| `pg-agent`, `my-agent`, `maria-agent` | | um agente do Wazuh para cada banco (`lab-postgres`, `lab-mysql`, `lab-mariadb`), lendo os logs e a configuração do banco pelos volumes |
| `mock-alerts` | | receptor falso de Telegram, Slack e SMTP: guarda as mensagens em vez de enviá-las |
| `app` | 10.250.77.20 | a aplicação normal (IP confiável) |
| `attacker` | 10.250.77.66 | o atacante (IP fora da lista de confiáveis) |
| `validator` | | a conferência no fim |

Enquanto o laboratório está no ar, o Reefed roda no **modo laboratório**
(`lab/manager.override.yml`): os alertas vão para o receptor falso, nunca para os canais
do seu `.env`; o bloqueio do Active Response dura 2 minutos; repetidos são agrupados por 1
minuto; e as listas de `lab/lists/` substituem as do repositório (só o `app` é confiável).
`make lab-down` volta tudo ao normal.

## O que acontece

1. **Tráfego normal** (`lab/runner/app.py`, do IP 10.250.77.20): logins certos,
   consultas, inserções e eventos da aplicação pela API do Reefed (login, exportação,
   troca de configuração). Mostra que o dia a dia não vira alerta grave.
2. **Ataques** (`lab/runner/attack.py`, do IP 10.250.77.66), em cada um dos três bancos:

   | Ataque | Regras esperadas |
   |---|---|
   | força bruta: 6 senhas erradas para o mesmo usuário | 110200 e o bloqueio 110260 |
   | password spraying: a mesma senha em 6 usuários | 110201 |
   | 5 falhas e um acerto | 110203 e acesso de IP desconhecido 110210 |
   | SQL injection: `OR '1'='1'`, `UNION SELECT` e comando empilhado (`; DROP TABLE ...--`) | 110300 a 110302 |
   | `DROP TABLE` e `TRUNCATE` pelo usuário da aplicação | 110421 e 110422 |
   | criação de usuário e `GRANT` de administrador | 110520 e 110521 |
   | leitura das tabelas de senha (`pg_authid`, `mysql.user`) | 110715 e 110716 |
   | exfiltração: dump e leitura em massa | 110603, 110610 e 110611 |

   E mais três que mexem nos arquivos dos bancos:

   | Ataque | Regras esperadas |
   |---|---|
   | linha `trust` no `pg_hba.conf` (backdoor de autenticação) | 110800 (FIM) |
   | `skip-grant-tables` gravado na configuração do MySQL | 110801 (FIM) e 110056 |
   | `error.log` do MySQL apagado (apagar rastros) | 110804 (FIM) |

   As regras de correlação (110950 a 110953) juntam vários passos do mesmo IP numa
   "cadeia de ataque".
3. **Conferência** (`lab/runner/validate.py`): consulta a API do Reefed e o receptor
   falso até tudo aparecer (no máximo 4 minutos) e imprime:

```
===== Resultado do laboratório Reefed =====
  [OK ] Força bruta detectada (110200)
  [OK ] IP do atacante (10.250.77.66) bloqueado pelo Active Response
  [OK ] Acesso de IP desconhecido (110210/110211)
  [OK ] SQL injection (grupo reefed_sqli)
  [OK ] Comando destrutivo por usuário comum (110420-110423, ou correlação 110950/110953)
  [OK ] Criação de usuário/privilégio por usuário comum (110520/110521, ou correlação 110952)
  [OK ] Leitura de hashes de senha (110715/110716)
  [OK ] Exfiltração: dump/leitura em massa ou correlação (110603/110604/110610/110611/110612/110951)
  [OK ] FIM: backdoor no pg_hba.conf (110800)
  [OK ] skip-grant-tables detectado (110056)
  [OK ] FIM: log do banco apagado (110804)
  [OK ] Evento da aplicação pela API (exportação 110159/110160)
  [OK ] Alerta enviado ao Telegram (mock)
  [OK ] Alerta enviado ao Slack (mock)
  [OK ] Alerta enviado por e-mail (mock)

Mensagens recebidas pelo receptor falso: email 27, slack 34, telegram 34 (para 97 alertas de nível 10 ou mais; os repetidos são agrupados)

15/15 verificações passaram.
Laboratório validado: ataques viram alertas, bloqueio e notificações.
```

## Passo a passo, em vez do make lab

Para mostrar o laboratório aos poucos (numa apresentação, por exemplo):

```bash
make lab-up         # sobe bancos, agentes e receptor falso; espera os agentes conectarem
make lab-attack     # tráfego normal e ataques
make lab-validate   # a conferência
make lab-down       # apaga o laboratório e volta o Reefed ao normal
```

Entre o `lab-attack` e o `lab-validate`, abra o painel **Reefed - Segurança do banco de
dados** no dashboard (`https://localhost`): os alertas vão aparecendo por severidade, por
tática e técnica MITRE ATT&CK, por IP de origem, nos IPs bloqueados e nos comandos SQL.

Para ver as mensagens que teriam ido para o Telegram, o Slack e o e-mail:

```bash
docker exec reefed-lab-mock-alerts-1 python -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/messages').read().decode())"
```

Para atacar só um banco (`postgresql`, `mysql` ou `mariadb`):

```bash
docker compose --project-directory lab -f lab/docker-compose.yml --env-file "$PWD/.env" \
  --profile attack run --rm --no-deps attacker attack.py postgresql
```

## Rodar de novo

`make lab` sempre recomeça do zero (apaga os bancos do laboratório e os agentes antigos).
O `make lab-attack` pode ser repetido no mesmo laboratório, mas o `skip-grant-tables` e o
log apagado só disparam no primeiro ataque: na segunda vez o arquivo já está alterado e o
log já não existe (o `make lab-attack` avisa). Para atacar do zero: `make lab-down && make
lab-up`.

## Diferenças para um servidor de verdade

- Os agentes rodam em containers ao lado dos bancos e leem os logs pelos volumes. Num
  servidor de verdade o agente roda no próprio servidor do banco
  ([docs/agentes.md](../docs/agentes.md)).
- O `iptables` dos agentes do laboratório só registra o comando: o laboratório confere que
  o Active Response mandou bloquear o IP certo, sem precisar de privilégios no Docker. Num
  servidor, o mesmo script do Wazuh bloqueia de verdade
  ([docs/active-response.md](../docs/active-response.md)).
- O atacante continua conseguindo conectar depois do bloqueio, por causa do item acima;
  por isso o bloqueio aparece repetido (`times_blocked`) em `GET /api/v1/blocked`.

## Problemas

| Sintoma | O que fazer |
|---|---|
| `tempo esgotado esperando: os 3 agentes do laboratório conectarem` | `make status` e `make logs S=wazuh.manager`; confira se a `REEFED_ENROLLMENT_PASSWORD` do `.env` é a que o manager usa (`make restart` depois de trocar) |
| uma verificação falha na primeira rodada | rode `make lab-validate` de novo: num computador lento, a indexação pode passar dos 4 minutos |
| só o `skip-grant-tables` ou o log apagado falham | o laboratório já tinha sido atacado; `make lab` recomeça do zero |
| depois do laboratório, os alertas não chegam no Telegram de verdade | o Reefed ficou no modo laboratório: `make lab-down` |
