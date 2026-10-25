# API do Reefed

A API do Reefed é a porta de entrada do seu sistema: consulta alertas, bloqueios e o
estado do SIEM, e recebe eventos da aplicação (login, exportação, troca de perfil). O
indexer e a API do Wazuh continuam fechados na própria máquina; o seu sistema só
conversa com esta API.

- Endereço: `http://IP_DO_REEFED:8000` (porta `REEFED_API_PORT`, interface `REEFED_API_BIND`)
- Documentação interativa: `http://IP_DO_REEFED:8000/docs`, onde dá para testar cada
  chamada no navegador (botão **Authorize** com a chave). O esquema OpenAPI fica em
  `/openapi.json`, útil para gerar clientes.
- Formato: JSON em UTF-8. Todos os caminhos, menos o `/health`, começam com `/api/v1`.

O passo a passo para ligar o seu sistema, com exemplos em Python, JavaScript, Java e PHP,
está em [integracao.md](integracao.md).

## Autenticação

Toda chamada, menos o `/health`, leva a chave no cabeçalho `X-API-Key`:

```bash
curl -H "X-API-Key: $REEFED_API_KEY" http://localhost:8000/api/v1/status
```

| Chave (`.env`) | Pode |
|---|---|
| `REEFED_API_KEY` | consultar e enviar eventos |
| `REEFED_API_READ_KEY` | só consultar (um `POST /api/v1/events` com ela recebe 403) |

Use a chave de leitura em quem só mostra alertas (um painel, um relatório) e a completa
só no servidor que envia eventos. A completa é gerada pelo `setup.sh`. A de leitura é
opcional: gere uma com `openssl rand -hex 24`, coloque em `REEFED_API_READ_KEY` no `.env`
e rode `make up`. Para trocar as chaves, veja [operacao.md](operacao.md#trocar-senhas).

## Resumo

| Método e caminho | Para quê |
|---|---|
| `GET /health` | a API, o indexer e a API do Wazuh respondem? (sem chave) |
| `GET /api/v1/status` | situação do manager, dos agentes e dos alertas das últimas 24 h |
| `GET /api/v1/alerts` | lista de alertas com filtros, mais novos primeiro |
| `GET /api/v1/alerts/summary` | contagens por severidade e os mais frequentes (regras, IPs, usuários, servidores, MITRE) |
| `GET /api/v1/alerts/{id}` | um alerta, com o documento completo do Wazuh |
| `GET /api/v1/blocked` | IPs bloqueados pelo Active Response, agora e no histórico |
| `GET /api/v1/agents` | agentes registrados e o estado de cada um |
| `GET /api/v1/rules` | catálogo das regras do Reefed, com MITRE |
| `POST /api/v1/events` | envia eventos da aplicação |

## Períodos

Os parâmetros `since` e `until` aceitam um tempo relativo, contado para trás a partir de
agora (`30s`, `15m`, `24h`, `7d`, `2w`), ou uma data ISO 8601 (`2026-10-22T08:00:00-03:00`).
Uma data sem fuso é lida como UTC.

## GET /health

Sem chave. Serve para um monitor de disponibilidade saber se o Reefed está no ar.

```json
{"status": "ok", "indexer": true, "wazuh_api": true, "version": "1.0.0"}
```

`status` vira `degraded` se o indexer ou a API do Wazuh não responder.

## GET /api/v1/status

```json
{
  "status": "ok",
  "checked_at": "2026-10-22T19:32:15.867Z",
  "manager": {
    "version": "v4.14.9",
    "timezone": "-0300",
    "daemons": {"wazuh-analysisd": "running", "wazuh-remoted": "running", "...": "..."},
    "stopped": [],
    "alert_channels": ["telegram", "slack", "email"]
  },
  "agents": {
    "connection": {"active": 3, "disconnected": 0, "never_connected": 0, "pending": 0, "total": 3},
    "configuration": {"synced": 3, "not_synced": 0, "total": 3}
  },
  "alerts_24h": {"total": 161, "by_severity": {"baixo": 49, "medio": 13, "alto": 59, "critico": 40}}
}
```

`status` é `degraded` quando algum serviço importante do manager está parado; os nomes
ficam em `manager.stopped`. `alert_channels` diz quais canais de alerta estão ligados.

## GET /api/v1/alerts

| Parâmetro | Padrão | O que faz |
|---|---|---|
| `since` | `24h` | início do período |
| `until` | agora | fim do período |
| `min_level` | `3` | nível mínimo (0 a 16) |
| `max_level` | | nível máximo |
| `severity` | | `baixo`, `medio`, `alto` ou `critico` (substitui `min_level` e `max_level`) |
| `rule_id` | | uma regra; pode repetir: `rule_id=110200&rule_id=110201` |
| `group` | | grupo de regra (`reefed_sqli`, `reefed_bruteforce`, `reefed_app`...); pode repetir |
| `agent` | | nome ou id do agente (`lab-postgres` ou `002`) |
| `srcip` | | IP de origem |
| `user` | | usuário do banco ou do sistema |
| `mitre` | | técnica (`T1110`, `T1110.001`) ou tática (`Credential Access`) |
| `q` | | texto na descrição ou no log (até 200 caracteres) |
| `all_rules` | `false` | `true` inclui os alertas das regras do próprio Wazuh (SSH, Windows, FIM do sistema...) |
| `limit` | `50` | itens por página (1 a 500) |
| `offset` | `0` | pula os N primeiros (até 10000) |

Sem `all_rules`, só vêm os alertas das regras do Reefed. A severidade segue o nível:
`baixo` 0 a 6, `medio` 7 a 9, `alto` 10 e 11, `critico` 12 a 15.

```bash
# SQL injection na última semana
curl -H "X-API-Key: $REEFED_API_KEY" "http://localhost:8000/api/v1/alerts?since=7d&group=reefed_sqli"
# tudo que o IP 203.0.113.7 fez hoje, inclusive os alertas baixos
curl -H "X-API-Key: $REEFED_API_KEY" "http://localhost:8000/api/v1/alerts?since=24h&srcip=203.0.113.7&min_level=0"
```

Resposta (alerta do laboratório):

```json
{
  "total": 2,
  "offset": 0,
  "limit": 1,
  "items": [
    {
      "id": "1792695920.2823201",
      "timestamp": "2026-10-22T16:05:20.808-0300",
      "level": 12,
      "severity": "critico",
      "rule": {
        "id": "110302",
        "description": "Reefed: SQL injection com UNION SELECT vinda de 10.250.77.66, usuário app.",
        "groups": ["reefed", "database", "reefed_sqli", "attack"],
        "firedtimes": 1,
        "mitre": {"ids": ["T1190"], "tactics": ["Initial Access"], "techniques": ["Exploit Public-Facing Application"]}
      },
      "agent": {"id": "002", "name": "lab-postgres", "ip": "172.18.0.7"},
      "srcip": "10.250.77.66",
      "user": "app",
      "database": {
        "name": "loja",
        "client": "10.250.77.66",
        "app": "loja-app",
        "query": "SELECT nome FROM clientes WHERE id = -1 UNION SELECT table_name FROM information_schema.tables ",
        "operation": null
      },
      "app_event": null,
      "location": "/var/lib/postgresql/data/log/postgresql-2026-10-22.log",
      "full_log": "2026-10-22 19:05:19.575 UTC [78] user=app db=loja client=10.250.77.66 app=loja-app LOG:  statement: SELECT nome FROM clientes WHERE id = -1 UNION SELECT table_name FROM information_schema.tables ",
      "index": "wazuh-alerts-4.x-2026.10.22"
    }
  ]
}
```

### Campos de um alerta

| Campo | Conteúdo |
|---|---|
| `id` | id do alerta no Wazuh (use em `GET /api/v1/alerts/{id}`) |
| `timestamp` | hora do alerta, no fuso do manager (`REEFED_TZ`) |
| `level`, `severity` | nível de 0 a 15 e a severidade em texto |
| `rule` | id, descrição, grupos, quantas vezes a regra disparou desde o início do manager (`firedtimes`) e MITRE ATT&CK |
| `agent` | servidor que mandou o log (`000` é o próprio manager, onde chegam os eventos da API) |
| `srcip`, `user` | IP de origem e usuário (do banco ou do sistema) |
| `database` | banco, cliente, aplicação que conectou, comando SQL e tipo de operação, quando o alerta veio de um log de banco |
| `app_event` | o evento enviado pelo seu sistema, quando o alerta veio de `POST /api/v1/events` |
| `location` | arquivo de log de onde a linha veio |
| `full_log` | a linha de log original |
| `index` | índice do indexer onde o alerta está |

Campos sem valor vêm como `null`.

## GET /api/v1/alerts/summary

Parâmetros: `since` (padrão `24h`), `until`, `min_level` (padrão 3), `agent`,
`all_rules` e `top` (quantos itens em cada lista, 1 a 50, padrão 10).

```json
{
  "since": "24h",
  "total": 161,
  "by_severity": {"baixo": 49, "medio": 13, "alto": 59, "critico": 40},
  "top_rules": [{"id": "110210", "count": 52, "description": "Reefed: acesso ao banco a partir de IP desconhecido 10.250.77.66 (usuário app).", "level": 10}],
  "top_srcips": [{"ip": "10.250.77.66", "count": 149}],
  "top_users": [{"user": "app", "count": 120}],
  "top_agents": [{"agent": "lab-mysql", "count": 64}],
  "top_mitre": [{"id": "T1078", "count": 58, "technique": "Valid Accounts"}]
}
```

Bom para um quadro de "segurança do banco" na tela de administração do seu sistema.

## GET /api/v1/alerts/{id}

O alerta no mesmo formato da lista, mais `raw`, com o documento completo que o Wazuh
gravou (todos os campos decodificados, `previous_output` das regras de correlação,
`syscheck` dos alertas de FIM). Procura nos últimos 30 dias; para alertas mais antigos,
passe `since=90d`. Devolve 404 se não achar.

## GET /api/v1/blocked

IPs bloqueados pelo Active Response. Parâmetro: `since` (padrão `24h`), o período do
histórico. A resposta e o significado de cada campo estão em
[active-response.md](active-response.md#ver-o-que-está-bloqueado).

## GET /api/v1/agents

Parâmetros: `status` (`active`, `disconnected`, `never_connected` ou `pending`) e `group`
(`database`, `postgresql`, `windows`...). A lista inclui o próprio manager (agente `000`).

```json
{
  "total": 1,
  "items": [
    {
      "id": "002",
      "name": "lab-postgres",
      "ip": "172.18.0.7",
      "status": "active",
      "os": "Amazon Linux 2023",
      "version": "Wazuh v4.14.9",
      "groups": ["linux", "database", "postgresql"],
      "last_keepalive": "2026-10-22T19:33:47+00:00",
      "registered_at": "2026-10-22T19:04:33+00:00"
    }
  ]
}
```

## GET /api/v1/rules

As regras do Reefed com nível, descrição, grupos, técnicas MITRE e o arquivo:

```json
{"id": "110006", "level": 5, "description": "Reefed: falha de login no PostgreSQL (usuário $(dstuser), origem $(db.client)).",
 "groups": ["authentication_failed", "reefed_login_fail", "reefed", "database", "postgresql"],
 "mitre": ["T1110.001"], "file": "reefed-0100-postgresql_rules.xml"}
```

O catálogo explicado está em [regras.md](regras.md).

## POST /api/v1/events

O seu sistema avisa o Reefed do que acontece do lado da aplicação. Cada evento vira um
alerta, que entra nas mesmas correlações, painéis e notificações dos alertas do banco.

```bash
curl -X POST -H "X-API-Key: $REEFED_API_KEY" -H "Content-Type: application/json" \
  -d '{"app": "loja", "event": "data_export", "user": "ana", "srcip": "203.0.113.7", "records": 15000}' \
  http://localhost:8000/api/v1/events
```

Um evento por chamada, ou até 100 de uma vez em `{"events": [...]}`. Resposta (202):

```json
{"accepted": 1, "failed": 0, "errors": []}
```

### Campos

| Campo | Obrigatório | Regra |
|---|---|---|
| `app` | sim | nome do sistema: letras, números, `_`, `.` e `-`, até 64 |
| `event` | sim | tipo do evento (tabela abaixo): minúsculas, números, `_`, `.` e `-`, até 64 |
| `user` | | usuário do sistema, até 128 caracteres |
| `srcip` | | IP de quem fez a ação (IPv4 ou IPv6). Sem ele, as regras que contam por IP não funcionam |
| `message` | | texto livre, até 2000 caracteres |
| `records` | | quantidade de registros (`data_export`, `bulk_delete`) |
| `role` | | perfil novo (`permission_change`), até 64 |
| `severity` | | `low`, `medium`, `high` ou `critical`, para eventos fora da tabela |
| `request_id` | | id da requisição no seu sistema, até 128, para achar o evento depois |
| `extra` | | até 20 campos simples (texto até 500 caracteres, número, booleano) |

Qualquer outro campo é recusado (422), assim como um `srcip` que não seja IP.

### Eventos e alertas

| `event` | Regra e nível | Sobe para |
|---|---|---|
| `login_success` | 110151, nível 3 | |
| `login_failed` | 110152, nível 5 | 110153, nível 10: 6 falhas do mesmo `srcip` em 2 minutos |
| `access_denied` | 110154, nível 5 | 110155, nível 10: 8 do mesmo `user` em 5 minutos |
| `permission_change` | 110156, nível 8 | 110157, nível 11: `role` com admin, root, super, dba, gerente ou owner |
| `user_created` | 110158, nível 5 | |
| `data_export` | 110159, nível 3 | 110160, nível 8, com `records` a partir de 1000; 110161, nível 11, a partir de 10000 |
| `bulk_delete` | 110162, nível 7 | 110163, nível 11, com `records` a partir de 100 |
| `sql_injection_blocked` | 110164, nível 12 | |
| `config_change` | 110165, nível 7 | |
| qualquer outro nome | 110170 a 110173 | nível 12, 10, 7 ou 3 conforme `severity` `critical`, `high`, `medium` ou `low` (padrão `low`) |

Os eventos chegam ao Wazuh como agente `000` (o manager), com `location` igual a
`API-Webhook`.

## Erros

| Código | Quando | Corpo |
|---|---|---|
| 401 | sem chave ou chave errada | `{"detail": "envie a chave no cabeçalho X-API-Key"}` ou `{"detail": "chave inválida"}` |
| 403 | `POST /api/v1/events` com a chave de leitura | `{"detail": "esta chave só pode consultar"}` |
| 404 | alerta não encontrado | `{"detail": "alerta não encontrado"}` |
| 422 | parâmetro ou evento inválido | `{"detail": "data inválida: ..."}` ou a lista de erros de validação |
| 502 | o indexer ou a API do Wazuh não respondeu | `{"detail": "... indisponível: ..."}` |

Um 422 de validação traz cada problema em `detail`, com o campo em `loc` (`evento` para
um evento sozinho, `lote` para `{"events": [...]}`):

```json
{"detail": [{"type": "string_pattern_mismatch", "loc": ["body", "evento", "app"], "msg": "String should match pattern '^[A-Za-z0-9_.-]+$'", "input": "minha loja", "ctx": {"pattern": "^[A-Za-z0-9_.-]+$"}}]}
```

## HTTPS, rede e navegador

A API fala HTTP. Numa rede de laboratório isso basta. Em qualquer outro lugar, a chave
iria aberta pela rede: coloque um proxy com HTTPS na frente e deixe a API escutando só
na própria máquina.

```bash
# .env
REEFED_API_BIND=127.0.0.1
```

Com o [Caddy](https://caddyserver.com/), que pede o certificado sozinho quando o servidor
tem um nome público:

```
reefed.exemplo.com {
    reverse_proxy 127.0.0.1:8000
}
```

Com o nginx:

```nginx
server {
    listen 8443 ssl;
    server_name reefed.exemplo.com;
    ssl_certificate     /etc/ssl/reefed/fullchain.pem;
    ssl_certificate_key /etc/ssl/reefed/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Se o seu sistema roda no mesmo servidor do Reefed, `REEFED_API_BIND=127.0.0.1` sozinho
já resolve. Se a API ficar aberta em `0.0.0.0`, libere a porta 8000 no firewall só para o
servidor do seu sistema.

**Do navegador:** chame a API pelo backend do seu sistema, não pelo JavaScript da página:
a chave ficaria visível para qualquer usuário. Se for mesmo preciso (um painel interno),
use só a chave de leitura e libere a origem do site:

```bash
REEFED_CORS_ORIGINS=https://admin.minhaloja.com
```

## Cliente Python e linha de comando

`api/client/reefed_client.py` usa só a biblioteca padrão do Python. Copie para o seu
projeto:

```python
from reefed_client import ReefedClient, ReefedError

reefed = ReefedClient("http://IP_DO_REEFED:8000", api_key="...")
reefed.send_event("loja", "login_failed", user="ana", srcip="203.0.113.7", message="senha incorreta")
graves = reefed.alerts(since="1h", severity="critico")
print(reefed.summary(since="7d")["by_severity"])
```

Métodos: `health`, `status`, `alerts`, `alert`, `summary`, `blocked`, `agents`, `rules`,
`send_event` e `send_events`. Erros da API viram `ReefedError`, com `status` e `detail`.

Na linha de comando:

```bash
export REEFED_URL=http://localhost:8000 REEFED_API_KEY=...
python api/client/reefed_client.py status
python api/client/reefed_client.py alerts --since 2h --min-level 10
python api/client/reefed_client.py event loja login_failed --user ana --srcip 203.0.113.7
```

`make api-test` faz o mesmo de dentro do container, com a chave do `.env`.
