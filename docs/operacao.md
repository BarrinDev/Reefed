# Operação

Como cuidar do Reefed no dia a dia. Rode tudo na pasta do repositório; `make` sozinho
lista os comandos. Sem o `make`, os comandos equivalentes estão no `Makefile` e em
`scripts/`.

## Ver se está tudo bem

```bash
make status
```

```
[reefed] Wazuh v4.14.9: manager, indexer e API no ar
[reefed] agentes: 3 ativo(s), 0 desconectado(s), 0 nunca conectado(s)
[reefed] alertas nas últimas 24 h: 1008 (crítico 230, alto 359, médio 61, baixo 358)
[reefed] notificações: Telegram, Slack, e-mail
```

O comando termina com erro se o manager, o indexer ou a API não responderem, ou se algum
processo importante do manager estiver parado (por exemplo, o `wazuh-integratord`, que
manda as notificações, quando há canal configurado).

Outros comandos úteis:

| Comando | Para quê |
|---|---|
| `make agents` | agentes registrados, IP e estado |
| `make logs S=wazuh.manager` | log de um container (`wazuh.indexer`, `wazuh.dashboard`, `reefed-api`, `reefed-init`) |
| `docker compose exec wazuh.manager tail -f /var/ossec/logs/ossec.log` | log do Wazuh no manager (erros de configuração, regras, agentes) |
| `docker compose exec wazuh.manager tail -f /var/ossec/logs/integrations.log` | envio para Telegram, Slack e e-mail |
| `docker compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.json` | alertas saindo do manager, um JSON por linha |
| `scripts/wazuh-api.sh GET '/agents?select=name,group,status'` | qualquer chamada da API do Wazuh (a porta 55000 só abre na própria máquina) |

## Mudar a configuração

Nada é editado dentro dos containers: muda-se o repositório ou o `.env` e aplica-se com um
destes comandos.

| O que mudou | Comando |
|---|---|
| Canais de alerta, níveis, horário comercial, Active Response ou syslog no `.env` | `make restart` |
| Senhas e chaves no `.env` | `make passwords` (veja [Trocar senhas](#trocar-senhas)) |
| Portas, `REEFED_API_BIND`, `REEFED_INDEXER_HEAP`, `REEFED_CORS_ORIGINS`, `REEFED_RETENTION_DAYS` | `make up` |
| Regras, decoders, listas, integrações ou `wazuh/shared/*/agent.conf` | `make deploy-rules` |
| Modelo do manager (`config/wazuh_manager/ossec.conf`) | `make restart` |
| Painéis (`dashboards/gerar_paineis.py`) | `python3 dashboards/gerar_paineis.py` e `make dashboards` |

O `make deploy-rules` copia o conteúdo do Reefed para o manager e reinicia os processos do
Wazuh lá dentro (uns 20 segundos; os agentes guardam os eventos e mandam quando o manager
volta). Os agentes recebem a configuração nova dos grupos em alguns minutos e reiniciam
sozinhos.

Antes de aplicar uma regra nova, confira o XML:

```bash
python3 tests/lint_xml.py     # XML de regras, decoders e configurações
make deploy-rules
make test-rules               # os 236 casos de teste, no manager que está rodando
```

Um erro de XML numa regra impede o Wazuh de iniciar. Se o manager não voltar depois do
`make deploy-rules`, o motivo está no fim do `ossec.log`:

```bash
docker compose exec wazuh.manager grep -E "ERROR|CRITICAL" /var/ossec/logs/ossec.log | tail -n 20
```

## Trocar senhas

1. Mude o valor no `.env`.
2. Rode `make passwords`.

Só mudar o `.env` não basta: o indexer guarda os usuários dele (`admin`, `kibanaserver` e
`reefed_api`) desde a primeira subida, e o dashboard grava a senha da API do Wazuh uma vez
só. O `make passwords` (`scripts/apply-passwords.sh`):

- refaz o `config/wazuh_indexer/internal_users.yml` com as senhas do `.env` e aplica no
  indexer;
- apaga a conexão com a API do Wazuh guardada pelo dashboard, que ele grava de novo com a
  senha nova;
- recria o manager, o dashboard e a API do Reefed com o `.env` novo. Ao iniciar, o manager
  troca a senha do usuário da API do Wazuh e a senha de registro de agentes.

Vale para qualquer combinação das seis (`INDEXER_PASSWORD`, `DASHBOARD_PASSWORD`,
`WAZUH_API_PASSWORD`, `REEFED_API_INDEXER_PASSWORD`, `REEFED_API_KEY` e
`REEFED_ENROLLMENT_PASSWORD`), e também para `REEFED_API_READ_KEY`. O Reefed fica uns dois
minutos fora do ar. O script confere os valores antes de mexer em qualquer coisa:

- a `WAZUH_API_PASSWORD` precisa de 8 ou mais caracteres, com maiúscula, minúscula, número
  e símbolo;
- as chaves da API do Reefed precisam de 16 ou mais caracteres;
- use letras, números e os símbolos `. _ - @ ! %`. O `$`, as aspas, o `#` e o espaço têm
  significado especial no `.env` e no YAML do dashboard.

Depois:

- `REEFED_API_KEY` ou `REEFED_API_READ_KEY`: atualize a chave no sistema que usa a API;
- `INDEXER_PASSWORD`: é o login do dashboard (usuário `admin`);
- `REEFED_ENROLLMENT_PASSWORD`: os agentes já registrados continuam funcionando; a senha
  nova só é pedida para registrar agentes novos.

## Backup e restauração

```bash
make backup                                       # vai para backups/AAAA-MM-DD_HHMMSS
scripts/restore.sh backups/2026-10-22_185606      # pergunta antes de apagar
```

O backup leva o `.env`, os certificados, o arquivo de usuários do indexer e todos os
volumes: alertas, agentes registrados (`client.keys`), configuração e usuários da API do
Wazuh, painéis e o estado do Filebeat. Para a cópia ficar consistente, o Reefed fica
parado enquanto os volumes são copiados (no laboratório, 25 segundos). Os agentes guardam
os eventos e mandam quando o manager volta.

O backup tem todas as senhas e as chaves privadas dos certificados. Os arquivos ficam só
com permissão do seu usuário, e a pasta `backups/` fica fora do git. Guarde uma cópia fora
do servidor.

A restauração apaga os dados atuais e põe os do backup no lugar, inclusive o `.env` e os
certificados daquele backup. Ela também serve para levar o Reefed para outra máquina:
clone o repositório, copie a pasta do backup e rode o `scripts/restore.sh` (sem o
`setup.sh`). Os agentes continuam registrados; se o endereço do servidor mudar, aponte os
agentes para o novo (veja [agentes.md](agentes.md)).

Testado assim: backup, `docker compose down -v` (apaga os volumes), `.env` e certificados
removidos, restauração. Os três agentes do laboratório voltaram sozinhos e os alertas
voltaram sem duplicar.

Para automatizar, um cron no servidor (todo dia às 3h, guardando 14 dias):

```cron
0 3 * * * cd /opt/reefed && scripts/backup.sh >> backups/backup.log 2>&1 && find backups -mindepth 1 -maxdepth 1 -type d -mtime +14 -exec rm -r {} +
```

## Espaço em disco e retenção

O que mais cresce é o indexer, com um índice de alertas por dia
(`wazuh-alerts-4.x-AAAA.MM.DD`). Para apagar os mais velhos, defina no `.env` quantos
dias guardar e rode `make up`:

```bash
REEFED_RETENTION_DAYS=180
```

O `reefed-init` cria uma política no indexer (Index State Management, `reefed-retencao`)
que apaga cada índice diário quando ele passa desse tempo, nos índices novos e nos que já
existem. `0` (o padrão) não apaga nada. Normas costumam pedir pelo menos um ano de
registros de acesso (o PCI DSS pede 12 meses, com 3 à mão), então combine a retenção com
backups.

O manager guarda também uma cópia dos alertas em arquivo, compactada por dia, em
`/var/ossec/logs/alerts/AAAA/Mês/`. Para apagar as de mais de 90 dias:

```bash
docker compose exec wazuh.manager find /var/ossec/logs/alerts /var/ossec/logs/archives -name '*.gz' -mtime +90 -delete
```

Os logs dos containers já têm limite (3 arquivos de 10 MB cada).

Se o disco do servidor passar de 95%, o indexer bloqueia a escrita para se proteger e os
alertas deixam de entrar (continuam no `alerts.json`). Libere espaço; o bloqueio sai
sozinho quando o uso volta para baixo de 90%.

## Atualizar o Wazuh

O Reefed foi testado com o Wazuh 4.14.9. Para outra versão da série 4.14:

1. `make backup`.
2. Mude `WAZUH_VERSION` no `.env`.
3. `docker compose pull` e `make up`.
4. `make test-rules`, para conferir que decoders e regras continuam funcionando com a
   versão nova.
5. Atualize os agentes depois do manager (um agente não pode ser mais novo que o manager):
   - Linux (Debian/Ubuntu): `sudo apt-get install --allow-change-held-packages wazuh-agent=VERSÃO-1`.
     O instalador do Reefed segura o pacote (`apt-mark hold`) para ele não ser
     atualizado antes do manager;
   - Linux (RHEL): `sudo dnf install --enablerepo=wazuh wazuh-agent-VERSÃO-1`;
   - Windows: rode o MSI da versão nova por cima
     (`msiexec /i wazuh-agent-VERSÃO-1.msi /qn`); o registro e a configuração ficam.

Para uma versão de outra série (4.15, 5.x), leia antes as notas de atualização do Wazuh
para Docker e rode o laboratório (`make lab`) antes de levar para produção. A versão
também aparece em `agents/linux/install-agent.sh`, `agents/windows/install-agent.ps1`,
`lab/agent/Dockerfile` e `.github/workflows/ci.yml`.

## Certificados

O `setup.sh` gera uma autoridade certificadora própria e os certificados do indexer, do
manager, do dashboard e do usuário administrativo do indexer, válidos por 10 anos. O
navegador avisa que não conhece quem assinou o certificado do dashboard; para tirar o
aviso, importe `config/wazuh_indexer_ssl_certs/root-ca.pem` como autoridade confiável no
navegador, ou ponha o dashboard atrás de um proxy com um certificado seu.

Para gerar todos de novo (chave vazada, por exemplo):

```bash
./setup.sh --force                       # novos certificados (as senhas do .env continuam)
docker compose up -d --force-recreate    # todos os containers passam a usar os novos
```

Os agentes não usam esses certificados e continuam conectados.

## Problemas comuns

**O indexer não sobe.** Veja `make logs S=wazuh.indexer`.

- `max virtual memory areas vm.max_map_count [65530] is too low`: rode
  `sudo sysctl -w vm.max_map_count=262144` e, para valer depois de reiniciar a máquina,
  `echo vm.max_map_count=262144 | sudo tee /etc/sysctl.d/99-reefed.conf`. No Docker
  Desktop com WSL 2: `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`.
- O container reinicia sozinho sem erro no log: falta memória. Feche outros programas,
  dê mais memória ao Docker Desktop ou diminua `REEFED_INDEXER_HEAP` (não abaixo de `512m`).

**O `make up` termina com "o Reefed não ficou pronto".** Na primeira vez o indexer leva
alguns minutos; rode `make status` de novo. Se continuar, a mensagem diz o que falta, por
exemplo "serviços do manager parados: wazuh-analysisd" (quase sempre um erro de XML numa
regra: veja o `ossec.log`).

**O agente não aparece ou fica "never connected".**

- Do servidor do agente, as portas precisam responder: `nc -zv IP_DO_REEFED 1514` e
  `nc -zv IP_DO_REEFED 1515` (no Windows: `Test-NetConnection IP_DO_REEFED -Port 1514`).
- A senha de registro tem de ser a `REEFED_ENROLLMENT_PASSWORD`.
- O agente não pode ser mais novo que o manager.
- O log do agente diz o motivo: `/var/ossec/logs/ossec.log` no Linux,
  `C:\Program Files (x86)\ossec-agent\ossec.log` no Windows.

**O agente está conectado, mas não chega alerta do banco.**

- Confira se o agente está no grupo do banco:
  `scripts/wazuh-api.sh GET '/agents?select=name,group'`.
- Confira a configuração de log do banco ([agentes.md](agentes.md)). No PostgreSQL o
  `log_line_prefix` precisa ser exatamente o do Reefed.
- O log do agente mostra os arquivos lidos (`Analyzing file: ...`).
- Teste uma linha do log do banco no manager: rode
  `docker compose exec wazuh.manager /var/ossec/bin/wazuh-logtest` e cole a linha. A
  saída mostra o decoder, os campos e a regra.

**O alerta aparece no dashboard, mas a notificação não chega.**

- `make status` mostra os canais ligados. Se faltar algum, confira as variáveis no `.env`
  e rode `make restart`.
- O nível da regra precisa ser igual ou maior que o do canal (`REEFED_TELEGRAM_LEVEL` e
  os outros).
- Alertas iguais viram uma mensagem por janela de `REEFED_ALERT_DEDUP_SECONDS`.
- Os erros de envio estão no `integrations.log` do manager. Veja [alertas.md](alertas.md).

**O dashboard diz que não alcança a API do Wazuh.** A senha guardada pelo dashboard ficou
diferente da `WAZUH_API_PASSWORD`; rode `make passwords`.

**Os alertas de horário saem na hora errada.** As regras de horário usam o relógio do
manager no fuso `REEFED_TZ` (padrão `America/Sao_Paulo`). Mude no `.env` e rode
`make restart`.
