# Regras do Reefed

As regras ficam em `wazuh/rules/` e os decoders em `wazuh/decoders/`. O manager
instala os dois a cada início (`config/wazuh_manager/entrypoint/10-reefed.sh`), então
basta editar no repositório e rodar `make deploy-rules`.

Todas as regras do Reefed usam IDs de 110000 a 119999 e o grupo `reefed`, o que facilita
filtrar no dashboard (`rule.groups:reefed`) e na API.

## Como ler o nível

| Nível | Severidade | O que significa | Notificação (padrão) |
|---|---|---|---|
| 0 | - | Regra base: só identifica o evento para as outras regras, não gera alerta | nenhuma |
| 1 a 6 | baixo | Atividade normal ou erro comum (login aceito, uma senha errada, configuração recarregada) | só no dashboard |
| 7 a 9 | médio | Suspeito, vale olhar (`DROP TABLE` ou `TRUNCATE` de um administrador, exportação grande, configuração do sistema alterada) | só no dashboard |
| 10 e 11 | alto | Ataque provável (força bruta, IP desconhecido, SQL injection por tempo) | Telegram e Slack |
| 12 a 15 | crítico | Ataque grave ou dano (DROP DATABASE, superusuário criado, backdoor no pg_hba.conf) | Telegram, Slack e e-mail |

Os limites das notificações mudam no `.env` (`REEFED_TELEGRAM_LEVEL`,
`REEFED_SLACK_LEVEL` e `REEFED_EMAIL_LEVEL`); veja [alertas.md](alertas.md). A API do
Reefed usa os mesmos nomes de severidade (`baixo`, `medio`, `alto`, `critico`).

## O que muda o nível de um alerta

Muitas regras têm duas versões: uma para quem tem motivo para fazer aquilo e outra,
mais alta, para quem não tem. Três coisas decidem:

- **Lista `db-admins`** (`wazuh/lists/db-admins`): usuários do banco que fazem
  manutenção. Um `DROP TABLE` do `postgres` é a regra 110401 (nível 8); o mesmo
  comando do usuário da aplicação é a 110421 (nível 12).
- **Lista `trusted-db-clients`** (`wazuh/lists/trusted-db-clients`): IPs que podem
  conectar no banco. Login de um IP fora da lista é a regra 110210 (nível 10), ou
  110211 (nível 12) se a conta for de administrador. Os IPs dessa lista também nunca
  são bloqueados pelo Active Response.
- **Horário comercial** (`REEFED_OFF_HOURS` e `REEFED_OFF_DAYS` no `.env`, padrão
  20:00 às 07:00 e fins de semana, no fuso `REEFED_TZ`): login, comando destrutivo,
  mudança de privilégio e exportação fora do horário viram as regras 110900 a 110908.

Coloque nas listas o servidor da aplicação, a máquina do DBA e o servidor de backup
antes de ligar o Reefed em produção, senão o primeiro dia gera muitos alertas de IP
desconhecido. O formato está em [wazuh/lists/README.md](../wazuh/lists/README.md).

## Mudar uma regra

- **Nível de uma regra**: edite o `level` no XML e rode `make deploy-rules`.
- **Desligar uma regra**: mude o nível para 0. Ela continua servindo de base para as
  regras que dependem dela.
- **Silenciar um caso conhecido** (por exemplo, o usuário `backup` que faz `pg_dump`
  a partir do servidor de backup e não é administrador, o que gera a regra 110612):
  crie uma regra filha de nível 0 num arquivo novo, como
  `wazuh/rules/reefed-0990-excecoes_rules.xml` (o nome precisa ter "reefed" e ordenar
  depois do arquivo da regra-mãe), e use IDs a partir de 111000:

  ```xml
  <group name="reefed,">
    <rule id="111000" level="0">
      <if_sid>110612</if_sid>
      <user>^backup$</user>
      <srcip>10.0.0.30</srcip>
      <description>Reefed: dump do servidor de backup (exceção conhecida).</description>
    </rule>
  </group>
  ```

  O IP do servidor de backup também precisa estar na `trusted-db-clients`; senão o
  alerta de IP desconhecido (110210) continua aparecendo, e isso é de propósito.

- **Regra nova**: use um ID livre da faixa do arquivo (cada arquivo tem a sua faixa,
  escrita no comentário do topo), escreva um caso de teste em `tests/rules/` e rode
  `make test-rules`.

## Testes das regras

`tests/rules/*.yml` tem 236 casos montados a partir de logs reais do PostgreSQL 17, do
MySQL 8.4 e do MariaDB 11.4. `make test-rules` manda cada log para o `wazuh-logtest`
do manager e confere decoder, regra, nível, campos e técnica MITRE, em todas as janelas
de horário. O formato dos casos está no começo de `tests/run_tests.py`. O CI roda os
mesmos testes num manager novo a cada push.

As regras de integridade de arquivos (110800 a 110805) não passam pelo logtest; os
caminhos que elas reconhecem, no Linux e no Windows, são conferidos em
`tests/fim/test_fim_paths.py` (`make test`) e no laboratório.

## Catálogo

Esta parte é gerada a partir dos XML por `python3 docs/gerar_regras.py`; o CI avisa se
ficar desatualizada. Os campos entre crases são preenchidos com os dados do evento.

<!-- REGRAS:INICIO (gerado por docs/gerar_regras.py; não edite à mão) -->

145 regras que geram alerta, em 14 arquivos (mais 18 regras de nível 0, que só agrupam eventos para as outras).

### Regras base do PostgreSQL

Arquivo: `wazuh/rules/reefed-0100-postgresql_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110005 | 3 (baixo) | Login no PostgreSQL (usuário `dstuser`, banco `db.name`, origem `db.client`). | T1078 |
| 110006 | 5 (baixo) | Falha de login no PostgreSQL (usuário `dstuser`, origem `db.client`). | T1110.001 |
| 110007 | 4 (baixo) | Conexão a um banco inexistente no PostgreSQL (`db.name`, origem `db.client`). | - |
| 110008 | 4 (baixo) | Permissão negada no PostgreSQL para `dstuser`: `db.message` | - |
| 110009 | 7 (médio) | Limite de conexões do PostgreSQL atingido (`db.message`). | T1499 |
| 110010 | 3 (baixo) | PostgreSQL iniciado e aceitando conexões. | - |
| 110011 | 7 (médio) | PostgreSQL recebeu um pedido de desligamento (`db.message`). | T1489 |
| 110012 | 10 (alto) | PostgreSQL entrou em PANIC: `db.message` | - |
| 110013 | 10 (alto) | Processo do PostgreSQL terminou de forma anormal: `db.message` | - |
| 110014 | 3 (baixo) | PostgreSQL recarregou os arquivos de configuração. | - |
| 110015 | 3 (baixo) | Parâmetro do PostgreSQL alterado: `db.message` | - |
| 110016 | 12 (crítico) | Configuração de log/auditoria do PostgreSQL alterada: `db.message` | T1562.001 |
| 110017 | 5 (baixo) | `dstuser` tentou conectar sem permissão no banco `db.name` do PostgreSQL (origem `db.client`). | - |

### Regras base do MySQL 8.x

Arquivo: `wazuh/rules/reefed-0110-mysql_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110051 | 5 (baixo) | Falha de login no MySQL (usuário `dstuser`, origem `db.client`). | T1110.001 |
| 110052 | 3 (baixo) | MySQL iniciado e aceitando conexões. | - |
| 110053 | 7 (médio) | MySQL recebeu um pedido de desligamento do usuário `dstuser`. | T1489 |
| 110054 | 3 (baixo) | MySQL desligado. | - |
| 110055 | 3 (baixo) | Erro registrado pelo MySQL: `db.message` | - |
| 110056 | 12 (crítico) | MySQL/MariaDB configurado para rodar sem verificação de senha (skip-grant-tables). | T1556 |
| 110058 | 3 (baixo) | skip-grant-tables não aparece mais na configuração do MySQL/MariaDB. | - |
| 110063 | 3 (baixo) | Log de consultas do MySQL (re)aberto (versão `db.version`). | - |
| 110073 | 4 (baixo) | Permissão negada no MySQL para `dstuser` (erro `db.errno`). | - |

### Regras base do MariaDB com o plugin server_audit

Arquivo: `wazuh/rules/reefed-0120-mariadb_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110103 | 3 (baixo) | Login no MariaDB (usuário `dstuser`, origem `db.client`). | T1078 |
| 110104 | 5 (baixo) | Falha de login no MariaDB (usuário `dstuser`, origem `db.client`, código `db.retcode`). | T1110.001 |
| 110105 | 5 (baixo) | `dstuser` tentou abrir um banco sem permissão no MariaDB (origem `db.client`). | - |
| 110106 | 3 (baixo) | Troca de usuário dentro de uma sessão do MariaDB (agora `dstuser`, origem `db.client`). | - |
| 110107 | 4 (baixo) | Permissão negada no MariaDB para `dstuser` (erro `db.retcode`). | - |

### Eventos enviados pela aplicação

Arquivo: `wazuh/rules/reefed-0150-aplicacao_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110151 | 3 (baixo) | Login no sistema `reefed.app` (usuário `dstuser`, origem `srcip`). | T1078 |
| 110152 | 5 (baixo) | Falha de login no sistema `reefed.app` (usuário `dstuser`, origem `srcip`). | T1110.001 |
| 110153 | 10 (alto) | Força bruta na tela de login do sistema `reefed.app` (origem `srcip`). | T1110 |
| 110154 | 5 (baixo) | Acesso negado no sistema `reefed.app` para `dstuser`: `reefed.message` | - |
| 110155 | 10 (alto) | `dstuser` teve muitos acessos negados no sistema `reefed.app` (possível escalada de privilégio). | T1068 |
| 110156 | 8 (médio) | Permissões de `dstuser` alteradas no sistema `reefed.app` (perfil `reefed.role`). | T1098 |
| 110157 | 11 (alto) | `dstuser` recebeu perfil administrativo (`reefed.role`) no sistema `reefed.app`. | T1098 |
| 110158 | 5 (baixo) | Usuário `dstuser` criado no sistema `reefed.app`. | T1136 |
| 110159 | 3 (baixo) | Exportação de dados no sistema `reefed.app` por `dstuser` (`reefed.records` registros). | T1213 |
| 110160 | 8 (médio) | Exportação grande no sistema `reefed.app` por `dstuser` (`reefed.records` registros). | T1213 |
| 110161 | 11 (alto) | Exportação em massa no sistema `reefed.app` por `dstuser` (`reefed.records` registros). | T1213, T1030 |
| 110162 | 7 (médio) | Exclusão em lote no sistema `reefed.app` por `dstuser` (`reefed.records` registros). | T1485 |
| 110163 | 11 (alto) | Exclusão em massa no sistema `reefed.app` por `dstuser` (`reefed.records` registros). | T1485 |
| 110164 | 12 (crítico) | A aplicação `reefed.app` bloqueou uma tentativa de SQL injection (origem `srcip`). | T1190 |
| 110165 | 7 (médio) | Configuração do sistema `reefed.app` alterada por `dstuser`: `reefed.message` | - |
| 110170 | 12 (crítico) | Evento crítico no sistema `reefed.app`: `reefed.event` `reefed.message` | - |
| 110171 | 10 (alto) | Evento de severidade alta no sistema `reefed.app`: `reefed.event` `reefed.message` | - |
| 110172 | 7 (médio) | Evento de severidade média no sistema `reefed.app`: `reefed.event` `reefed.message` | - |
| 110173 | 3 (baixo) | Evento `reefed.event` no sistema `reefed.app`: `reefed.message` | - |

### Autenticação e acesso ao banco

Arquivo: `wazuh/rules/reefed-0200-autenticacao_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110200 | 10 (alto) | Força bruta contra o banco a partir de `db.client` (5+ falhas de login em 2 min, último usuário `dstuser`). | T1110.001 |
| 110201 | 12 (crítico) | Password spraying contra o banco a partir de `db.client` (falhas de login em vários usuários). | T1110.003 |
| 110202 | 12 (crítico) | Força bruta distribuída contra o usuário `dstuser` do banco (falhas vindas de várias origens). | T1110 |
| 110203 | 13 (crítico) | Login aceito para `dstuser` a partir de `db.client` depois de várias falhas (senha possivelmente descoberta). | T1110, T1078 |
| 110210 | 10 (alto) | Acesso ao banco a partir de IP desconhecido `srcip` (usuário `dstuser`). | T1078 |
| 110211 | 12 (crítico) | Conta administrativa `dstuser` acessada a partir de IP desconhecido `srcip`. | T1078.001 |
| 110220 | 10 (alto) | `dstuser` teve muitos acessos negados no banco em 5 minutos (tentando acessar dados sem permissão). | T1213 |

### Firewall e Active Response

Arquivo: `wazuh/rules/reefed-0250-firewall_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110250 | 3 (baixo) | Firewall bloqueou conexão de `srcip` na porta do banco (`dstport`/`protocol`). | - |
| 110251 | 10 (alto) | `srcip` insistindo nas portas do banco (10 bloqueios do firewall em 2 min). | T1046 |
| 110252 | 3 (baixo) | Firewall bloqueou conexão de `srcip` na porta do banco (`dstport`/`protocol`). | - |
| 110260 | 8 (médio) | IP `parameters.alert.data.srcip` bloqueado no servidor de banco pelo Active Response (regra `parameters.alert.rule.id`). | - |
| 110261 | 3 (baixo) | Bloqueio do IP `parameters.alert.data.srcip` expirou (Active Response). | - |

### SQL injection vista de dentro do banco

Arquivo: `wazuh/rules/reefed-0300-sqli_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110300 | 14 (crítico) | SQL injection com comando empilhado (stacked query) vindo de `db.client`, usuário `dstuser`. | T1190, T1059 |
| 110301 | 12 (crítico) | SQL injection por tautologia (OR 1=1) vinda de `db.client`, usuário `dstuser`. | T1190 |
| 110302 | 12 (crítico) | SQL injection com UNION SELECT vinda de `db.client`, usuário `dstuser`. | T1190 |
| 110303 | 10 (alto) | Possível SQL injection por tempo (sleep/benchmark) vinda de `db.client`, usuário `dstuser`. | T1190 |
| 110304 | 10 (alto) | SQL injection baseada em erro vinda de `db.client`, usuário `dstuser`. | T1190 |
| 110305 | 10 (alto) | SQL injection com comentário cortando o comando vinda de `db.client`, usuário `dstuser`. | T1190 |
| 110306 | 8 (médio) | Comando SQL ofuscado (CHAR/hex/comentário de versão) vindo de `db.client`, usuário `dstuser`. | T1190, T1027 |
| 110310 | 2 (baixo) | Erro de SQL típico de sondagem no PostgreSQL (`db.message`). | - |
| 110311 | 2 (baixo) | Erro de SQL típico de sondagem no MySQL (erro `db.errno`). | - |
| 110312 | 2 (baixo) | Erro de SQL típico de sondagem no MariaDB (erro `db.retcode`). | - |
| 110315 | 10 (alto) | Muitos erros de SQL vindos de `db.client` em 2 minutos (possível sondagem de SQL injection). | T1190 |

### Comandos destrutivos e DDL

Arquivo: `wazuh/rules/reefed-0400-destrutivo_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110400 | 12 (crítico) | DROP DATABASE/SCHEMA enviado por `dstuser` (origem `db.client`). | T1485 |
| 110401 | 8 (médio) | DROP TABLE enviado por `dstuser` (origem `db.client`). | T1485 |
| 110402 | 8 (médio) | TRUNCATE enviado por `dstuser` (origem `db.client`). | T1485 |
| 110403 | 9 (médio) | DELETE sem WHERE (apaga a tabela inteira) enviado por `dstuser` (origem `db.client`). | T1485 |
| 110404 | 7 (médio) | UPDATE sem WHERE (altera a tabela inteira) enviado por `dstuser` (origem `db.client`). | T1565.001 |
| 110405 | 7 (médio) | ALTER TABLE removendo coluna/restrição enviado por `dstuser` (origem `db.client`). | T1485 |
| 110406 | 5 (baixo) | Objeto do banco removido por `dstuser` (origem `db.client`). | - |
| 110407 | 3 (baixo) | DDL (mudança de estrutura) enviado por `dstuser` (origem `db.client`). | - |
| 110420 | 14 (crítico) | DROP DATABASE/SCHEMA enviado por usuário que não é administrador (`dstuser`, origem `db.client`). | T1485 |
| 110421 | 12 (crítico) | DROP TABLE enviado por usuário que não é administrador (`dstuser`, origem `db.client`). | T1485 |
| 110422 | 12 (crítico) | TRUNCATE enviado por usuário que não é administrador (`dstuser`, origem `db.client`). | T1485 |
| 110423 | 12 (crítico) | DELETE sem WHERE enviado por usuário que não é administrador (`dstuser`, origem `db.client`). | T1485 |
| 110424 | 10 (alto) | UPDATE sem WHERE enviado por usuário que não é administrador (`dstuser`, origem `db.client`). | T1565.001 |
| 110425 | 10 (alto) | ALTER TABLE removendo coluna/restrição enviado por usuário que não é administrador (`dstuser`, origem `db.client`). | T1485 |
| 110426 | 8 (médio) | Objeto do banco removido por usuário que não é administrador (`dstuser`, origem `db.client`). | - |
| 110427 | 5 (baixo) | DDL enviado por usuário que não é administrador (`dstuser`, origem `db.client`). | - |

### Usuários e privilégios do banco

Arquivo: `wazuh/rules/reefed-0500-privilegios_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110500 | 8 (médio) | Usuário/role criado no banco por `dstuser` (origem `db.client`). | T1136 |
| 110501 | 12 (crítico) | Usuário com privilégio de superusuário criado/alterado por `dstuser` (origem `db.client`). | T1136, T1098 |
| 110502 | 10 (alto) | Usuário que aceita conexão de qualquer host ('%') criado por `dstuser` (origem `db.client`). | T1136 |
| 110503 | 12 (crítico) | Privilégio amplo concedido (GRANT ALL / WITH GRANT OPTION / SUPER / FILE) por `dstuser` (origem `db.client`). | T1098 |
| 110504 | 5 (baixo) | Permissão concedida (GRANT) por `dstuser` (origem `db.client`). | T1098 |
| 110505 | 5 (baixo) | Permissão revogada (REVOKE) por `dstuser` (origem `db.client`). | T1098 |
| 110506 | 6 (baixo) | Senha de usuário do banco alterada por `dstuser` (origem `db.client`). | T1098 |
| 110507 | 7 (médio) | Usuário/role removido do banco por `dstuser` (origem `db.client`). | T1531 |
| 110508 | 12 (crítico) | Tabela interna de usuários do banco alterada diretamente por `dstuser` (origem `db.client`). | T1098, T1556 |
| 110520 | 12 (crítico) | Usuário que não é administrador (`dstuser`, origem `db.client`) criou usuário ou concedeu permissão no banco. | T1098 |
| 110521 | 14 (crítico) | Usuário que não é administrador (`dstuser`, origem `db.client`) concedeu privilégio de administrador no banco (possível escalada de privilégio). | T1098, T1068 |

### Exportação e leitura em massa

Arquivo: `wazuh/rules/reefed-0600-exfiltracao_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110600 | 12 (crítico) | Dados gravados em arquivo no servidor (INTO OUTFILE/DUMPFILE) por `dstuser` (origem `db.client`). | T1005, T1074.001 |
| 110601 | 12 (crítico) | Dados gravados em arquivo no servidor (COPY TO/lo_export) por `dstuser` (origem `db.client`). | T1005, T1074.001 |
| 110602 | 7 (médio) | Exportação de tabela com COPY TO STDOUT por `dstuser` (origem `db.client`). | T1213 |
| 110603 | 7 (médio) | Consulta devolveu `db.rows_sent` linhas para `dstuser` (origem `db.client`). | T1213 |
| 110604 | 11 (alto) | Leitura em massa: consulta devolveu `db.rows_sent` linhas para `dstuser` (origem `db.client`). | T1213, T1030 |
| 110605 | 10 (alto) | `dstuser` leu muitas linhas em várias consultas em 5 minutos (origem `db.client`). | T1213, T1119 |
| 110606 | 2 (baixo) | Tabela lida por inteiro por `dstuser`. | - |
| 110607 | 10 (alto) | `dstuser` leu muitas tabelas inteiras em 2 minutos (origem `db.client`): possível cópia em massa. | T1213, T1119 |
| 110610 | 8 (médio) | Dump do PostgreSQL iniciado por `dstuser` no banco `db.name` (origem `db.client`). | T1213 |
| 110611 | 8 (médio) | Dump do MySQL/MariaDB (mysqldump) iniciado por `dstuser` (origem `db.client`). | T1213 |
| 110612 | 11 (alto) | Dump do banco feito por usuário que não é administrador (`dstuser`, origem `db.client`). | T1213 |

### Execução de comandos, leitura de arquivos, credenciais e adulteração

Arquivo: `wazuh/rules/reefed-0700-execucao_evasao_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110700 | 13 (crítico) | Comando do sistema operacional executado pelo banco (COPY PROGRAM) por `dstuser` (origem `db.client`). | T1059, T1059.004 |
| 110701 | 13 (crítico) | Função com código nativo/sem restrição criada no banco por `dstuser` (origem `db.client`). | T1505.001, T1059 |
| 110702 | 10 (alto) | Extensão perigosa instalada no PostgreSQL por `dstuser` (origem `db.client`). | T1505.001 |
| 110703 | 10 (alto) | Plugin/componente instalado no MySQL/MariaDB por `dstuser` (origem `db.client`). | T1505 |
| 110704 | 5 (baixo) | Trigger/evento agendado criado no banco por `dstuser` (origem `db.client`). | T1505.001 |
| 110705 | 9 (médio) | Trigger/evento agendado criado por usuário que não é administrador (`dstuser`, origem `db.client`). | T1505.001 |
| 110710 | 12 (crítico) | Arquivo do servidor lido pelo PostgreSQL a pedido de `dstuser` (origem `db.client`). | T1005, T1083 |
| 110711 | 12 (crítico) | Arquivo do servidor lido pelo MySQL/MariaDB a pedido de `dstuser` (origem `db.client`). | T1005 |
| 110715 | 10 (alto) | Leitura dos hashes de senha do banco por `dstuser` (origem `db.client`). | T1555 |
| 110716 | 12 (crítico) | Usuário que não é administrador (`dstuser`, origem `db.client`) leu hashes de senha do banco. | T1555 |
| 110717 | 5 (baixo) | `dstuser` listou usuários/permissões do banco (origem `db.client`). | T1087, T1069 |
| 110720 | 10 (alto) | Comando SHUTDOWN enviado ao banco por `dstuser` (origem `db.client`). | T1489 |
| 110721 | 6 (baixo) | Sessão de outro usuário encerrada por `dstuser` (origem `db.client`). | T1489 |
| 110730 | 12 (crítico) | Registro de auditoria do banco desligado/reduzido por `dstuser` (origem `db.client`). | T1562.001 |
| 110731 | 10 (alto) | Log binário do MySQL/MariaDB desligado ou apagado por `dstuser` (origem `db.client`). | T1070 |
| 110732 | 12 (crítico) | Tabela de log/auditoria apagada por `dstuser` (origem `db.client`). | T1070 |
| 110733 | 8 (médio) | Trigger/política de segurança removida ou desativada por `dstuser` (origem `db.client`). | T1562.001 |
| 110734 | 5 (baixo) | Configuração global do banco alterada via SQL por `dstuser` (origem `db.client`). | - |

### Integridade de arquivos do servidor de banco

Arquivo: `wazuh/rules/reefed-0800-fim_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110800 | 12 (crítico) | Arquivo de autenticação do PostgreSQL alterado: `file` | T1556 |
| 110801 | 10 (alto) | Configuração do banco alterada: `file` | T1562.001 |
| 110802 | 12 (crítico) | Biblioteca/extensão nova ou alterada no diretório de plugins do banco: `file` | T1505.001 |
| 110803 | 8 (médio) | Chave/certificado TLS do banco alterado: `file` | T1552.004 |
| 110804 | 12 (crítico) | Arquivo de configuração/log do banco apagado: `file` | T1070.004 |
| 110805 | 10 (alto) | Configuração do agente do Reefed/Wazuh alterada: `file` | T1562.001 |

### Atividade fora do horário comercial

Arquivo: `wazuh/rules/reefed-0900-horario_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110900 | 8 (médio) | Acesso ao banco fora do horário comercial (usuário `dstuser`, origem `db.client`). | T1078 |
| 110901 | 7 (médio) | Acesso ao banco em dia sem expediente (usuário `dstuser`, origem `db.client`). | T1078 |
| 110902 | 12 (crítico) | Acesso ao banco a partir de IP desconhecido `srcip` fora do horário comercial (usuário `dstuser`). | T1078 |
| 110903 | 13 (crítico) | Conta administrativa `dstuser` acessada a partir de IP desconhecido `srcip` fora do horário comercial. | T1078.001 |
| 110904 | 12 (crítico) | Comando destrutivo fora do horário comercial enviado por `dstuser` (origem `db.client`). | T1485 |
| 110905 | 14 (crítico) | DROP DATABASE/SCHEMA fora do horário comercial enviado por `dstuser` (origem `db.client`). | T1485 |
| 110906 | 11 (alto) | Usuários/permissões do banco alterados fora do horário comercial por `dstuser` (origem `db.client`). | T1098 |
| 110907 | 13 (crítico) | Privilégio de administrador concedido fora do horário comercial por `dstuser` (origem `db.client`). | T1098 |
| 110908 | 11 (alto) | Exportação/dump do banco fora do horário comercial por `dstuser` (origem `db.client`). | T1213 |

### Correlação de etapas de um ataque

Arquivo: `wazuh/rules/reefed-0950-correlacao_rules.xml`

| ID | Nível | Alerta | MITRE ATT&CK |
|---|---|---|---|
| 110950 | 14 (crítico) | SQL injection seguida de comando destrutivo a partir de `db.client` (usuário `dstuser`). | T1190, T1485 |
| 110951 | 14 (crítico) | SQL injection seguida de exportação de dados a partir de `db.client` (usuário `dstuser`). | T1190, T1213 |
| 110952 | 15 (crítico) | Força bruta seguida de mudança de usuários/privilégios a partir de `db.client` (usuário `dstuser`): provável invasão. | T1110, T1098 |
| 110953 | 15 (crítico) | Força bruta seguida de comando destrutivo a partir de `db.client` (usuário `dstuser`): provável invasão. | T1110, T1485 |
| 110954 | 14 (crítico) | Força bruta seguida de exportação de dados a partir de `db.client` (usuário `dstuser`): provável invasão. | T1110, T1213 |

### Cobertura MITRE ATT&CK

Cada técnica aparece em todas as táticas a que pertence no ATT&CK.

| Tática | Técnica | Regras |
|---|---|---|
| Acesso inicial (Initial Access) | T1078 Valid Accounts | 110005, 110103, 110151, 110203, 110210, 110900, 110901, 110902 |
| Acesso inicial (Initial Access) | T1078.001 Default Accounts | 110211, 110903 |
| Acesso inicial (Initial Access) | T1190 Exploit Public-Facing Application | 110164, 110300, 110301, 110302, 110303, 110304, 110305, 110306, 110315, 110950, 110951 |
| Execução (Execution) | T1059 Command and Scripting Interpreter | 110300, 110700, 110701 |
| Execução (Execution) | T1059.004 Unix Shell | 110700 |
| Persistência (Persistence) | T1078 Valid Accounts | 110005, 110103, 110151, 110203, 110210, 110900, 110901, 110902 |
| Persistência (Persistence) | T1078.001 Default Accounts | 110211, 110903 |
| Persistência (Persistence) | T1098 Account Manipulation | 110156, 110157, 110501, 110503, 110504, 110505, 110506, 110508, 110520, 110521, 110906, 110907, 110952 |
| Persistência (Persistence) | T1136 Create Account | 110158, 110500, 110501, 110502 |
| Persistência (Persistence) | T1505 Server Software Component | 110703 |
| Persistência (Persistence) | T1505.001 SQL Stored Procedures | 110701, 110702, 110704, 110705, 110802 |
| Persistência (Persistence) | T1556 Modify Authentication Process | 110056, 110508, 110800 |
| Escalada de privilégio (Privilege Escalation) | T1068 Exploitation for Privilege Escalation | 110155, 110521 |
| Escalada de privilégio (Privilege Escalation) | T1078 Valid Accounts | 110005, 110103, 110151, 110203, 110210, 110900, 110901, 110902 |
| Escalada de privilégio (Privilege Escalation) | T1078.001 Default Accounts | 110211, 110903 |
| Escalada de privilégio (Privilege Escalation) | T1098 Account Manipulation | 110156, 110157, 110501, 110503, 110504, 110505, 110506, 110508, 110520, 110521, 110906, 110907, 110952 |
| Evasão de defesas (Defense Evasion) | T1027 Obfuscated Files or Information | 110306 |
| Evasão de defesas (Defense Evasion) | T1070 Indicator Removal | 110731, 110732 |
| Evasão de defesas (Defense Evasion) | T1070.004 File Deletion | 110804 |
| Evasão de defesas (Defense Evasion) | T1078 Valid Accounts | 110005, 110103, 110151, 110203, 110210, 110900, 110901, 110902 |
| Evasão de defesas (Defense Evasion) | T1078.001 Default Accounts | 110211, 110903 |
| Evasão de defesas (Defense Evasion) | T1556 Modify Authentication Process | 110056, 110508, 110800 |
| Evasão de defesas (Defense Evasion) | T1562.001 Disable or Modify Tools | 110016, 110730, 110733, 110801, 110805 |
| Acesso a credenciais (Credential Access) | T1110 Brute Force | 110153, 110202, 110203, 110952, 110953, 110954 |
| Acesso a credenciais (Credential Access) | T1110.001 Password Guessing | 110006, 110051, 110104, 110152, 110200 |
| Acesso a credenciais (Credential Access) | T1110.003 Password Spraying | 110201 |
| Acesso a credenciais (Credential Access) | T1552.004 Private Keys | 110803 |
| Acesso a credenciais (Credential Access) | T1555 Credentials from Password Stores | 110715, 110716 |
| Acesso a credenciais (Credential Access) | T1556 Modify Authentication Process | 110056, 110508, 110800 |
| Descoberta (Discovery) | T1046 Network Service Discovery | 110251 |
| Descoberta (Discovery) | T1069 Permission Groups Discovery | 110717 |
| Descoberta (Discovery) | T1083 File and Directory Discovery | 110710 |
| Descoberta (Discovery) | T1087 Account Discovery | 110717 |
| Coleta (Collection) | T1005 Data from Local System | 110600, 110601, 110710, 110711 |
| Coleta (Collection) | T1074.001 Local Data Staging | 110600, 110601 |
| Coleta (Collection) | T1119 Automated Collection | 110605, 110607 |
| Coleta (Collection) | T1213 Data from Information Repositories | 110159, 110160, 110161, 110220, 110602, 110603, 110604, 110605, 110607, 110610, 110611, 110612, 110908, 110951, 110954 |
| Exfiltração (Exfiltration) | T1030 Data Transfer Size Limits | 110161, 110604 |
| Impacto (Impact) | T1485 Data Destruction | 110162, 110163, 110400, 110401, 110402, 110403, 110405, 110420, 110421, 110422, 110423, 110425, 110904, 110905, 110950, 110953 |
| Impacto (Impact) | T1489 Service Stop | 110011, 110053, 110720, 110721 |
| Impacto (Impact) | T1499 Endpoint Denial of Service | 110009 |
| Impacto (Impact) | T1531 Account Access Removal | 110507 |
| Impacto (Impact) | T1565.001 Stored Data Manipulation | 110404, 110424 |

<!-- REGRAS:FIM -->
