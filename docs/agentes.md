# Agentes

O agente do Wazuh vai em cada servidor que o Reefed vigia: o servidor do banco (o mais
importante), o servidor da aplicação e outros. Ele se registra no manager na porta
1515/tcp com a senha `REEFED_ENROLLMENT_PASSWORD` do `.env` e depois manda os eventos pela
1514/tcp, criptografados.

## Grupos

Cada agente entra em grupos, e o manager manda para ele a configuração de cada grupo
(`wazuh/shared/<grupo>/agent.conf`). Os instaladores escolhem os grupos sozinhos.

| Grupo | Para quem | O que acrescenta |
|---|---|---|
| `linux` | todo servidor Linux | auditd (se instalado) e FIM em tempo real do `sshd_config`, do `/etc/sudoers.d` e das chaves SSH do root |
| `windows` | todo servidor Windows | firewall do Windows (mudanças de regra e conexões bloqueadas), Defender, PowerShell, RDP e Sysmon (se instalado) |
| `database` | servidor de banco | rótulo `reefed.role=database` nos alertas e FIM da configuração do próprio agente (regra 110805) |
| `postgresql`, `mysql`, `mariadb` | servidor daquele banco | logs do banco e FIM da configuração, da autenticação, de plugins e extensões, das chaves TLS e dos logs |
| `app` | servidor da aplicação, se ela gravar os eventos num arquivo em vez de usar a API (opcional, `--groups linux,app`) | leitura de `/var/log/reefed/eventos.json` (Windows: `C:\reefed\eventos.json`), veja [integracao.md](integracao.md#eventos-por-arquivo) |

O que a configuração padrão do agente já lê continua valendo: no Linux, o journald (ou
`/var/log/auth.log`, `secure`, `syslog`, `messages` e `kern.log`), com SSH, `sudo`, `su`,
logins e o firewall do kernel (UFW, iptables, firewalld); no Windows, os canais Security,
System e Application. Por isso os grupos só acrescentam o que falta.

Um servidor de banco PostgreSQL no Linux fica nos grupos `linux,database,postgresql`.

## Servidor Linux

Copie a pasta `agents/` para o servidor (ou clone o repositório) e rode como root:

```bash
sudo ./agents/linux/install-agent.sh --manager IP_DO_REEFED --password SENHA                     # servidor comum
sudo ./agents/linux/install-agent.sh --manager IP_DO_REEFED --password SENHA --db postgresql     # servidor de banco
```

| Opção | O que faz |
|---|---|
| `--manager IP` | endereço do servidor do Reefed |
| `--password SENHA` | a `REEFED_ENROLLMENT_PASSWORD` do `.env` |
| `--db BANCO` | `postgresql`, `mysql` ou `mariadb`: servidor de banco |
| `--name NOME` | nome do agente (padrão: o hostname) |
| `--groups LISTA` | grupos, se quiser outros que os padrão |
| `--version X.Y.Z` | versão do agente (padrão 4.14.9; não pode ser maior que a do manager) |
| `--no-firewall` | não instala o iptables (sem ele o bloqueio automático de IP não funciona) |
| `--flags-interval N` | segundos entre as verificações de `skip-grant-tables` (padrão 300) |
| `--configure-only` | não instala nem registra; só aplica os ajustes do Reefed no `ossec.conf` |

O script:

- instala o pacote oficial do Wazuh (apt no Debian/Ubuntu, dnf ou yum no RHEL, Rocky,
  Alma, Fedora e Amazon Linux) e segura a versão, para o agente não ser atualizado antes
  do manager;
- registra o agente nos grupos certos;
- tira `.log$` da lista de arquivos que o FIM ignora, para o Reefed saber quando alguém
  apaga um log do banco (regra 110804);
- em servidor MySQL ou MariaDB, acrescenta a verificação que procura `skip-grant-tables`
  na linha de comando e na configuração do banco (regra 110056). Comandos não podem vir
  da configuração central do manager, por segurança, por isso ficam no agente;
- em servidor de banco, instala o iptables, que o Active Response usa para bloquear IPs.

Pode rodar de novo: ele registra o agente outra vez e refaz os ajustes sem duplicar
nada. Se o agente foi instalado de outro jeito, rode só com `--configure-only --db BANCO`.
Precisa de saída para `packages.wazuh.com` e para as portas 1514 e 1515 do Reefed.

## Servidor Windows

Copie a pasta `agents\windows` para o servidor e rode num PowerShell aberto como
administrador:

```powershell
.\install-agent.ps1 -Manager IP_DO_REEFED -Password SENHA                       # servidor comum
.\install-agent.ps1 -Manager IP_DO_REEFED -Password SENHA -Database mysql       # servidor de banco
```

Se a política de execução bloquear o script:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-agent.ps1 -Manager IP_DO_REEFED -Password SENHA -Database mysql
```

| Opção | O que faz |
|---|---|
| `-Manager`, `-Password`, `-Name`, `-Groups`, `-Version` | como no Linux |
| `-Database BANCO` | `postgresql`, `mysql` ou `mariadb`: servidor de banco |
| `-DatabaseService NOME` | serviço do Windows do banco, se houver mais de um ou o script não achar (`Get-Service`) |
| `-MsiPath ARQUIVO` | MSI do agente já baixado, para servidor sem internet |
| `-SkipSignatureCheck` | não confere a assinatura digital do MSI (só com arquivo de origem conhecida) |
| `-NoFirewall` | não mexe no log do firewall do Windows |
| `-NoAuditPolicy` | não mexe na política de auditoria (quando ela vem de uma GPO do domínio) |
| `-FlagsInterval N` | segundos entre as verificações de `skip-grant-tables` (padrão 300) |
| `-ConfigureOnly` | não instala nem registra; só refaz os ajustes do Reefed e reinicia o agente |

O script:

- baixa o MSI oficial do Wazuh, confere a assinatura digital (tem de ser da Wazuh), instala
  e registra o agente;
- liga o log de conexões bloqueadas do firewall do Windows (`pfirewall.log`) e avisa se
  algum perfil do firewall estiver desligado, porque o Active Response bloqueia IPs com uma
  regra do firewall (`netsh`);
- liga a auditoria de logon, de contas e grupos e de mudanças de política (eventos 4624,
  4625, 4720, 4732 e outros), que alimenta as regras de login do Windows;
- em servidor de banco, acha a instalação pelo serviço do Windows, lê o `postgresql.conf`
  ou o `my.ini` dele e grava no `ossec.conf` do agente os caminhos dos logs e dos arquivos
  vigiados pelo FIM. No MySQL e no MariaDB grava também a verificação de
  `skip-grant-tables`. Os caminhos mudam com a versão instalada, por isso ficam no agente
  e não na configuração do grupo;
- confere a configuração de log do banco e mostra as linhas que faltam (ele não muda a
  configuração do banco).

Depois de atualizar o banco ou mudar os caminhos de log, rode de novo com
`-ConfigureOnly -Database BANCO`. Funciona no Windows PowerShell 5.1 e no PowerShell 7
(Windows 10/11 e Windows Server 2016 ou mais novo). O CI do repositório instala o agente
com este script num Windows Server do GitHub a cada push.

## Configurar o log do banco

O agente só lê o que o banco grava. Os arquivos de `agents/database/` ligam o log no formato
que os decoders do Reefed entendem. Sem eles o Reefed não vê logins, comandos nem erros do
banco.

### PostgreSQL

Arquivo: `agents/database/postgresql/reefed.conf`.

| Instalação | Onde colocar | Como aplicar |
|---|---|---|
| Debian/Ubuntu | `/etc/postgresql/<versão>/main/conf.d/reefed.conf` | `sudo systemctl reload postgresql` |
| RHEL/PGDG | no diretório de dados (ex.: `/var/lib/pgsql/17/data/reefed.conf`) e, no fim do `postgresql.conf`, `include_if_exists = 'reefed.conf'` | `sudo systemctl reload postgresql-17` |
| Windows | `C:\Program Files\PostgreSQL\<versão>\data\reefed.conf`, com o mesmo `include_if_exists` | `pg_ctl reload -D "C:\Program Files\PostgreSQL\<versão>\data"` (o instalador mostra o comando com os caminhos) |

O que ele liga:

- `log_line_prefix = '%m [%p] user=%u db=%d client=%h app=%a '`: data, processo, usuário,
  banco, IP do cliente e aplicação em cada linha. Os decoders dependem exatamente desse
  formato, inclusive do espaço no fim;
- `log_connections` e `log_disconnections`: logins aceitos, recusados e fim de sessão;
- `log_statement = 'all'`: todos os comandos, base das regras de SQL injection, DDL,
  privilégios, exportação e leitura de hashes. Em banco com muito movimento, `'ddl'`
  diminui o volume, mas desliga as regras que olham `SELECT`, `INSERT`, `UPDATE` e
  `DELETE`;
- `log_min_error_statement = error`: o comando que deu erro aparece junto do erro;
- `log_hostname = off`: IP em vez de nome no campo do cliente, porque as listas e o
  bloqueio usam IP.

Confira com `sudo -u postgres psql -c 'SHOW log_line_prefix'`.

O arquivo de log continua onde a instalação já grava, e o grupo `postgresql` lê esses
caminhos: `/var/log/postgresql/postgresql-*.log` no Debian/Ubuntu e
`<dados>/log/postgresql-*.log` no RHEL, na imagem Docker oficial e no Windows.

### MySQL 8.x

Arquivo: `agents/database/mysql/reefed.cnf`.

| Instalação | Onde colocar |
|---|---|
| Debian/Ubuntu | `/etc/mysql/mysql.conf.d/reefed.cnf` |
| RHEL | `/etc/my.cnf.d/reefed.cnf` |
| Windows | as linhas da seção `[mysqld]` no `my.ini` do serviço (o instalador do agente diz qual é e quais linhas faltam) |

No Linux, crie a pasta dos logs e reinicie:

```bash
sudo install -d -o mysql -g mysql -m 750 /var/log/mysql
sudo systemctl restart mysql      # ou mysqld
```

No RHEL com SELinux, libere a pasta para o MySQL:
`sudo semanage fcontext -a -t mysqld_log_t "/var/log/mysql(/.*)?" && sudo restorecon -Rv /var/log/mysql`.

O que ele liga:

- `error.log` com `log_error_verbosity = 3`: falhas de login ("Access denied") só aparecem
  nessa verbosidade;
- slow log com `long_query_time = 0` e `log_slow_extra = ON`: um registro por comando, com
  usuário, IP, código de erro e linhas devolvidas (a base das regras de exportação em
  massa);
- general log: só as linhas `Connect` são lidas pelo agente, para saber de cada nova
  sessão.

No Windows, sem caminho no `my.ini` o MySQL grava esses logs na pasta Data com o nome do
computador; o instalador do agente acha os nomes sozinho. As linhas para o `my.ini`:

```ini
[mysqld]
log_error_verbosity       = 3
slow_query_log            = ON
long_query_time           = 0
log_slow_extra            = ON
log_slow_admin_statements = ON
general_log               = ON
```

Depois, `Restart-Service MySQL80` (o nome do serviço muda com a versão) e
`.\install-agent.ps1 -ConfigureOnly -Database mysql`.

O slow log e o general log gravam todos os comandos. Em servidor com muito movimento,
acompanhe o espaço em disco; no Linux o pacote do MySQL já traz um logrotate para
`/var/log/mysql`.

### MariaDB

Arquivo: `agents/database/mariadb/reefed.cnf`. O MariaDB registra logins (inclusive os
que falharam), comandos e tabelas usadas pelo plugin `server_audit`, que já vem com o
servidor.

| Instalação | Onde colocar |
|---|---|
| Debian/Ubuntu | `/etc/mysql/mariadb.conf.d/90-reefed.cnf` |
| RHEL | `/etc/my.cnf.d/reefed.cnf` |
| Windows | as linhas no `my.ini` da pasta data, com `server_audit_file_path = server_audit.log` |

No Linux, crie a pasta do log e reinicie:

```bash
sudo install -d -o mysql -g mysql -m 750 /var/log/mysql
sudo systemctl restart mariadb
```

`server_audit = FORCE_PLUS_PERMANENT` impede desligar o plugin com `UNINSTALL PLUGIN`
enquanto o servidor roda, e desligar a auditoria com `SET GLOBAL server_audit_logging`
vira alerta crítico (regra 110730).

### Conferir

Erre a senha uma vez de outra máquina:

```bash
psql "host=IP_DO_BANCO user=postgres password=errada"         # PostgreSQL
mysql -h IP_DO_BANCO -u root -perrada                          # MySQL e MariaDB
```

Em até um minuto aparece o alerta "Falha de login" (regras 110006, 110051 ou 110104) no
dashboard ou em `make api-test`. Cinco erros em dois minutos viram "força bruta" (110200)
e o IP é bloqueado no servidor do banco.

No alerta, o campo `srcip` precisa ter o IP de quem errou a senha. Se o MySQL ou o
MariaDB mostrar o nome da máquina (`'root'@'notebook.local'`), o alerta de falha sai, mas
o bloqueio e o alerta de IP desconhecido não funcionam; a solução está em
[active-response.md](active-response.md#limites).

## Banco em Docker

Se o banco do seu projeto roda num container, há dois jeitos.

**Agente no servidor que roda o Docker** (o jeito para produção). Instale o agente no
servidor com `install-agent.sh --db BANCO` e monte as pastas do banco nos mesmos caminhos
que o grupo do banco lê. No PostgreSQL, monte o diretório de dados em
`/var/lib/postgresql/data` também no servidor e passe as opções do `reefed.conf` com
`-c` (o mesmo que o serviço `postgres` de `lab/docker-compose.yml` faz):

```yaml
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    command:
      - postgres
      - -c
      - logging_collector=on
      - -c
      - log_directory=log
      - -c
      - log_filename=postgresql-%Y-%m-%d.log
      - -c
      - "log_line_prefix=%m [%p] user=%u db=%d client=%h app=%a "   # com o espaço no fim
      - -c
      - log_connections=on
      - -c
      - log_disconnections=on
      - -c
      - log_statement=all
      - -c
      - log_min_error_statement=error
    volumes:
      # mesmo caminho no servidor: o agente lê data/log e vigia o pg_hba.conf
      - /var/lib/postgresql/data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
```

No MySQL e no MariaDB, monte `/var/log/mysql` e `/etc/mysql/conf.d` do servidor no
container e ponha o `reefed.cnf` no `/etc/mysql/conf.d` do servidor. O usuário `mysql` da
imagem oficial é o uid 999, então crie a pasta do log assim:
`sudo install -d -o 999 -g 999 -m 750 /var/log/mysql`.

O bloqueio de IP funciona nesse modelo: o `firewall-drop` do Wazuh bloqueia o IP nas
cadeias `INPUT` e `FORWARD` do iptables (conferido no laboratório), e as conexões às portas
publicadas pelo Docker passam pela `FORWARD`.

**Agente num container ao lado do banco**, que lê os volumes do banco. É o que o
laboratório faz (`lab/docker-compose.yml`, serviços `pg-agent`, `my-agent` e
`maria-agent`, com a imagem de `lab/agent/Dockerfile`), e serve para testar. Nesse modelo o
bloqueio de IP do Active Response roda dentro do container do agente e não protege o
banco; no laboratório o iptables é de mentira e só registra o comando.

## Remover um agente

```bash
scripts/wazuh-api.sh DELETE '/agents?agents_list=ID&status=all&older_than=0s&purge=true'
```

O ID aparece em `make agents`. Depois desinstale o pacote no servidor
(`sudo apt-get remove wazuh-agent`, ou "Wazuh Agent" em Aplicativos no Windows).
