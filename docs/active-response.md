# Active Response: bloqueio automático de IPs

Quando um IP erra a senha do banco várias vezes seguidas, o agente do servidor de banco
bloqueia esse IP no firewall do próprio servidor por 10 minutos. Depois disso o bloqueio
sai sozinho. Cada bloqueio vira um alerta, aparece no dashboard e na API do Reefed
(`GET /api/v1/blocked`), e o atacante fica sem acesso a nenhuma porta do servidor
enquanto durar.

## Quando bloqueia

| Regra | Nível | Situação |
|---|---|---|
| 110200 | 10 | força bruta: 5 falhas de login no banco vindas do mesmo IP em 2 minutos |
| 110201 | 12 | password spraying: 5 falhas do mesmo IP em 5 minutos, cada uma num usuário diferente |

As duas contam as falhas de login do PostgreSQL, do MySQL e do MariaDB. A força bruta na
tela de login do seu sistema (regra 110153, eventos `login_failed` enviados pela API) gera
alerta mas não bloqueia: quem conecta no banco é o servidor da aplicação, então o IP do
atacante nem chega ao servidor de banco. Esse caso o próprio sistema precisa tratar
(bloqueio da conta, captcha, limite de tentativas).

## Como funciona

1. O banco registra a falha de login com o IP do cliente. O agente manda a linha para o
   manager, que junta as falhas e dispara a regra 110200 ou 110201.
2. O manager manda o agente **que viu o ataque** rodar o bloqueio
   (`<location>local</location>`):
   - **Linux** (`firewall-drop`): `iptables -I INPUT -s IP -j DROP` e
     `iptables -I FORWARD -s IP -j DROP`. A regra no `FORWARD` também protege um banco em
     Docker com a porta publicada no mesmo servidor
     ([agentes.md](agentes.md#banco-em-docker)).
   - **Windows** (`netsh`): uma regra de entrada no Firewall do Windows chamada
     `WAZUH ACTIVE RESPONSE BLOCKED IP`, bloqueando o IP.

   Os dois comandos vão para todos os agentes e cada um roda o que existe no seu sistema.
   Por isso o agente Linux registra no próprio log um aviso inofensivo:
   `Active response command not present: 'active-response/bin/netsh.exe'`.
3. Depois de `REEFED_AR_TIMEOUT` segundos (padrão 600), o agente tira a regra do firewall.
4. O bloqueio e a liberação viram os alertas 110260 (nível 8, "IP 203.0.113.7 bloqueado
   no servidor de banco pelo Active Response") e 110261 (nível 3, "bloqueio do IP ...
   expirou").

Cada servidor bloqueia por conta própria: quem atacou o PostgreSQL fica bloqueado no
servidor do PostgreSQL. Se outro ataque do mesmo IP chega a outro servidor, ele também
bloqueia. Para bloquear em todos os servidores com agente de uma vez, troque
`<location>local</location>` por `<location>all</location>` nos dois blocos
`<active-response>` de `config/wazuh_manager/ossec.conf` e rode `make deploy-rules`.

## IPs que nunca são bloqueados

Antes de usar em produção, coloque na lista `wazuh/lists/trusted-db-clients` o servidor da
aplicação, a máquina do DBA e o servidor de backup:

```
10.0.0.15:servidor da aplicação
10.0.0.20:servidor de backup
192.168.1.:rede do laboratório da faculdade
```

Um IP terminado em ponto vale para a rede inteira (`192.168.1.` é `192.168.1.0/24`). O
formato está em [wazuh/lists/README.md](../wazuh/lists/README.md). Essa lista também
decide o alerta de IP desconhecido (regra 110210).

Para não mexer na lista, ou para redes que não terminam num octeto inteiro, use o `.env`:

```bash
REEFED_AR_WHITELIST=10.0.0.15,10.20.0.0/22
```

O `127.0.0.1` nunca é bloqueado. Rode `make deploy-rules` depois de editar a lista, ou
`make restart` depois de mudar o `.env`.

**Por que isso importa:** se a senha do banco no sistema estiver errada (depois de uma
troca de senha, por exemplo), a aplicação erra o login várias vezes seguidas. Sem o
servidor da aplicação na lista, o Reefed bloquearia a própria aplicação e o sistema
ficaria fora do ar por 10 minutos.

## Ligar, desligar e mudar o tempo

```bash
REEFED_AR_ENABLED=yes     # no desliga o bloqueio (os alertas continuam)
REEFED_AR_TIMEOUT=600     # segundos que o IP fica bloqueado
```

Depois de mudar, rode `make restart`. O manager registra a configuração ao iniciar:

```bash
docker compose logs wazuh.manager | grep "Active Response"
```

```
[reefed] ossec.conf gerado; alertas: Telegram, e-mail; Active Response: ligado; white_list: 127.0.0.1, 10.0.0.15, 10.20.0.0/22; ...
```

## Ver o que está bloqueado

**Pela API do Reefed** (exemplo do laboratório, onde o bloqueio dura 2 minutos):

```bash
curl -H "X-API-Key: $REEFED_API_KEY" "http://localhost:8000/api/v1/blocked?since=24h"
```

```json
{
  "active": [],
  "history": [
    {
      "ip": "10.250.77.66",
      "agent": "lab-postgres",
      "agent_id": "002",
      "blocked_at": "2026-10-22T19:05:30.763Z",
      "expires_at": "2026-10-22T19:07:30.763Z",
      "unblocked_at": "2026-10-22T19:08:15.791Z",
      "rule": {"id": "110200", "description": "Reefed: força bruta contra o banco a partir de 10.250.77.66 (5+ falhas de login em 2 min, último usuário app)."},
      "times_blocked": 4,
      "active": false
    }
  ],
  "ar_timeout_seconds": 120
}
```

`active` são os bloqueios que ainda valem e `history` os que já expiraram, um por IP e
servidor. `times_blocked` conta quantas vezes o bloqueio foi acionado para aquele IP no
período: enquanto o ataque continua, a regra dispara de novo e o bloqueio é renovado.
`expires_at` é calculado a partir do último acionamento.

**No dashboard:** em Discover, pesquise `rule.id:(110260 or 110261)`.

**No servidor:**

```bash
sudo iptables -S INPUT | grep DROP                 # Linux
sudo tail -n 20 /var/ossec/logs/active-responses.log
```

```powershell
netsh advfirewall firewall show rule name="WAZUH ACTIVE RESPONSE BLOCKED IP"   # Windows
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 20
```

## Liberar um IP antes da hora

No servidor de banco que bloqueou:

```bash
# Linux
sudo iptables -D INPUT -s 203.0.113.7 -j DROP
sudo iptables -D FORWARD -s 203.0.113.7 -j DROP
```

```powershell
# Windows (PowerShell como administrador)
netsh advfirewall firewall delete rule name="WAZUH ACTIVE RESPONSE BLOCKED IP" remoteip=203.0.113.7/32
```

Quando o tempo acabar, o agente vai tentar tirar a regra de novo e registrar um erro
inofensivo no `active-responses.log`. A API continua mostrando o IP em `active` até lá.
Se o IP é de alguém confiável, coloque-o na lista (acima) para não ser bloqueado de novo.

## Testar

O `make lab` testa o bloqueio: o atacante (10.250.77.66) faz força bruta nos três bancos
e a conferência exige o alerta 110260 e o `firewall-drop` chamado com o IP certo em cada
agente. No laboratório os agentes rodam em containers e o `iptables` deles só registra o
comando, sem bloquear de verdade; o script do Wazuh que roda é o mesmo de um servidor
real. Veja [lab/README.md](../lab/README.md).

Num servidor seu, teste **de outra máquina**, que não esteja na lista de confiáveis e que
você não use para entrar por SSH no servidor de banco: o bloqueio corta todas as portas,
inclusive o SSH, por 10 minutos.

```bash
# PostgreSQL: 6 tentativas com senha errada
for i in 1 2 3 4 5 6; do PGPASSWORD=errada psql -h IP_DO_BANCO -U app -d loja -c 'select 1'; done

# MySQL ou MariaDB
for i in 1 2 3 4 5 6; do mysql -h IP_DO_BANCO -u app -perrada -e 'select 1'; done
```

Em alguns segundos a próxima conexão fica parada até dar tempo esgotado, e o IP aparece
em `active` no `GET /api/v1/blocked`.

## Limites

- **O banco precisa registrar o IP**, não o nome da máquina: sem IP não há o que
  bloquear (o alerta sai do mesmo jeito). No PostgreSQL, o `reefed.conf` já desliga o
  `log_hostname`. O MySQL e o MariaDB registram o nome quando o IP do cliente tem DNS
  reverso (`'app'@'servidor-app.local'` no log); nesse caso, ligue
  `skip_name_resolve = ON` no arquivo de configuração do banco. As imagens Docker oficiais
  dos dois já vêm assim. Antes, confira as contas: com essa opção, uma conta criada com
  nome de máquina para de funcionar, e uma conexão TCP para `127.0.0.1` deixa de usar as
  contas `'usuario'@'localhost'` (crie a conta com o IP ou com `'%'`).
- **Proxy ou pool de conexões na frente do banco** (PgBouncer, ProxySQL): o banco vê o IP
  do proxy, não o do atacante. Coloque o proxy na lista de confiáveis; as falhas continuam
  gerando alerta, mas ninguém é bloqueado no servidor de banco. Para bloquear, o agente
  precisa estar no servidor do proxy, lendo o log dele.
- **Banco em container com agente ao lado (sidecar):** o bloqueio fica dentro do container
  do agente e não protege o banco. Instale o agente no servidor
  ([agentes.md](agentes.md#banco-em-docker)).
- O bloqueio é por IP. Um atacante que troca de IP a cada tentativa (botnet) passa por
  baixo do limite de 5 falhas por IP; nesse caso os alertas de IP desconhecido (110210) e
  de falhas em sequência continuam aparecendo.
