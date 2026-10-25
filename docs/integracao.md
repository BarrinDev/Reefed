# Integração com o seu sistema

Este guia liga o Reefed ao sistema do seu projeto (uma loja, um sistema acadêmico, uma
API) e ao banco que ele usa. O exemplo usa um sistema chamado `loja`; troque pelo nome do
seu.

## O que cada parte faz

| Parte | Como chega ao Reefed | O que o Reefed detecta | Mexe no código? |
|---|---|---|---|
| **Banco** | o agente lê o log do banco | força bruta e password spraying, login de IP desconhecido, SQL injection que chegou ao banco, `DROP`/`TRUNCATE`/`ALTER`, `GRANT` e superusuário criado, exportação em massa, leitura de hashes de senha, acesso fora do horário, mudança na configuração do banco | não |
| **Aplicação** | o seu sistema manda eventos pela API (ou grava num arquivo) | login na tela do sistema, acesso negado, troca de perfil, exportação de relatório, exclusão em lote, SQL injection barrada pela validação | algumas linhas |
| **Consulta** | o seu sistema lê a API | alertas, bloqueios e estado do SIEM numa tela de administração | opcional |

A parte do banco sozinha já protege bastante e não muda nada no sistema. A da aplicação
cobre o que o banco não vê: para o banco, um login na tela do sistema é só um `SELECT` na
tabela de usuários.

## Passo a passo

### 1. Suba o Reefed e instale o agente no servidor do banco

Siga o [README](../README.md#começando) e depois o [guia de agentes](agentes.md): o
agente no servidor do banco com `--db postgresql` (ou `mysql`, `mariadb`) e o arquivo
de log do banco de `agents/database/`. Confira errando a senha do banco uma vez: em até
um minuto aparece o alerta de falha de login.

### 2. Dê ao sistema um usuário próprio no banco

O sistema não deve conectar como `postgres` ou `root`. As regras separam quem faz
manutenção (a lista `db-admins`) de quem não deveria: um `DROP TABLE` do `postgres` é a
regra 110401 (nível 8, manutenção); o mesmo comando vindo do usuário do sistema é a
110421 (nível 12, crítico), porque provavelmente é um SQL injection. Se o sistema usa o
superusuário, um ataque pela aplicação parece manutenção.

PostgreSQL:

```sql
CREATE ROLE loja_app LOGIN PASSWORD 'troque-esta-senha';
GRANT CONNECT ON DATABASE loja TO loja_app;
GRANT USAGE ON SCHEMA public TO loja_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO loja_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO loja_app;
```

MySQL e MariaDB (com o IP do servidor do sistema):

```sql
CREATE USER 'loja_app'@'10.0.0.15' IDENTIFIED BY 'troque-esta-senha';
GRANT SELECT, INSERT, UPDATE, DELETE ON loja.* TO 'loja_app'@'10.0.0.15';
```

Quem faz manutenção (você, o DBA do grupo) usa outro usuário, que vai para a lista
`wazuh/lists/db-admins` junto com `postgres` e `root`:

```
postgres:superusuário padrão do PostgreSQL
root:superusuário padrão do MySQL/MariaDB
dba_grupo:DBA do trabalho
```

No PostgreSQL, ponha também o nome do sistema na conexão
(`application_name=loja-app` na string de conexão). Ele aparece nos alertas em
`database.app` e separa o sistema de quem conecta pelo `psql`, pelo pgAdmin ou pelo
DBeaver.

### 3. Diga ao Reefed quais IPs são da casa

Em `wazuh/lists/trusted-db-clients`, o servidor do sistema, a máquina de quem administra
e o servidor de backup (formato em [wazuh/lists/README.md](../wazuh/lists/README.md)):

```
10.0.0.15:servidor do sistema loja
192.168.0.:rede do laboratório
```

Depois de editar as listas, rode `make deploy-rules`. Sem isso, toda conexão do próprio
sistema vira alerta de IP desconhecido, e um erro de senha na configuração do sistema
pode fazer o Active Response bloquear o próprio sistema
([active-response.md](active-response.md#ips-que-nunca-são-bloqueados)).

### 4. Mande os eventos da aplicação

Copie para o projeto o cliente da linguagem do sistema, de `api/client/` (nenhum precisa
de biblioteca extra):

| Linguagem | Arquivo | Requisito |
|---|---|---|
| Python | `reefed_client.py` | Python 3.8+ |
| JavaScript | `reefed.mjs` | Node.js 18+ |
| Java | `Reefed.java` | Java 11+ |
| PHP | `reefed.php` | PHP 7.4+ com a extensão curl |

Configure o endereço e a chave em variáveis de ambiente do sistema (no `.env` dele, fora
do git), nunca no código:

```bash
REEFED_URL=http://10.0.0.5:8000
REEFED_API_KEY=a REEFED_API_KEY do .env do Reefed
```

Os exemplos de cada linguagem estão [mais abaixo](#exemplos). Os eventos e o que cada um
gera:

| Onde, no seu código | `event` | Campos | Alerta |
|---|---|---|---|
| login aceito | `login_success` | `user`, `srcip` | 110151 (nível 3) |
| login recusado | `login_failed` | `user`, `srcip`, `message` | 110152 (5); 6 do mesmo IP em 2 min: 110153 (10) |
| tela ou ação negada (HTTP 403) | `access_denied` | `user`, `srcip`, `message` | 110154 (5); 8 do mesmo usuário em 5 min: 110155 (10) |
| perfil ou permissão alterada | `permission_change` | `user` (quem recebeu), `role`, `message` (quem mudou) | 110156 (8); perfil de administrador: 110157 (11) |
| usuário criado | `user_created` | `user`, `srcip`, `message` | 110158 (5) |
| exportação, relatório, download | `data_export` | `user`, `srcip`, `records` | 110159 (3); 1000+: 110160 (8); 10000+: 110161 (11) |
| exclusão em lote | `bulk_delete` | `user`, `srcip`, `records` | 110162 (7); 100+: 110163 (11) |
| validação recusou entrada com SQL | `sql_injection_blocked` | `srcip`, `user`, `message` | 110164 (12) |
| configuração do sistema alterada | `config_change` | `user`, `message` | 110165 (7) |
| qualquer outra coisa | um nome seu, como `pagamento_estornado` | `severity` e o que mais fizer sentido | 110170 a 110173 (12, 10, 7 ou 3) |

Três cuidados:

- **Mande sempre o `srcip`**, o IP de quem está usando o sistema. É ele que junta as
  tentativas de login e liga o evento a outros alertas do mesmo IP. Atrás de um proxy
  (nginx, Cloudflare), pegue o IP real do cabeçalho que o seu proxy preenche, e só dele.
- **Não mande senha, token, CPF ou dados de cartão** em `message` nem em `extra`: tudo
  fica guardado no indexer.
- **O Reefed fora do ar não pode derrubar o sistema.** Os clientes têm um `notify`, que
  envia sem esperar a resposta e sem lançar erro (no PHP ele espera, então use um timeout
  curto). Use o `notify` no fluxo do usuário e o `send_event` só onde quiser tratar o erro.

### 5. Teste

```bash
make lab              # o laboratório completo, com ataques de verdade
```

E no seu sistema: erre a senha da tela de login 6 vezes seguidas. Em segundos aparece o
alerta 110153 (força bruta na tela de login) no dashboard, em
`GET /api/v1/alerts?since=15m&group=reefed_app` e no Telegram, se estiver configurado.

## Exemplos

### Python (Flask)

```python
import os
from flask import Flask, request
from reefed_client import ReefedClient

app = Flask(__name__)
reefed = ReefedClient(os.environ["REEFED_URL"], api_key=os.environ["REEFED_API_KEY"], timeout=3)


@app.post("/login")
def login():
    usuario = request.form["usuario"]
    ip = request.remote_addr  # atrás de um proxy, use o ProxyFix do werkzeug
    if not senha_confere(usuario, request.form["senha"]):
        reefed.notify("loja", "login_failed", user=usuario, srcip=ip, message="senha incorreta")
        return "Usuário ou senha inválidos", 401
    reefed.notify("loja", "login_success", user=usuario, srcip=ip)
    ...


@app.get("/relatorios/clientes.csv")
def exportar_clientes():
    linhas = buscar_clientes()
    reefed.notify("loja", "data_export", user=usuario_logado(), srcip=request.remote_addr,
                  records=len(linhas), message="relatório de clientes (CSV)")
    return gerar_csv(linhas)
```

`notify` envia numa thread e registra as falhas no `logging` (logger `reefed`). No Django
é igual; o IP vem de `request.META["REMOTE_ADDR"]`.

### JavaScript (Node.js com Express)

```js
import express from "express";
import { ReefedClient } from "./reefed.mjs";

const app = express();
app.set("trust proxy", 1); // só se houver um proxy na frente: req.ip vira o IP real
const reefed = new ReefedClient(process.env.REEFED_URL, process.env.REEFED_API_KEY, { timeoutMs: 3000 });

app.post("/login", express.json(), async (req, res) => {
  const { usuario, senha } = req.body;
  if (!(await senhaConfere(usuario, senha))) {
    reefed.notify("loja", "login_failed", { user: usuario, srcip: req.ip, message: "senha incorreta" });
    return res.status(401).send("Usuário ou senha inválidos");
  }
  reefed.notify("loja", "login_success", { user: usuario, srcip: req.ip });
  // ...
});

app.delete("/pedidos/antigos", async (req, res) => {
  const apagados = await apagarPedidosAntigos();
  reefed.notify("loja", "bulk_delete", { user: req.usuario, srcip: req.ip, records: apagados });
  res.json({ apagados });
});
```

Um `req.ip` no formato `::ffff:203.0.113.7` é aceito; a API guarda `203.0.113.7`.

### Java (Spring Boot)

```java
@RestController
public class LoginController {
    private final Reefed reefed = new Reefed(System.getenv("REEFED_URL"), System.getenv("REEFED_API_KEY"),
                                             Duration.ofSeconds(3));

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginForm form, HttpServletRequest request) {
        String ip = request.getRemoteAddr(); // atrás de um proxy: server.forward-headers-strategy=native
        if (!usuarios.senhaConfere(form.usuario(), form.senha())) {
            reefed.notify("loja", "login_failed", Map.of("user", form.usuario(), "srcip", ip, "message", "senha incorreta"));
            return ResponseEntity.status(401).body("Usuário ou senha inválidos");
        }
        reefed.notify("loja", "login_success", Map.of("user", form.usuario(), "srcip", ip));
        // ...
    }

    @PutMapping("/usuarios/{login}/perfil")
    public void mudarPerfil(@PathVariable String login, @RequestBody String perfil, Principal quem, HttpServletRequest request) {
        usuarios.mudarPerfil(login, perfil);
        reefed.notify("loja", "permission_change", Map.of("user", login, "role", perfil,
            "srcip", request.getRemoteAddr(), "message", "alterado por " + quem.getName()));
    }
}
```

Acrescente no topo do `Reefed.java` a linha `package` do pacote onde ele ficar. As
consultas devolvem o JSON como texto; leia com o Jackson que o Spring já traz. O
`Map.of` não aceita `null`: só coloque os campos que têm valor.

### PHP

```php
<?php
require_once __DIR__ . '/reefed.php';

$reefed = new ReefedClient(getenv('REEFED_URL'), getenv('REEFED_API_KEY'), 2);
$ip = $_SERVER['REMOTE_ADDR'];

if (!password_verify($_POST['senha'], $hashDoBanco)) {
    $reefed->notify('loja', 'login_failed', ['user' => $_POST['usuario'], 'srcip' => $ip, 'message' => 'senha incorreta']);
    http_response_code(401);
    exit('Usuário ou senha inválidos');
}
$reefed->notify('loja', 'login_success', ['user' => $_POST['usuario'], 'srcip' => $ip]);
```

No Laravel, coloque o cliente em `app/` e use `$request->ip()` para o IP.

### Um evento que não está na tabela

Use um nome seu e a severidade:

```python
reefed.notify("loja", "pagamento_estornado", user="ana", srcip=ip, severity="high",
              message="estorno de R$ 4.500,00 sem aprovação", extra={"pedido": 1042})
```

`high` vira a regra 110171 (nível 10), que já chega no Telegram e no Slack.

## Mostrar os alertas no sistema

Uma tela de administração pode mostrar o resumo do dia, os alertas graves e os IPs
bloqueados. Faça a consulta no backend, com a chave de leitura
(`REEFED_API_READ_KEY`), e entregue à página só o resultado:

```python
leitura = ReefedClient(os.environ["REEFED_URL"], api_key=os.environ["REEFED_API_READ_KEY"])


@app.get("/admin/seguranca")
def painel_seguranca():  # só para administradores
    return render_template(
        "seguranca.html",
        resumo=leitura.summary(since="24h"),                      # contagem por severidade e os mais frequentes
        graves=leitura.alerts(since="24h", min_level=10, limit=20)["items"],
        bloqueados=leitura.blocked()["active"],
    )
```

Os campos de cada resposta estão na [referência da API](api.md).

## Eventos por arquivo

Se o sistema não puder chamar a API (sem rede até o Reefed, ou para não depender dela), ele
pode gravar os eventos num arquivo, uma linha JSON por evento, que o agente do servidor do
sistema lê. Instale o agente no servidor do sistema no grupo `app`:

```bash
sudo ./agents/linux/install-agent.sh --manager IP_DO_REEFED --password SENHA --groups linux,app
```

No Windows, `-Groups windows,app`. O agente lê `/var/log/reefed/eventos.json` (no Windows,
`C:\reefed\eventos.json`). Crie o arquivo antes, com dono o usuário do sistema:

```bash
sudo install -d -m 755 /var/log/reefed
sudo install -o www-data -m 640 /dev/null /var/log/reefed/eventos.json   # www-data: o usuário do seu sistema
```

O agente só lê as linhas gravadas depois que ele abre o arquivo; com o arquivo criado
antes, nada se perde. Cada linha tem o formato que a API monta:

```json
{"reefed":{"source":"app","app":"loja","event":"login_failed","message":"senha incorreta"},"srcip":"203.0.113.7","dstuser":"ana"}
```

Em Python:

```python
import json

def evento_reefed(event, user=None, srcip=None, **campos):
    linha = {"reefed": {"source": "app", "app": "loja", "event": event,
                        **{k: v for k, v in campos.items() if v is not None}}}
    if srcip:
        linha["srcip"] = srcip
    if user:
        linha["dstuser"] = user
    with open("/var/log/reefed/eventos.json", "a", encoding="utf-8") as arquivo:
        arquivo.write(json.dumps(linha, ensure_ascii=False) + "\n")
```

Os campos são os da API (`message`, `records`, `role`, `severity`, `request_id`, `extra`),
mas ninguém valida: um `srcip` que não seja IP quebra as regras que contam por IP. Os
alertas saem com o servidor do sistema como agente e o arquivo em `location`. Quem pode
escrever no arquivo pode criar eventos, então mantenha a permissão fechada. Para o
arquivo não crescer para sempre, use o logrotate; o agente percebe a rotação sozinho.

## Lista de conferência

- [ ] `make agents` mostra o agente do servidor do banco como `active`
- [ ] uma senha errada no banco gera alerta de falha de login
- [ ] o sistema conecta no banco com um usuário próprio, sem privilégio de administrador
- [ ] os usuários de manutenção estão em `db-admins` e os IPs da casa em `trusted-db-clients`
- [ ] o sistema manda `login_failed` e `login_success` com `srcip`
- [ ] a chave da API está numa variável de ambiente, fora do git
- [ ] a API só é alcançada pelo servidor do sistema (firewall, `REEFED_API_BIND` ou proxy
      com HTTPS, veja [api.md](api.md#https-rede-e-navegador))
- [ ] pelo menos um canal de alerta configurado e testado ([alertas.md](alertas.md#testar-os-canais))

## Para apresentar o trabalho

Um roteiro curto que mostra tudo funcionando:

1. `make status` com os agentes conectados e os canais de alerta ligados.
2. O painel **Reefed - Segurança do banco de dados** no dashboard.
3. `make lab-attack` (com o laboratório no ar) ou uma força bruta de outra máquina: o
   alerta chega no Telegram, o IP aparece em `GET /api/v1/blocked` e a conexão do
   atacante para de responder.
4. Um SQL injection na tela de busca do seu sistema, aparecendo como alerta com o
   comando SQL completo e a técnica MITRE.
5. A tela de segurança do seu sistema lendo a API do Reefed.
