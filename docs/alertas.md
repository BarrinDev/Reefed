# Alertas no Telegram, no Slack e por e-mail

O Reefed manda um resumo dos alertas importantes para o Telegram, para um canal do Slack
e por e-mail. Cada canal liga sozinho quando as variáveis dele estão preenchidas no
`.env`. Depois de mexer no `.env`, rode:

```bash
make restart
make status     # a linha "notificações" mostra os canais ligados
```

```
[reefed] notificações: Telegram, Slack, e-mail
```

Todos os alertas continuam no dashboard e na API, com ou sem canal configurado. Os canais
servem para ninguém precisar ficar olhando o dashboard.

## Como funciona

A cada início, o manager monta um bloco `<integration>` no `ossec.conf` para cada canal
preenchido no `.env`. O `wazuh-integratord` (serviço do Wazuh) chama o script do canal
(`wazuh/integrations/custom-reefed-*`) para cada alerta com nível igual ou maior que o do
canal. O script monta a mensagem em português e envia.

| Canal | Variáveis obrigatórias | Nível mínimo (padrão) |
|---|---|---|
| Telegram | `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID` | `REEFED_TELEGRAM_LEVEL=10` |
| Slack | `SLACK_WEBHOOK_URL` | `REEFED_SLACK_LEVEL=10` |
| E-mail | `SMTP_HOST` e `ALERT_EMAIL_TO` (mais usuário e senha, se o servidor pedir) | `REEFED_EMAIL_LEVEL=12` |

Os níveis vão de 0 a 15:

| Nível | Severidade | Exemplos | Vai para (padrão) |
|---|---|---|---|
| 0 a 6 | 🔵 baixo | login aceito, uma senha errada, configuração recarregada | só dashboard |
| 7 a 9 | 🟡 médio | `DROP TABLE` ou `TRUNCATE` de um administrador, exportação grande, configuração do sistema alterada | só dashboard |
| 10 e 11 | 🟠 alto | força bruta, login de IP desconhecido, SQL injection por tempo | Telegram e Slack |
| 12 a 15 | 🔴 crítico | password spraying, `DROP DATABASE`, superusuário criado, backdoor no `pg_hba.conf` | Telegram, Slack e e-mail |

O nível de cada regra está no [catálogo de regras](regras.md).

## Telegram

1. **Crie o bot.** No Telegram, abra uma conversa com o [@BotFather](https://t.me/BotFather),
   mande `/newbot`, escolha um nome (ex.: `Reefed Alertas`) e um usuário terminado em `bot`
   (ex.: `reefed_projeto_bot`). Ele responde com o token, algo como
   `7212345678:AAH3k...`. Esse é o `TELEGRAM_BOT_TOKEN`.

2. **Descubra o chat_id**, que é para onde o bot manda as mensagens:

   - **Só para você:** mande qualquer mensagem para o bot e abra no navegador
     `https://api.telegram.org/bot<TOKEN>/getUpdates` (troque `<TOKEN>` pelo token). O
     número em `"chat":{"id":123456789` é o chat_id.
   - **Para um grupo** (a equipe toda recebe): adicione o bot ao grupo, mande no grupo
     `/start@reefed_projeto_bot` (com o usuário do seu bot) e abra o mesmo endereço. O id
     do grupo é negativo, como `-1001234567890`; copie com o sinal de menos.

   Se o `getUpdates` voltar com `"result":[]`, mande outra mensagem e recarregue a página.

3. **Preencha o `.env`** e rode `make restart`:

   ```bash
   TELEGRAM_BOT_TOKEN=7212345678:AAH3k...
   TELEGRAM_CHAT_ID=-1001234567890
   ```

Se o servidor do Reefed só sai para a internet por um proxy, coloque o endereço que leva à
API do Telegram em `TELEGRAM_API_URL`.

## Slack

1. Em <https://api.slack.com/apps>, clique em **Create New App > From scratch**, dê um
   nome (ex.: `Reefed`) e escolha o workspace.
2. No menu do app, abra **Incoming Webhooks**, ligue **Activate Incoming Webhooks** e
   clique em **Add New Webhook to Workspace**. Escolha o canal (ex.: `#seguranca`) e
   autorize.
3. Copie a **Webhook URL** (`https://hooks.slack.com/services/T.../B.../...`) para o
   `.env` e rode `make restart`:

   ```bash
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0000/B0000/XXXXXXXX
   ```

Quem tem essa URL consegue postar no canal: trate como senha. Para trocar de canal, crie
outro webhook e troque a URL.

## E-mail

O e-mail sai por um servidor SMTP com usuário e senha (o envio nativo do Wazuh não faz
login, por isso o Reefed tem o próprio).

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURITY=starttls          # starttls (porta 587), ssl (porta 465) ou none
SMTP_USER=alertas.projeto@gmail.com
SMTP_PASSWORD=abcdefghijklmnop  # no Gmail, a senha de app (sem espaços)
SMTP_FROM=alertas.projeto@gmail.com
ALERT_EMAIL_TO=voce@exemplo.com,professor@exemplo.com
```

**Gmail:** a senha normal da conta não funciona. Ligue a verificação em duas etapas na
conta Google e crie uma senha de app em <https://myaccount.google.com/apppasswords>. O
Google mostra 16 letras em grupos de quatro; use as 16 juntas no `SMTP_PASSWORD`. Vale
criar uma conta só para os alertas.

**Outros provedores:** use o servidor, a porta e o tipo de conexão que o provedor indicar.
Serviços de envio como Amazon SES, SendGrid, Mailgun e Brevo têm SMTP com usuário e senha.
Um servidor interno que não pede login funciona com `SMTP_USER` e `SMTP_PASSWORD` vazios
(e `SMTP_SECURITY=none` se ele não tiver TLS).

O assunto traz a severidade e a descrição, como
`[Reefed] CRÍTICO (nível 12): Reefed: DROP DATABASE executado por app...`. O corpo vai em
HTML e em texto puro, com regra, servidor, MITRE ATT&CK, origem, usuário, banco, o comando
SQL ou a linha de log, a hora e o link do dashboard.

Para não lotar a caixa de entrada nem estourar o limite diário do provedor, o Reefed
manda no máximo `REEFED_EMAIL_MAX_PER_HOUR` (padrão 30) e-mails por hora. Passando disso,
nada sai por e-mail até a hora seguinte, e o próximo e-mail diz quantos ficaram de fora.

## Escolher o que chega

| Variável | Para quê |
|---|---|
| `REEFED_TELEGRAM_LEVEL`, `REEFED_SLACK_LEVEL`, `REEFED_EMAIL_LEVEL` | nível mínimo de cada canal |
| `REEFED_NOTIFY_GROUP` | só alertas de um grupo de regras. `reefed` deixa só os alertas do Reefed (banco, aplicação, firewall, FIM dos bancos e bloqueios) e corta os das regras do próprio Wazuh, como SSH e Windows. Vazio = todos |
| `REEFED_ALERT_DEDUP_SECONDS` | janela do agrupamento de repetidos (abaixo). Padrão 600 |
| `REEFED_DASHBOARD_URL` | link do dashboard nas mensagens (ex.: `https://10.0.0.5`) |

### Alertas repetidos

Durante um ataque, cada tentativa vira um alerta. Uma força bruta com 300 senhas daria 300
mensagens. Por isso, alertas iguais viram uma mensagem só por janela de
`REEFED_ALERT_DEDUP_SECONDS` (padrão 10 minutos). "Iguais" quer dizer a mesma regra, o
mesmo servidor e a mesma origem: o IP de origem, ou o arquivo no caso do FIM, ou o
usuário.

O primeiro alerta sai na hora. Os iguais que chegam dentro da janela são só contados, e a
próxima mensagem depois da janela começa com:

```
🔁 Desde a mensagem anterior, mais 37 alertas iguais ficaram sem mensagem
(mesma regra, servidor e origem). Todos estão no dashboard.
```

Se nenhum alerta igual chegar depois da janela, essa contagem não chega a ser enviada;
os alertas estão todos no dashboard e na API. Cada canal conta separado. Um ataque de
outro IP, ou outra regra, sai na hora. `REEFED_ALERT_DEDUP_SECONDS=0` manda uma mensagem
por alerta.

## Como a mensagem aparece

Telegram (do laboratório, força bruta no PostgreSQL):

```
🟠 Reefed · ALTO (nível 10)
Reefed: força bruta contra o banco a partir de 10.250.77.66 (5+ falhas de login em 2 min, último usuário app).

Regra: 110200
MITRE: T1110.001 Password Guessing (Credential Access)
Servidor: lab-postgres (002)
Origem: 10.250.77.66
Usuário: app
Banco: loja
Aplicação: [unknown]
Log:
2026-10-22 19:05:21.234 UTC [90] user=app db=loja client=10.250.77.66 app=[unknown] FATAL:  password authentication failed for user "app"
Quando: 22/10/2026 16:05:22 (-03:00)
Abrir o dashboard · alerta 1792695922.2841033
```

No Slack vem o mesmo conteúdo num cartão com a cor da severidade (vermelho, laranja,
amarelo ou azul) e os campos lado a lado. No e-mail, como descrito acima. Quando o
alerta tem um comando SQL, ele aparece no lugar da linha de log.

## Testar os canais

Mande um evento crítico pela API do Reefed. Ele vira a regra 110170 (nível 12) e chega em
todos os canais ligados com os níveis padrão, em poucos segundos:

```bash
curl -X POST -H "X-API-Key: $REEFED_API_KEY" -H "Content-Type: application/json" \
  -d '{"app": "teste", "event": "teste_de_alerta", "severity": "critical",
       "message": "teste dos canais de alerta", "srcip": "192.0.2.10"}' \
  http://localhost:8000/api/v1/events
```

A resposta é `{"accepted":1,"failed":0,"errors":[]}`. Para repetir o teste antes de 10
minutos, troque o `srcip` (`192.0.2.11`, `192.0.2.12`...): com o mesmo IP, o segundo
cai no agrupamento de repetidos. Com `REEFED_NOTIFY_GROUP` preenchido, o teste só chega
se o grupo for `reefed` ou `reefed_app`.

O `make lab` também testa os três canais, mas com um receptor falso: nada sai para o
Telegram, o Slack ou o e-mail de verdade.

## Quando não chega

1. `make status` deve listar o canal em "notificações". Se aparecer "nenhum canal
   configurado", confira os nomes das variáveis no `.env` e rode `make restart`.
2. Veja o log das integrações, onde os scripts registram cada falha:

   ```bash
   docker compose exec wazuh.manager tail -n 30 /var/ossec/logs/integrations.log
   ```

   | Mensagem | Causa |
   |---|---|
   | `custom-reefed-telegram: falha ao enviar: HTTP 401` ou `HTTP 404` | token do bot errado |
   | `custom-reefed-telegram: falha ao enviar: HTTP 400 ... chat not found` | chat_id errado, ou ninguém mandou mensagem para o bot, ou o bot não está no grupo |
   | `custom-reefed-telegram: falha ao enviar: HTTP 400 ... upgraded to a supergroup` | o grupo virou supergrupo e mudou de id; o id novo vem na mesma linha, em `migrate_to_chat_id` |
   | `custom-reefed-telegram: falha ao enviar: HTTP 403 ... bot was kicked` | o bot foi removido do grupo |
   | `custom-reefed-slack: falha ao enviar: HTTP 403`, `404` ou `410` | webhook apagado, canal arquivado ou URL errada |
   | `custom-reefed-email: falha ao enviar e-mail ... (535, ...)` | usuário ou senha do SMTP recusados (no Gmail, falta a senha de app) |
   | `custom-reefed-email: limite de 30 e-mails por hora atingido` | o limite de `REEFED_EMAIL_MAX_PER_HOUR` |
   | `falha ao enviar: ... Max retries exceeded`, `timed out` | o servidor do Reefed não alcança a internet ou a porta do SMTP |

3. O alerta precisa ter nível igual ou maior que o do canal. Os de nível 7 a 9 ficam só no
   dashboard com os valores padrão.
4. O servidor do Reefed precisa sair para a internet em HTTPS (`api.telegram.org`,
   `hooks.slack.com`) e na porta do SMTP. Algumas redes de faculdade e provedores
   bloqueiam as portas 25, 465 e 587.
