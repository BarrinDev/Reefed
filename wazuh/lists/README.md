# Listas do Reefed (CDB)

O Wazuh compila estas listas quando o manager inicia. Depois de editar, rode
`make deploy-rules` para aplicar.

Formato: uma entrada por linha, `chave:descrição`. Não use comentários dentro do
arquivo: o Wazuh trataria a linha como uma entrada.

## trusted-db-clients

Endereços que podem conectar no banco sem gerar o alerta "acesso de IP
desconhecido" (regra 110210). Coloque aqui o servidor da aplicação, a máquina do
DBA, o servidor de backup...

- IP exato: `10.0.0.15:servidor da aplicação`
- Rede inteira: termine com ponto. `10.0.0.:rede da aplicação` vale para 10.0.0.0/24,
  `172.16.:docker` vale para 172.16.0.0/16.

O mesmo conteúdo é usado no `white_list` do Active Response, para que um IP
confiável nunca seja bloqueado.

## db-admins

Usuários do banco que fazem manutenção (DDL, criação de usuários, dumps). Quando
um usuário que NÃO está aqui roda DROP, TRUNCATE, GRANT, CREATE USER ou faz dump,
o alerta sobe de nível. Exemplo:

```
postgres:superusuário padrão do PostgreSQL
dba_joao:DBA da equipe
```
