-- Reefed lab - dados e usuários de exemplo do PostgreSQL.
CREATE DATABASE loja;
\connect loja

CREATE TABLE clientes (
  id serial PRIMARY KEY,
  nome text NOT NULL,
  email text NOT NULL,
  cpf text NOT NULL
);
CREATE TABLE pedidos (
  id serial PRIMARY KEY,
  cliente_id integer REFERENCES clientes(id),
  total numeric(10,2) NOT NULL,
  criado_em timestamptz DEFAULT now()
);

INSERT INTO clientes (nome, email, cpf)
SELECT 'Cliente ' || g, 'cliente' || g || '@loja.local', lpad(g::text, 11, '0')
FROM generate_series(1, 500) g;
INSERT INTO pedidos (cliente_id, total)
SELECT (random()*499 + 1)::int, (random()*900 + 10)::numeric(10,2)
FROM generate_series(1, 2000) g;

-- Aplicação (acesso normal) e um usuário de relatórios com menos permissão.
CREATE USER app WITH PASSWORD 'app-senha-forte';
GRANT CONNECT ON DATABASE loja TO app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app;

CREATE USER relatorios WITH PASSWORD 'rel-senha';
GRANT CONNECT ON DATABASE loja TO relatorios;
GRANT SELECT ON clientes TO relatorios;
