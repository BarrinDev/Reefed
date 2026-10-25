-- Reefed lab - dados e usuários de exemplo do MariaDB.
CREATE DATABASE IF NOT EXISTS loja;
USE loja;
SET SESSION max_recursive_iterations = 100000;

CREATE TABLE clientes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(120) NOT NULL,
  email VARCHAR(160) NOT NULL,
  cpf CHAR(11) NOT NULL
);
CREATE TABLE pedidos (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cliente_id INT,
  total DECIMAL(10,2) NOT NULL,
  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO clientes (nome, email, cpf)
WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 500)
SELECT CONCAT('Cliente ', n), CONCAT('cliente', n, '@loja.local'), LPAD(n, 11, '0') FROM seq;
INSERT INTO pedidos (cliente_id, total)
WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 2000)
SELECT FLOOR(RAND()*499)+1, ROUND(RAND()*900+10, 2) FROM seq;

CREATE USER 'app'@'%' IDENTIFIED BY 'app-senha-forte';
GRANT SELECT, INSERT, UPDATE ON loja.* TO 'app'@'%';
CREATE USER 'relatorios'@'%' IDENTIFIED BY 'rel-senha';
GRANT SELECT ON loja.clientes TO 'relatorios'@'%';
FLUSH PRIVILEGES;
