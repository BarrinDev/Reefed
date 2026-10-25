# Reefed - atalhos do dia a dia. Rode "make" sozinho para ver a lista.
#
# Variáveis:
#   NO_BUILD=1   não reconstrói as imagens locais (API do Reefed e laboratório)
#   S=serviço    escolhe o serviço no "make logs" (ex.: make logs S=wazuh.manager)

SHELL := /usr/bin/env bash
COMPOSE := docker compose
MANAGER := $(COMPOSE) exec -T wazuh.manager
BUILD := $(if $(NO_BUILD),,--build)
export NO_BUILD

.DEFAULT_GOAL := help
.PHONY: help setup up down restart status ps logs agents passwords backup deploy-rules test-rules test \
        dashboards api-test lab lab-up lab-attack lab-validate lab-down

help: ## mostra esta lista
	@echo "Reefed - comandos (rode na pasta do repositório):"
	@awk 'BEGIN {FS = ":.*## "} /^[a-z][a-z-]*:.*## / {printf "  \033[1;34mmake %-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ------------------------------------------------------------------ servidor
setup: ## primeira vez: cria o .env com senhas, os certificados e os usuários do indexer
	./setup.sh

up: ## sobe o Reefed (manager, indexer, dashboard e API) e espera ficar pronto
	$(COMPOSE) up -d $(BUILD)
	@scripts/status.sh

down: ## para o Reefed (alertas e configurações continuam nos volumes)
	$(COMPOSE) down

restart: ## reinicia o manager (relê o .env, o ossec.conf, as regras e as integrações)
	$(COMPOSE) up -d wazuh.manager
	$(COMPOSE) restart wazuh.manager

status: ## mostra se está tudo no ar, os agentes e os alertas das últimas 24 h
	@scripts/status.sh 60

ps: ## lista os containers do Reefed
	$(COMPOSE) ps

logs: ## acompanha os logs (todos, ou de um serviço: make logs S=wazuh.manager)
	$(COMPOSE) logs -f --tail=100 $(S)

agents: ## lista os agentes registrados e o estado de cada um
	@$(MANAGER) /var/ossec/bin/agent_control -l

passwords: ## aplica as senhas e chaves do .env depois de trocar alguma (docs/operacao.md)
	scripts/apply-passwords.sh

backup: ## backup do .env, dos certificados e de todos os volumes em backups/ (para o Reefed durante a cópia)
	scripts/backup.sh

# ------------------------------------------------------------------ regras e painéis
deploy-rules: ## aplica mudanças em regras, decoders, listas e integrações (sem recriar o container)
	$(MANAGER) bash /entrypoint-scripts/10-reefed.sh
	$(MANAGER) /var/ossec/bin/wazuh-control restart

test-rules: ## testa decoders e regras no wazuh-logtest, em todas as janelas de horário
	$(MANAGER) /var/ossec/framework/python/bin/python3 /reefed/tests/run_tests.py --all-windows

test: ## testes da API, das integrações de alerta e dos caminhos do FIM (pytest num container Python)
	docker run --rm -v "$(CURDIR):/reefed:ro" -w /reefed -e PYTHONDONTWRITEBYTECODE=1 python:3.12-slim \
	  sh -c "pip install -q --root-user-action=ignore -r api/requirements-dev.txt && python -m pytest -q -p no:cacheprovider api/tests tests/integrations tests/fim"

dashboards: ## importa ou atualiza os painéis do Reefed no dashboard
	$(COMPOSE) run --rm reefed-init python /reefed/init/reefed_init.py --overwrite

api-test: ## consulta a API do Reefed com a chave do .env (estado e últimos alertas)
	@$(COMPOSE) exec -T -e REEFED_URL=http://127.0.0.1:8000 reefed-api python - status < api/client/reefed_client.py
	@$(COMPOSE) exec -T -e REEFED_URL=http://127.0.0.1:8000 reefed-api python - alerts --since 24h --limit 5 < api/client/reefed_client.py

# ------------------------------------------------------------------ laboratório (lab/README.md)
lab: ## laboratório completo do zero: sobe bancos e agentes, ataca e valida
	scripts/lab.sh run

lab-up: ## sobe o laboratório (Reefed no modo laboratório, bancos, agentes, receptor falso)
	scripts/lab.sh up

lab-attack: ## roda o tráfego normal e os ataques simulados
	scripts/lab.sh attack

lab-validate: ## confere se os ataques viraram alertas, bloqueio e notificações
	scripts/lab.sh validate

lab-down: ## apaga o laboratório e volta o Reefed à configuração normal
	scripts/lab.sh down
