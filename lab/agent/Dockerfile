# Reefed lab - agente do Wazuh com o iptables de mentira e os ajustes do Reefed.
# Construído a partir da raiz do repositório (precisa do agents/linux/install-agent.sh):
#   build: { context: .., dockerfile: lab/agent/Dockerfile }
FROM wazuh/wazuh-agent:4.14.9

# iptables de mentira: o firewall-drop do Active Response registra o bloqueio
# num log em vez de mexer no firewall do kernel (que o container não tem).
COPY lab/agent/iptables /usr/sbin/iptables
RUN chmod 0755 /usr/sbin/iptables && mkdir -p /var/log/reefed-lab

# Os mesmos ajustes do Reefed de um servidor real, aplicados no start do container.
COPY agents/linux/install-agent.sh /opt/reefed/install-agent.sh
COPY lab/agent/10-reefed-lab.sh /entrypoint-scripts/10-reefed-lab.sh
RUN chmod 0755 /opt/reefed/install-agent.sh /entrypoint-scripts/10-reefed-lab.sh
