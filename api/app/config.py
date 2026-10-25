"""Configuração da API do Reefed, lida das variáveis de ambiente (docker-compose.yml)."""

import os
from dataclasses import dataclass, field


def _bool(value, default=False):
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "sim", "on")


def _list(value):
    return [item.strip() for item in (value or "").split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    api_key: str
    read_key: str = ""
    indexer_url: str = "https://wazuh.indexer:9200"
    indexer_username: str = "reefed_api"
    indexer_password: str = ""
    indexer_ca: str = ""
    indexer_verify_tls: bool = True
    alerts_index: str = "wazuh-alerts-*"
    wazuh_api_url: str = "https://wazuh.manager:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = ""
    wazuh_api_verify_tls: bool = False
    ar_timeout: int = 600
    cors_origins: list = field(default_factory=list)
    timeout: float = 15.0

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        api_key = env.get("REEFED_API_KEY", "")
        if len(api_key) < 16:
            raise RuntimeError("REEFED_API_KEY precisa ter pelo menos 16 caracteres (rode ./setup.sh)")
        read_key = env.get("REEFED_API_READ_KEY", "")
        if read_key and len(read_key) < 16:
            raise RuntimeError("REEFED_API_READ_KEY precisa ter pelo menos 16 caracteres")
        return cls(
            api_key=api_key,
            read_key=read_key,
            indexer_url=env.get("INDEXER_URL", cls.indexer_url).rstrip("/"),
            indexer_username=env.get("INDEXER_USERNAME", cls.indexer_username),
            indexer_password=env.get("INDEXER_PASSWORD", ""),
            indexer_ca=env.get("INDEXER_CA", ""),
            indexer_verify_tls=_bool(env.get("INDEXER_VERIFY_TLS"), True),
            alerts_index=env.get("REEFED_ALERTS_INDEX", cls.alerts_index),
            wazuh_api_url=env.get("WAZUH_API_URL", cls.wazuh_api_url).rstrip("/"),
            wazuh_api_user=env.get("WAZUH_API_USER", cls.wazuh_api_user),
            wazuh_api_password=env.get("WAZUH_API_PASSWORD", ""),
            wazuh_api_verify_tls=_bool(env.get("WAZUH_API_VERIFY_TLS"), False),
            ar_timeout=int(env.get("REEFED_AR_TIMEOUT", "600") or 600),
            cors_origins=_list(env.get("REEFED_CORS_ORIGINS")),
        )
