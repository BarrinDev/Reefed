"""Eventos que o sistema envia para o Reefed (login, exportação, troca de perfil...).

A API valida cada evento e monta o JSON que as regras reefed-0150-aplicacao_rules.xml
esperam. Só os campos abaixo passam: o cliente não consegue imitar um log de banco
nem um evento de outro módulo do Wazuh.
"""

import ipaddress
import json
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Discriminator, Field, Tag, field_validator

KNOWN_EVENTS = (
    "login_success", "login_failed", "access_denied", "permission_change", "user_created",
    "data_export", "bulk_delete", "sql_injection_blocked", "config_change",
)

MAX_BATCH = 100  # limite do POST /events da API do Wazuh


class AppEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$",
                     description="nome do sistema que enviou o evento")
    event: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$",
                       description="login_success, login_failed, access_denied, permission_change, user_created, "
                                   "data_export, bulk_delete, sql_injection_blocked, config_change ou outro nome")
    user: Optional[str] = Field(default=None, max_length=128, description="usuário do sistema envolvido")
    srcip: Optional[str] = Field(default=None, description="IP de quem fez a ação (IPv4 ou IPv6)")
    message: Optional[str] = Field(default=None, max_length=2000)
    records: Optional[int] = Field(default=None, ge=0, le=10**12,
                                   description="quantidade de registros (data_export, bulk_delete)")
    role: Optional[str] = Field(default=None, max_length=64, description="novo perfil (permission_change)")
    severity: Optional[Literal["low", "medium", "high", "critical"]] = Field(
        default=None, description="nível para eventos com outro nome (padrão: low)")
    request_id: Optional[str] = Field(default=None, max_length=128)
    extra: Optional[dict[str, Union[str, int, float, bool, None]]] = Field(
        default=None, description="outros dados simples (texto, número, booleano)")

    @field_validator("srcip")
    @classmethod
    def valid_ip(cls, value):
        if value is None:
            return value
        try:
            ip = ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValueError("srcip precisa ser um endereço IP") from exc
        # "::ffff:203.0.113.7" (Node.js, Java e PHP em servidor IPv6) vira 203.0.113.7,
        # o mesmo IP que aparece nos logs do banco e nas listas
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return str(ip)

    @field_validator("extra")
    @classmethod
    def small_extra(cls, value):
        if value is None:
            return value
        if len(value) > 20:
            raise ValueError("extra aceita no máximo 20 campos")
        for key, item in value.items():
            if not key.replace("_", "").isalnum() or len(key) > 40:
                raise ValueError(f"nome de campo inválido em extra: {key!r}")
            if isinstance(item, str) and len(item) > 500:
                raise ValueError(f"extra.{key} passa de 500 caracteres")
        return value

    def to_wazuh(self):
        """JSON que vai para o analysisd (uma linha)."""
        reefed = {"source": "app", "app": self.app, "event": self.event}
        for name in ("message", "records", "role", "severity", "request_id"):
            value = getattr(self, name)
            if value is not None:
                reefed[name] = value
        if self.extra:
            reefed["extra"] = self.extra
        payload = {"reefed": reefed}
        if self.srcip:
            payload["srcip"] = self.srcip
        if self.user:
            payload["dstuser"] = self.user
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[AppEvent] = Field(min_length=1, max_length=MAX_BATCH)


def _payload_kind(value):
    """Um evento ou um lote, pela chave "events": assim um erro de validação fala só
    do formato que o cliente quis mandar."""
    if isinstance(value, dict):
        return "lote" if "events" in value else "evento"
    return "lote" if isinstance(value, EventBatch) else "evento"


EventPayload = Annotated[
    Union[Annotated[EventBatch, Tag("lote")], Annotated[AppEvent, Tag("evento")]],
    Discriminator(_payload_kind),
]
