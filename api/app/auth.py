"""Autenticação por chave (cabeçalho X-API-Key).

REEFED_API_KEY       acesso completo: consulta e envio de eventos
REEFED_API_READ_KEY  só consulta (opcional): para painéis e relatórios
"""

import hmac

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="chave da API do Reefed")


def _matches(given, expected):
    return bool(expected) and hmac.compare_digest(given.encode(), expected.encode())


def _role(request: Request, key):
    settings = request.app.state.settings
    if not key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "envie a chave no cabeçalho X-API-Key",
                            headers={"WWW-Authenticate": "API-Key"})
    if _matches(key, settings.api_key):
        return "full"
    if _matches(key, settings.read_key):
        return "read"
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "chave inválida", headers={"WWW-Authenticate": "API-Key"})


def require_read(request: Request, key: str = Depends(api_key_header)):
    return _role(request, key)


def require_write(request: Request, key: str = Depends(api_key_header)):
    role = _role(request, key)
    if role != "full":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "esta chave só pode consultar")
    return role
