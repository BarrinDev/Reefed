"""Clientes do Wazuh indexer (alertas) e da API do Wazuh (manager e agentes)."""

import asyncio
import time

import httpx


class UpstreamError(Exception):
    """Falha ao falar com o indexer ou com a API do Wazuh."""

    def __init__(self, service, message, status=None):
        super().__init__(f"{service}: {message}")
        self.service = service
        self.status = status


def _verify(enabled, ca_path):
    if not enabled:
        return False
    return ca_path or True


class IndexerClient:
    def __init__(self, settings, transport=None):
        self.index = settings.alerts_index
        self.client = httpx.AsyncClient(
            base_url=settings.indexer_url,
            auth=(settings.indexer_username, settings.indexer_password),
            verify=_verify(settings.indexer_verify_tls, settings.indexer_ca),
            timeout=settings.timeout,
            transport=transport,
        )

    async def search(self, body):
        try:
            response = await self.client.post(f"/{self.index}/_search", json=body)
        except httpx.HTTPError as exc:
            raise UpstreamError("indexer", str(exc) or exc.__class__.__name__) from exc
        if response.status_code == 404:
            # Ainda não existe índice de alertas (instalação nova)
            return {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}
        if response.status_code >= 400:
            raise UpstreamError("indexer", f"HTTP {response.status_code}: {response.text[:300]}",
                                response.status_code)
        return response.json()

    async def ping(self):
        # O usuário da API só lê índices (sem permissão de cluster): testa a leitura dos alertas
        try:
            response = await self.client.get(f"/{self.index}/_count")
            return response.status_code in (200, 404)
        except httpx.HTTPError:
            return False

    async def close(self):
        await self.client.aclose()


class WazuhClient:
    """API do Wazuh (porta 55000) com o token JWT guardado até perto de expirar."""

    TOKEN_TTL = 600  # o Wazuh emite tokens de 900 s

    def __init__(self, settings, transport=None):
        self.user = settings.wazuh_api_user
        self.password = settings.wazuh_api_password
        self.client = httpx.AsyncClient(
            base_url=settings.wazuh_api_url,
            verify=settings.wazuh_api_verify_tls,
            timeout=settings.timeout,
            transport=transport,
        )
        self._token = None
        self._token_time = 0.0
        self._lock = asyncio.Lock()

    async def _authenticate(self):
        try:
            response = await self.client.post("/security/user/authenticate", params={"raw": "true"},
                                              auth=(self.user, self.password))
        except httpx.HTTPError as exc:
            raise UpstreamError("wazuh", str(exc) or exc.__class__.__name__) from exc
        if response.status_code != 200:
            raise UpstreamError("wazuh", f"login recusado (HTTP {response.status_code})", response.status_code)
        self._token = response.text.strip()
        self._token_time = time.monotonic()

    async def _token_value(self, refresh=False):
        async with self._lock:
            if refresh or not self._token or time.monotonic() - self._token_time > self.TOKEN_TTL:
                await self._authenticate()
            return self._token

    async def request(self, method, path, **kwargs):
        for attempt in (1, 2):
            token = await self._token_value(refresh=attempt == 2)
            try:
                response = await self.client.request(method, path, headers={"Authorization": f"Bearer {token}"},
                                                     **kwargs)
            except httpx.HTTPError as exc:
                raise UpstreamError("wazuh", str(exc) or exc.__class__.__name__) from exc
            if response.status_code == 401 and attempt == 1:
                continue  # token expirou: entra de novo e repete
            if response.status_code >= 400:
                raise UpstreamError("wazuh", f"HTTP {response.status_code}: {response.text[:300]}",
                                    response.status_code)
            return response.json()
        raise UpstreamError("wazuh", "não autorizado", 401)

    async def get(self, path, **params):
        return await self.request("GET", path, params=params or None)

    async def ping(self):
        try:
            await self.get("/")
            return True
        except UpstreamError:
            return False

    async def close(self):
        await self.client.aclose()
