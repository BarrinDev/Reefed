// Cliente JavaScript da API do Reefed (Node.js 18 ou mais novo, sem dependências).
//
// Copie este arquivo para o seu projeto:
//
//   import { ReefedClient } from "./reefed.mjs";
//
//   const reefed = new ReefedClient(process.env.REEFED_URL, process.env.REEFED_API_KEY);
//   reefed.notify("loja", "login_failed", { user: "ana", srcip: req.ip, message: "senha incorreta" });
//   const { items } = await reefed.alerts({ since: "1h", min_level: 10 });
//
// Use no servidor (Node.js), nunca no JavaScript da página: a chave ficaria visível.
// Com CommonJS (require), carregue com: const { ReefedClient } = await import("./reefed.mjs");
// Referência da API: docs/api.md.

export class ReefedError extends Error {
  constructor(status, detail) {
    super(`HTTP ${status}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    this.status = status;
    this.detail = detail;
  }
}

export class ReefedClient {
  constructor(baseUrl, apiKey, { timeoutMs = 10000 } = {}) {
    if (!baseUrl) throw new Error("informe o endereço da API do Reefed (ex.: http://10.0.0.5:8000)");
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  async request(method, path, { params, body } = {}) {
    const url = new URL(this.baseUrl + path);
    for (const [key, value] of Object.entries(params || {})) {
      if (value === undefined || value === null) continue;
      for (const item of Array.isArray(value) ? value : [value]) url.searchParams.append(key, String(item));
    }
    const headers = { "X-API-Key": this.apiKey, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }
    if (!response.ok) throw new ReefedError(response.status, data && data.detail !== undefined ? data.detail : data);
    return data;
  }

  health() { return this.request("GET", "/health"); }
  status() { return this.request("GET", "/api/v1/status"); }

  /** Alertas mais novos primeiro. Filtros: since, until, min_level, max_level, severity
   *  (baixo, medio, alto, critico), rule_id, group, agent, srcip, user, mitre, q,
   *  all_rules, limit, offset. rule_id e group aceitam lista. */
  alerts(filters = {}) { return this.request("GET", "/api/v1/alerts", { params: filters }); }
  alert(id) { return this.request("GET", `/api/v1/alerts/${encodeURIComponent(id)}`); }
  summary(filters = {}) { return this.request("GET", "/api/v1/alerts/summary", { params: filters }); }
  blocked(since = "24h") { return this.request("GET", "/api/v1/blocked", { params: { since } }); }
  agents(filters = {}) { return this.request("GET", "/api/v1/agents", { params: filters }); }
  rules() { return this.request("GET", "/api/v1/rules"); }

  /** Envia um evento e espera a resposta. Campos: user, srcip, message, records, role,
   *  severity (low, medium, high, critical), request_id, extra. */
  sendEvent(app, event, fields = {}) {
    const body = { app, event };
    for (const [key, value] of Object.entries(fields)) if (value !== undefined && value !== null) body[key] = value;
    return this.request("POST", "/api/v1/events", { body });
  }

  /** Lote de até 100 eventos ({ app, event, ...campos }). */
  sendEvents(events) { return this.request("POST", "/api/v1/events", { body: { events } }); }

  /** Envia o evento sem esperar nem falhar: um Reefed fora do ar não derruba o seu
   *  sistema. Problemas vão para o console. */
  notify(app, event, fields = {}) {
    this.sendEvent(app, event, fields).catch((error) => console.warn(`[reefed] evento ${event} não enviado: ${error.message}`));
  }
}
