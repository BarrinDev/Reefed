// Cliente Java da API do Reefed (Java 11 ou mais novo, sem dependências).
//
// Copie este arquivo para o seu projeto (com a linha package do pacote onde ele ficar):
//
//   Reefed reefed = new Reefed(System.getenv("REEFED_URL"), System.getenv("REEFED_API_KEY"));
//   reefed.notify("loja", "login_failed", Map.of("user", "ana", "srcip", request.getRemoteAddr()));
//   String json = reefed.alerts(Map.of("since", "1h", "min_level", 10));
//
// As consultas devolvem o JSON da resposta como texto; leia com a biblioteca de JSON
// do seu projeto (Jackson, Gson...). Referência da API: docs/api.md.

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;

public class Reefed {

    /** Resposta de erro da API (status HTTP e o corpo em JSON). */
    public static class ReefedException extends IOException {
        private static final long serialVersionUID = 1L;
        public final int status;
        public final String body;

        public ReefedException(int status, String body) {
            super("HTTP " + status + ": " + body);
            this.status = status;
            this.body = body;
        }
    }

    private final HttpClient http;
    private final String baseUrl;
    private final String apiKey;
    private final Duration timeout;

    public Reefed(String baseUrl, String apiKey) {
        this(baseUrl, apiKey, Duration.ofSeconds(10));
    }

    public Reefed(String baseUrl, String apiKey, Duration timeout) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalArgumentException("informe o endereço da API do Reefed (ex.: http://10.0.0.5:8000)");
        }
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.apiKey = apiKey;
        this.timeout = timeout;
        this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
    }

    // ------------------------------------------------------------------ consultas
    public String health() throws IOException, InterruptedException { return get("/health", null); }
    public String status() throws IOException, InterruptedException { return get("/api/v1/status", null); }

    /** Filtros: since, until, min_level, max_level, severity, rule_id, group, agent, srcip,
     *  user, mitre, q, all_rules, limit, offset. */
    public String alerts(Map<String, ?> filters) throws IOException, InterruptedException {
        return get("/api/v1/alerts", filters);
    }

    public String alert(String id) throws IOException, InterruptedException {
        return get("/api/v1/alerts/" + URLEncoder.encode(id, StandardCharsets.UTF_8), null);
    }

    public String summary(Map<String, ?> filters) throws IOException, InterruptedException {
        return get("/api/v1/alerts/summary", filters);
    }

    public String blocked(String since) throws IOException, InterruptedException {
        return get("/api/v1/blocked", Map.of("since", since));
    }

    public String agents(Map<String, ?> filters) throws IOException, InterruptedException {
        return get("/api/v1/agents", filters);
    }

    public String rules() throws IOException, InterruptedException { return get("/api/v1/rules", null); }

    // ------------------------------------------------------------------ eventos
    /** Envia um evento e espera a resposta. Campos: user, srcip, message, records, role,
     *  severity (low, medium, high, critical), request_id, extra (outro Map). */
    public String sendEvent(String app, String event, Map<String, ?> fields) throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(eventRequest(app, event, fields), HttpResponse.BodyHandlers.ofString());
        return check(response);
    }

    /** Envia o evento em segundo plano, sem esperar nem lançar exceção: um Reefed fora do
     *  ar não derruba o seu sistema. Problemas vão para o System.err. */
    public CompletableFuture<Void> notify(String app, String event, Map<String, ?> fields) {
        return http.sendAsync(eventRequest(app, event, fields), HttpResponse.BodyHandlers.ofString())
            .thenAccept(response -> {
                if (response.statusCode() != 202) {
                    System.err.println("[reefed] evento " + event + " recusado: HTTP " + response.statusCode() + " " + response.body());
                }
            })
            .exceptionally(error -> {
                System.err.println("[reefed] evento " + event + " não enviado: " + error);
                return null;
            });
    }

    private HttpRequest eventRequest(String app, String event, Map<String, ?> fields) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("app", app);
        body.put("event", event);
        if (fields != null) {
            fields.forEach((key, value) -> { if (value != null) body.put(key, value); });
        }
        return HttpRequest.newBuilder(URI.create(baseUrl + "/api/v1/events"))
            .timeout(timeout)
            .header("X-API-Key", apiKey)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(toJson(body)))
            .build();
    }

    // ------------------------------------------------------------------ HTTP e JSON
    private String get(String path, Map<String, ?> params) throws IOException, InterruptedException {
        StringJoiner query = new StringJoiner("&", "?", "").setEmptyValue("");
        if (params != null) {
            params.forEach((key, value) -> {
                if (value == null) return;
                Iterable<?> items = value instanceof Iterable ? (Iterable<?>) value : java.util.List.of(value);
                for (Object item : items) {
                    query.add(URLEncoder.encode(key, StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(String.valueOf(item), StandardCharsets.UTF_8));
                }
            });
        }
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path + query))
            .timeout(timeout)
            .header("X-API-Key", apiKey)
            .header("Accept", "application/json")
            .GET()
            .build();
        return check(http.send(request, HttpResponse.BodyHandlers.ofString()));
    }

    private static String check(HttpResponse<String> response) throws ReefedException {
        if (response.statusCode() >= 400) {
            throw new ReefedException(response.statusCode(), response.body());
        }
        return response.body();
    }

    /** JSON de texto, número, booleano, null e Map (para o campo extra). */
    static String toJson(Object value) {
        if (value == null) return "null";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map) {
            StringJoiner object = new StringJoiner(",", "{", "}");
            ((Map<?, ?>) value).forEach((key, item) -> object.add(toJson(String.valueOf(key)) + ":" + toJson(item)));
            return object.toString();
        }
        String text = value.toString();
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }
}
