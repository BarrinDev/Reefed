<?php
// Cliente PHP da API do Reefed (PHP 7.4 ou mais novo, com a extensão curl).
//
// Copie este arquivo para o seu projeto:
//
//   require_once 'reefed.php';
//
//   $reefed = new ReefedClient(getenv('REEFED_URL'), getenv('REEFED_API_KEY'));
//   $reefed->notify('loja', 'login_failed', ['user' => 'ana', 'srcip' => $_SERVER['REMOTE_ADDR']]);
//   $graves = $reefed->alerts(['since' => '1h', 'min_level' => 10])['items'];
//
// Referência da API: docs/api.md.

class ReefedException extends RuntimeException
{
    /** @var mixed corpo da resposta de erro (o "detail" da API) */
    public $detail;

    public function __construct(int $status, $detail)
    {
        parent::__construct('HTTP ' . $status . ': ' . (is_string($detail) ? $detail : json_encode($detail, JSON_UNESCAPED_UNICODE)), $status);
        $this->detail = $detail;
    }
}

class ReefedClient
{
    private $baseUrl;
    private $apiKey;
    private $timeout;

    public function __construct(string $baseUrl, string $apiKey, int $timeout = 10)
    {
        if ($baseUrl === '') {
            throw new InvalidArgumentException('informe o endereço da API do Reefed (ex.: http://10.0.0.5:8000)');
        }
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->apiKey = $apiKey;
        $this->timeout = $timeout;
    }

    public function health(): array { return $this->request('GET', '/health'); }
    public function status(): array { return $this->request('GET', '/api/v1/status'); }

    /** Filtros: since, until, min_level, max_level, severity, rule_id, group, agent,
     *  srcip, user, mitre, q, all_rules, limit, offset. rule_id e group aceitam array. */
    public function alerts(array $filters = []): array { return $this->request('GET', '/api/v1/alerts', $filters); }
    public function alert(string $id): array { return $this->request('GET', '/api/v1/alerts/' . rawurlencode($id)); }
    public function summary(array $filters = []): array { return $this->request('GET', '/api/v1/alerts/summary', $filters); }
    public function blocked(string $since = '24h'): array { return $this->request('GET', '/api/v1/blocked', ['since' => $since]); }
    public function agents(array $filters = []): array { return $this->request('GET', '/api/v1/agents', $filters); }
    public function rules(): array { return $this->request('GET', '/api/v1/rules'); }

    /** Envia um evento e espera a resposta. Campos: user, srcip, message, records, role,
     *  severity (low, medium, high, critical), request_id, extra. */
    public function sendEvent(string $app, string $event, array $fields = []): array
    {
        $body = ['app' => $app, 'event' => $event] + array_filter($fields, function ($value) { return $value !== null; });
        return $this->request('POST', '/api/v1/events', [], $body);
    }

    /** Lote de até 100 eventos (arrays com app, event e os outros campos). */
    public function sendEvents(array $events): array
    {
        return $this->request('POST', '/api/v1/events', [], ['events' => $events]);
    }

    /** Envia o evento sem lançar exceção: um Reefed fora do ar não derruba o seu
     *  sistema. Problemas vão para o error_log do PHP. Use um timeout curto. */
    public function notify(string $app, string $event, array $fields = []): bool
    {
        try {
            $this->sendEvent($app, $event, $fields);
            return true;
        } catch (Throwable $error) {
            error_log('[reefed] evento ' . $event . ' não enviado: ' . $error->getMessage());
            return false;
        }
    }

    private function request(string $method, string $path, array $params = [], ?array $body = null): array
    {
        $query = [];
        foreach ($params as $key => $value) {
            if ($value === null) {
                continue;
            }
            foreach ((array) $value as $item) {
                $query[] = rawurlencode($key) . '=' . rawurlencode(is_bool($item) ? ($item ? 'true' : 'false') : (string) $item);
            }
        }
        $url = $this->baseUrl . $path . ($query ? '?' . implode('&', $query) : '');
        $headers = ['X-API-Key: ' . $this->apiKey, 'Accept: application/json'];
        $curl = curl_init($url);
        curl_setopt_array($curl, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_TIMEOUT => $this->timeout,
        ]);
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($body, JSON_UNESCAPED_UNICODE));
        }
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        $text = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $error = curl_error($curl);
        if ($text === false) {
            throw new ReefedException(0, 'Reefed não respondeu: ' . $error);
        }
        $data = json_decode($text, true);
        if ($status >= 400) {
            throw new ReefedException($status, is_array($data) && array_key_exists('detail', $data) ? $data['detail'] : $text);
        }
        return is_array($data) ? $data : [];
    }
}
