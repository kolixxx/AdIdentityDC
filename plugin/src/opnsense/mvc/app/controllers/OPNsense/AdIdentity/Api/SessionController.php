<?php

namespace OPNsense\AdIdentity\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\AdIdentity\AdIdentity;
use OPNsense\AdIdentity\AliasHelper;

/**
 * Agent-facing session ingest API (pilot contract).
 *
 * POST /api/adidentity/session/upsert
 * POST /api/adidentity/session/remove
 * GET  /api/adidentity/session/list
 * GET  /api/adidentity/session/traffic
 */
class SessionController extends ApiControllerBase
{
    private function model(): AdIdentity
    {
        return new AdIdentity();
    }

    private function isEnabled(): bool
    {
        return (string)$this->model()->general->enabled === '1';
    }

    private function authorizeAgent(): bool
    {
        $expected = trim((string)$this->model()->general->shared_token);
        if ($expected === '') {
            return false;
        }

        $header = $this->request->getHeader('Authorization');
        if (!is_string($header) || stripos($header, 'Bearer ') !== 0) {
            return false;
        }

        $token = trim(substr($header, 7));
        if (!hash_equals($expected, $token)) {
            return false;
        }

        // Allowlist of agent/collector IPs. Empty means unrestricted (lab only).
        return $this->sourceIpAllowed();
    }

    /**
     * Restrict Bearer session API to configured source addresses.
     * Empty allowlist keeps the lab usable; production must list the DC
     * (or collector) so a stolen token cannot push rights from anywhere.
     */
    private function sourceIpAllowed(): bool
    {
        $raw = trim((string)$this->model()->general->allowed_source_ips);
        if ($raw === '') {
            return true;
        }

        $parts = preg_split('/[\r\n,;]+/', $raw) ?: [];
        $allowed = [];
        foreach ($parts as $p) {
            $p = trim($p);
            if ($p !== '' && filter_var($p, FILTER_VALIDATE_IP)) {
                $allowed[] = $p;
            }
        }
        if ($allowed === []) {
            // Misconfigured list with no valid IPs: fail closed for Bearer.
            return false;
        }

        $client = (string)$this->request->getClientAddress(true);
        if ($client === '') {
            $client = (string)$this->request->getClientAddress(false);
        }

        return in_array($client, $allowed, true);
    }

    /**
     * Agent uses Authorization: Bearer <shared_token>.
     * Stock ApiControllerBase only accepts Basic (OPNsense API key:secret) and
     * would reject Bearer before our actions run — so accept Bearer here first.
     * UI / API-key clients still go through the parent path.
     */
    public function beforeExecuteRoute($dispatcher)
    {
        $header = $this->request->getHeader('Authorization');
        if (is_string($header) && stripos($header, 'Bearer ') === 0) {
            if ($this->authorizeAgent()) {
                $this->logged_in_user = 'adidentity-agent';
                return true;
            }
            $this->response->setStatusCode(401, 'Unauthorized');
            $this->response->setContentType('application/json', 'UTF-8');
            $this->response->setContent(['status' => 'failed', 'message' => 'unauthorized']);
            $this->response->send();
            return false;
        }

        return parent::beforeExecuteRoute($dispatcher);
    }

    private function monitoredGroups(): array
    {
        $raw = (string)$this->model()->general->monitored_groups;
        $parts = preg_split('/[\r\n,;]+/', $raw) ?: [];
        $out = [];
        foreach ($parts as $p) {
            $p = trim($p);
            if ($p !== '') {
                $out[] = $p;
            }
        }
        return $out;
    }

    private function ensureAliasesForPayload(array $payload): array
    {
        $model = $this->model();
        if ((string)$model->general->auto_create_aliases !== '1') {
            return ['created' => [], 'existing' => [], 'errors' => [], 'skipped' => true];
        }

        $names = [];
        $errors = [];
        $allow = $this->monitoredGroups();
        $groups = $payload['groups'] ?? [];
        if (is_array($groups)) {
            foreach ($groups as $g) {
                $g = trim((string)$g);
                if ($g === '') {
                    continue;
                }
                if ($allow && !in_array($g, $allow, true)) {
                    continue;
                }
                // [D28 ascii-names]
                $refusal = AliasHelper::asciiAliasRefusal($g);
                if ($refusal !== null) {
                    $errors[] = $refusal;
                    continue;
                }
                $names[] = AliasHelper::normalizeName($g);
            }
        }

        if ((string)$model->general->enable_user_aliases === '1') {
            $prefix = (string)$model->general->user_alias_prefix;
            if ($prefix === '') {
                $prefix = 'u_';
            }
            $user = trim((string)($payload['user'] ?? ''));
            if ($user !== '') {
                // [D28 ascii-names]
                $refusal = AliasHelper::asciiAliasRefusal($user);
                if ($refusal !== null) {
                    $errors[] = $refusal;
                } else {
                    $names[] = AliasHelper::normalizeName($user, $prefix);
                }
            }
        }

        $result = AliasHelper::ensureExternalAliases($names);
        if ($errors !== []) {
            $result['errors'] = array_values(array_unique(array_merge($result['errors'], $errors)));
        }
        return $result;
    }

    private function runStore(string $action, array $payload): array
    {
        $backend = new Backend();
        $b64 = base64_encode(json_encode($payload));
        $raw = trim($backend->configdpRun('adidentity session-' . $action, [$b64]));
        if ($raw === '') {
            return ['status' => 'failed', 'message' => 'empty backend response'];
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return ['status' => 'failed', 'message' => 'invalid backend response', 'raw' => $raw];
        }
        return $decoded;
    }

    public function upsertAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        if (!$this->isEnabled()) {
            return ['status' => 'failed', 'message' => 'AdIdentity disabled'];
        }
        if (!$this->authorizeAgent()) {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['status' => 'failed', 'message' => 'unauthorized'];
        }

        $payload = $this->request->getJsonRawBody(true);
        if (!is_array($payload)) {
            return ['status' => 'failed', 'message' => 'invalid json'];
        }

        foreach (['user', 'domain', 'ip', 'groups', 'event', 'ts'] as $field) {
            if (!array_key_exists($field, $payload)) {
                return ['status' => 'failed', 'message' => "missing field: {$field}"];
            }
        }
        if (!is_array($payload['groups'])) {
            return ['status' => 'failed', 'message' => 'groups must be an array'];
        }

        // Only what the agent actually produces: a logon, and a refresh from
        // either Kerberos activity or the periodic re-push.
        $allowedEvents = ['login', 'refresh'];
        if (!in_array((string)$payload['event'], $allowedEvents, true)) {
            return ['status' => 'failed', 'message' => 'invalid event'];
        }

        $aliasResult = $this->ensureAliasesForPayload($payload);
        $storeResult = $this->runStore('upsert', $payload);
        $storeResult['aliases'] = $aliasResult;
        return $storeResult;
    }

    public function removeAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        if (!$this->isEnabled()) {
            return ['status' => 'failed', 'message' => 'AdIdentity disabled'];
        }
        if (!$this->authorizeAgent()) {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['status' => 'failed', 'message' => 'unauthorized'];
        }

        $payload = $this->request->getJsonRawBody(true);
        if (!is_array($payload)) {
            return ['status' => 'failed', 'message' => 'invalid json'];
        }

        foreach (['user', 'domain', 'ip', 'reason'] as $field) {
            if (!array_key_exists($field, $payload)) {
                return ['status' => 'failed', 'message' => "missing field: {$field}"];
            }
        }

        return $this->runStore('remove', $payload);
    }

    public function listAction()
    {
        if (!$this->isEnabled()) {
            return ['status' => 'failed', 'message' => 'AdIdentity disabled', 'sessions' => []];
        }

        $backend = new Backend();
        $raw = trim($backend->configdRun('adidentity session-list'));
        if ($raw === '') {
            return ['status' => 'ok', 'sessions' => [], 'message' => 'empty or backend unavailable'];
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return ['status' => 'failed', 'message' => 'invalid backend response', 'sessions' => []];
        }

        return $decoded;
    }

    /**
     * Bytes and open connections per session address, summed from the pf state
     * table here so the browser never downloads the whole table. Only inbound
     * states count: a forwarded connection also has an outbound state carrying
     * the same address, which would double it.
     */
    public function trafficAction()
    {
        if (!$this->isEnabled()) {
            return ['status' => 'failed', 'message' => 'AdIdentity disabled', 'items' => new \stdClass()];
        }

        $backend = new Backend();
        $sessions = json_decode(trim($backend->configdRun('adidentity session-list')), true);
        $items = [];
        foreach (($sessions['sessions'] ?? []) as $s) {
            $ip = trim((string)($s['ip'] ?? ''));
            if ($ip !== '') {
                $items[$ip] = ['bytes' => 0, 'states' => 0];
            }
        }
        if ($items === []) {
            return ['status' => 'ok', 'items' => new \stdClass()];
        }

        $top = json_decode($backend->configdRun('filter diag top'), true);
        if (!is_array($top) || !isset($top['details']) || !is_array($top['details'])) {
            return ['status' => 'failed', 'message' => 'state table unavailable', 'items' => new \stdClass()];
        }

        foreach ($top['details'] as $row) {
            if (($row['dir'] ?? '') !== 'in') {
                continue;
            }
            $addrs = array_unique([(string)($row['src_addr'] ?? ''), (string)($row['dst_addr'] ?? '')]);
            foreach ($addrs as $addr) {
                if (isset($items[$addr])) {
                    $items[$addr]['bytes'] += (int)($row['bytes'] ?? 0);
                    $items[$addr]['states']++;
                }
            }
        }

        return ['status' => 'ok', 'items' => $items];
    }
}
