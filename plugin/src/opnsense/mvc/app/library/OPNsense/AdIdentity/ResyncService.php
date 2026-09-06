<?php

namespace OPNsense\AdIdentity;

use OPNsense\Core\Backend;

/**
 * Pull full session snapshot from Windows Agent and replace local store.
 */
class ResyncService
{
    public function run(): array
    {
        $model = new AdIdentity();
        if ((string)$model->general->enabled !== '1') {
            return ['status' => 'failed', 'message' => 'AdIdentity disabled'];
        }

        $agentUrl = rtrim(trim((string)$model->general->agent_base_url), '/');
        $token = trim((string)$model->general->shared_token);
        if ($agentUrl === '' || $token === '') {
            return [
                'status' => 'failed',
                'message' => 'agent_base_url and shared_token are required for resync',
            ];
        }

        $insecure = (string)$model->general->agent_tls_insecure === '1';
        $fetch = $this->fetchAgentSessions($agentUrl, $token, $insecure);
        if (($fetch['status'] ?? '') !== 'ok') {
            return $fetch;
        }

        $sessions = $fetch['sessions'];

        // D8: an empty agent snapshot after service restart must not wipe live aliases.
        // Plugin expire (D5) already removes timed-out IPs; a cold agent is not authority
        // to clear everyone who is still logged in on the wire.
        if (count($sessions) === 0) {
            $local = $this->countLocalSessions();
            if ($local > 0) {
                return [
                    'status' => 'failed',
                    'message' => 'refusing empty agent resync: local store still has '
                        . $local
                        . ' session(s). Restarted agent has not rebuilt state yet; '
                        . 'wait for logons or restore agent sessions.json.',
                    'local_sessions' => $local,
                    'agent_sessions' => 0,
                ];
            }
        }

        $aliasStats = ['created' => [], 'existing' => [], 'errors' => []];
        if ((string)$model->general->auto_create_aliases === '1') {
            $collected = $this->collectAliasNames($model, $sessions);
            $aliasStats = AliasHelper::ensureExternalAliases($collected['names']);
            if ($collected['errors'] !== []) {
                $aliasStats['errors'] = array_values(array_unique(array_merge(
                    $aliasStats['errors'],
                    $collected['errors']
                )));
            }
        }

        $backend = new Backend();
        $payload = ['sessions' => $sessions];
        $b64 = base64_encode(json_encode($payload));
        $raw = trim($backend->configdpRun('adidentity session-replace', [$b64]));
        if ($raw === '') {
            return ['status' => 'failed', 'message' => 'empty backend response from replace-all'];
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return ['status' => 'failed', 'message' => 'invalid backend response', 'raw' => $raw];
        }

        $decoded['agent'] = [
            'url' => $agentUrl . '/api/v1/sessions',
            'fetched' => count($sessions),
        ];
        // D9: make a weak channel visible in the UI response instead of only in docs.
        if (stripos($agentUrl, 'https://') !== 0) {
            $decoded['agent']['transport_warning'] =
                'plain HTTP: the shared token is sent in clear text';
        } elseif ($insecure) {
            $decoded['agent']['transport_warning'] =
                'certificate validation disabled for the agent';
        }
        $decoded['aliases'] = $aliasStats;
        return $decoded;
    }

    private function fetchAgentSessions(string $agentUrl, string $token, bool $insecure = false): array
    {
        $url = $agentUrl . '/api/v1/sessions';
        if (!function_exists('curl_init')) {
            return ['status' => 'failed', 'message' => 'curl extension missing on OPNsense'];
        }

        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Authorization: Bearer ' . $token,
            ],
        ];

        // D9: verify the agent certificate by default. This request sends the shared
        // token, so an unverified TLS session lets anyone who can answer on the
        // address collect it. Skipping the check stays possible for a self-signed
        // lab agent, but only when the operator asks for it explicitly.
        if ($insecure) {
            $opts[CURLOPT_SSL_VERIFYPEER] = false;
            $opts[CURLOPT_SSL_VERIFYHOST] = false;
        }

        curl_setopt_array($ch, $opts);
        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $err = curl_error($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($errno !== 0) {
            $result = ['status' => 'failed', 'message' => 'agent fetch failed: ' . $err];
            // Without this hint a rejected certificate is indistinguishable from an
            // agent that is simply down, and the operator goes looking at the service.
            if (in_array($errno, [CURLE_SSL_PEER_CERTIFICATE, CURLE_SSL_CACERT, 60, 77], true)) {
                $result['tls_hint'] = 'The agent certificate was rejected. Install a '
                    . 'certificate the firewall trusts on the agent, or tick '
                    . '"Skip agent certificate validation" to accept a self-signed one.';
            }
            return $result;
        }
        if ($code !== 200) {
            return ['status' => 'failed', 'message' => "agent HTTP {$code}", 'body' => $body];
        }

        $decoded = json_decode((string)$body, true);
        if (!is_array($decoded) || !isset($decoded['sessions']) || !is_array($decoded['sessions'])) {
            return ['status' => 'failed', 'message' => 'agent response missing sessions[]'];
        }

        return ['status' => 'ok', 'sessions' => $decoded['sessions']];
    }

    private function countLocalSessions(): int
    {
        $backend = new Backend();
        $raw = trim($backend->configdRun('adidentity session-list'));
        if ($raw === '') {
            return 0;
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return 0;
        }
        if (isset($decoded['count'])) {
            return (int)$decoded['count'];
        }
        $sessions = $decoded['sessions'] ?? [];
        return is_array($sessions) ? count($sessions) : 0;
    }

    private function collectAliasNames(AdIdentity $model, array $sessions): array
    {
        $allow = [];
        $raw = (string)$model->general->monitored_groups;
        foreach (preg_split('/[\r\n,;]+/', $raw) ?: [] as $p) {
            $p = trim($p);
            if ($p !== '') {
                $allow[] = $p;
            }
        }

        $names = [];
        $errors = [];
        $enableUser = (string)$model->general->enable_user_aliases === '1';
        $prefix = (string)$model->general->user_alias_prefix;
        if ($prefix === '') {
            $prefix = 'u_';
        }

        foreach ($sessions as $s) {
            if (!is_array($s)) {
                continue;
            }
            $groups = $s['groups'] ?? [];
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
            if ($enableUser) {
                $user = trim((string)($s['user'] ?? ''));
                if ($user !== '') {
                    $refusal = AliasHelper::asciiAliasRefusal($user);
                    if ($refusal !== null) {
                        $errors[] = $refusal;
                    } else {
                        $names[] = AliasHelper::normalizeName($user, $prefix);
                    }
                }
            }
        }

        return [
            'names' => array_values(array_unique($names)),
            'errors' => array_values(array_unique($errors)),
        ];
    }
}
