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

        $fetch = $this->fetchAgentSessions($agentUrl, $token);
        if (($fetch['status'] ?? '') !== 'ok') {
            return $fetch;
        }

        $sessions = $fetch['sessions'];
        $aliasStats = ['created' => [], 'existing' => [], 'errors' => []];
        if ((string)$model->general->auto_create_aliases === '1') {
            $names = $this->collectAliasNames($model, $sessions);
            $aliasStats = AliasHelper::ensureExternalAliases($names);
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
        $decoded['aliases'] = $aliasStats;
        return $decoded;
    }

    private function fetchAgentSessions(string $agentUrl, string $token): array
    {
        $url = $agentUrl . '/api/v1/sessions';
        if (!function_exists('curl_init')) {
            return ['status' => 'failed', 'message' => 'curl extension missing on OPNsense'];
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Authorization: Bearer ' . $token,
            ],
            // Pilot: agent may use HTTP or self-signed HTTPS.
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $err = curl_error($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($errno !== 0) {
            return ['status' => 'failed', 'message' => 'agent fetch failed: ' . $err];
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
                    $names[] = AliasHelper::normalizeName($g);
                }
            }
            if ($enableUser) {
                $user = trim((string)($s['user'] ?? ''));
                if ($user !== '') {
                    $names[] = AliasHelper::normalizeName($user, $prefix);
                }
            }
        }

        return array_values(array_unique($names));
    }
}
