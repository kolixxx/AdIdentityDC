<?php

namespace OPNsense\AdIdentity;

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;

/**
 * Ensure External firewall aliases exist for AdIdentity group/user names.
 */
class AliasHelper
{
    public static function normalizeName(string $name, ?string $forcePrefix = null): string
    {
        $cleaned = preg_replace('/[^A-Za-z0-9_]/', '_', trim($name));
        $cleaned = preg_replace('/_+/', '_', $cleaned);
        $cleaned = trim($cleaned, '_');
        if ($cleaned === '') {
            $cleaned = 'unknown';
        }
        if ($forcePrefix !== null && $forcePrefix !== '' && stripos($cleaned, $forcePrefix) !== 0) {
            $cleaned = $forcePrefix . $cleaned;
        }
        if (!preg_match('/^[A-Za-z]/', $cleaned)) {
            $cleaned = 'g_' . $cleaned;
        }
        return substr($cleaned, 0, 64);
    }

    /**
     * Create missing aliases as type=external (runtime content via pf tables).
     *
     * @param string[] $names
     * @return array{created:string[], existing:string[], errors:string[]}
     */
    public static function ensureExternalAliases(array $names): array
    {
        $created = [];
        $existing = [];
        $errors = [];

        $names = array_values(array_unique(array_filter(array_map('strval', $names))));
        if ($names === []) {
            return compact('created', 'existing', 'errors');
        }

        $cfg = Config::getInstance();
        $cfg->lock();
        try {
            $model = new Alias();
            $changed = false;

            foreach ($names as $name) {
                $found = false;
                foreach ($model->aliases->alias->iterateItems() as $alias) {
                    if ((string)$alias->name === $name) {
                        $found = true;
                        break;
                    }
                }
                if ($found) {
                    $existing[] = $name;
                    continue;
                }

                try {
                    $node = $model->aliases->alias->Add();
                    $node->name = $name;
                    $node->type = 'external';
                    $node->description = 'AdIdentity managed alias';
                    $node->enabled = '1';
                    $created[] = $name;
                    $changed = true;
                } catch (\Throwable $ex) {
                    $errors[] = $name . ': ' . $ex->getMessage();
                }
            }

            if ($changed) {
                $model->serializeToConfig();
                $cfg->save();
                // Make new External aliases visible to pf / filter subsystem.
                $backend = new \OPNsense\Core\Backend();
                $backend->configdRun('template reload OPNsense/Filter', true);
                $backend->configdRun('filter reload', true);
            }
        } finally {
            $cfg->unlock();
        }

        return compact('created', 'existing', 'errors');
    }
}
