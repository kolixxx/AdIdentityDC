<?php

namespace OPNsense\AdIdentity;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Cron\Cron;

/**
 * Register the periodic expiry job.
 *
 * Session timeout is only evaluated when something calls the store, so without
 * a timer a logged-off user keeps matching group rules until the next push.
 */
class CronHelper
{
    private const ORIGIN = 'adidentity';
    private const COMMAND = 'adidentity expire';

    /**
     * Create the expiry cron job once; leave an admin-edited schedule alone.
     *
     * @return array{status:string, action?:string, message?:string}
     */
    public static function ensureExpireJob(string $minutes = '*/2'): array
    {
        try {
            $cfg = Config::getInstance();
            $cfg->lock();
            try {
                $model = new Cron();
                foreach ($model->jobs->job->iterateItems() as $job) {
                    if ((string)$job->origin === self::ORIGIN) {
                        return ['status' => 'ok', 'action' => 'exists'];
                    }
                }

                $job = $model->jobs->job->Add();
                $job->origin = self::ORIGIN;
                $job->enabled = '1';
                $job->minutes = $minutes;
                $job->hours = '*';
                $job->days = '*';
                $job->months = '*';
                $job->weekdays = '*';
                $job->who = 'root';
                $job->command = self::COMMAND;
                $job->description = 'AdIdentity: expire timed-out sessions';

                $messages = $model->performValidation();
                if ($messages->count() > 0) {
                    $errors = [];
                    foreach ($messages as $message) {
                        $errors[] = $message->getField() . ': ' . $message->getMessage();
                    }
                    return ['status' => 'failed', 'message' => implode('; ', $errors)];
                }

                $model->serializeToConfig();
                $cfg->save();
            } finally {
                $cfg->unlock();
            }

            $backend = new Backend();
            $backend->configdRun('template reload OPNsense/Cron', true);

            return ['status' => 'ok', 'action' => 'created'];
        } catch (\Throwable $ex) {
            // Never break Apply over this; the job can be added by hand.
            return ['status' => 'failed', 'message' => $ex->getMessage()];
        }
    }
}
