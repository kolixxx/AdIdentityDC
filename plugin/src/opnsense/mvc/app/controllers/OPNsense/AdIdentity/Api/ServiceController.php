<?php

namespace OPNsense\AdIdentity\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\AdIdentity\CronHelper;
use OPNsense\AdIdentity\ResyncService;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\AdIdentity\AdIdentity';
    protected static $internalServiceTemplate = 'OPNsense/AdIdentity';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'adidentity';

    protected function reconfigureForceRestart()
    {
        return 0;
    }

    /**
     * After apply/reconfigure: refresh templates/dirs, then pull snapshot from Agent.
     */
    public function reconfigureAction()
    {
        $result = parent::reconfigureAction();
        if (($result['status'] ?? '') === 'ok') {
            $cron = CronHelper::ensureExpireJob();
            if (($cron['status'] ?? '') !== 'ok') {
                $result['cron_warning'] = $cron['message'] ?? 'expire job not registered';
            }

            $resync = (new ResyncService())->run();
            $result['resync'] = $resync;
            // Keep reconfigure successful even if agent is temporarily unreachable.
            if (($resync['status'] ?? '') !== 'ok') {
                $result['resync_warning'] = $resync['message'] ?? 'resync failed';
            }
        }
        return $result;
    }

    /**
     * Manual full resync: Plugin <- Agent sessions snapshot.
     * POST /api/adidentity/service/resync
     */
    public function resyncAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        return (new ResyncService())->run();
    }
}
