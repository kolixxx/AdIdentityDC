<?php

namespace OPNsense\AdIdentity;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->pick('OPNsense/AdIdentity/index');
    }
}
