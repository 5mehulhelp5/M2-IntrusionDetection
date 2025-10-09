<?php
namespace Merlin\IntrusionDetection\Observer;

use Magento\Framework\Event\ObserverInterface;
use Magento\Framework\Event\Observer;
use Merlin\IntrusionDetection\Model\Config;
use Merlin\IntrusionDetection\Model\EventLogger;
use Merlin\IntrusionDetection\Model\BlockService;

class AdminLoginFailed implements ObserverInterface
{
    public function __construct(private Config $config, private EventLogger $logger, private BlockService $blockService) {}

    public function execute(Observer $observer)
    {
        if (!$this->config->bfEnabled()) return;
        $user = $observer->getEvent()->getUser();
        if ($user && !$observer->getEvent()->getPasswordMatched()) {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
            $this->logger->log('bruteforce_admin', 'high', $ip, '/depot-backend', $_SERVER['HTTP_USER_AGENT'] ?? '', 'Admin login failed');
        }
    }
}
