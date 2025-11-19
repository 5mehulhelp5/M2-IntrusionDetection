<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Observer;

use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;

class PredispatchLogger implements ObserverInterface
{
    private \Merlin\IntrusionDetection\Model\EventLogFactory $eventFactory;
    private \Merlin\IntrusionDetection\Model\ResourceModel\EventLog $eventResource;
    private \Merlin\IntrusionDetection\Model\Config $config;

    public function __construct(
        \Merlin\IntrusionDetection\Model\EventLogFactory $eventFactory,
        \Merlin\IntrusionDetection\Model\ResourceModel\EventLog $eventResource,
        \Merlin\IntrusionDetection\Model\Config $config
    ) {
        $this->eventFactory  = $eventFactory;
        $this->eventResource = $eventResource;
        $this->config        = $config;
    }

    public function execute(Observer $observer): void
    {
        if (!$this->config->isEnabled()) {
            return;
        }

        $event = $observer->getEvent();

        // Preferred: request is passed directly on the event
        $request = $event->getData('request') ?? (method_exists($event, 'getRequest') ? $event->getRequest() : null);

        // Fallback: controller action may expose getRequest(), but not all interceptors do
        if (!$request) {
            $controller = $event->getControllerAction();
            if ($controller && method_exists($controller, 'getRequest')) {
                $request = $controller->getRequest();
            }
        }

        if (!$request) {
            // Nothing usable to log
            return;
        }

        $ip   = (string)($request->getServer('REMOTE_ADDR') ?? '');
        $path = (string)($request->getRequestUri() ?? $request->getPathInfo() ?? '');
        $ua   = (string)($request->getServer('HTTP_USER_AGENT') ?? '');

        $model = $this->eventFactory->create();
        $model->setData([
            'ip'         => $ip,
            'path'       => $path,
            'user_agent' => $ua,
            'detector'   => 'Predispatch',
            'severity'   => 'low',
            'details'    => null,
        ]);

        try {
            $this->eventResource->save($model);
        } catch (\Throwable $e) {
            // Intentionally swallow to avoid disrupting request flow
        }
    }
}
