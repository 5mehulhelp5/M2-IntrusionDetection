<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Merlin\IntrusionDetection\Api\DetectorInterface;
use Magento\Framework\App\RequestInterface;
use Merlin\IntrusionDetection\Api\BlockServiceInterface;

class IpBlockDetector implements DetectorInterface {
    private $svc;
    public function __construct(BlockServiceInterface $svc){ $this->svc=$svc; }
    public function getName(): string { return 'IpBlockDetector'; }
    public function inspect(RequestInterface $request): array {
        $ip = (string)($request->getServer('REMOTE_ADDR') ?? '');
        if ($ip && $this->svc->isBlocked($ip)) { return [true, 'critical', 'IP is on blocklist']; }
        return [false, 'low', null];
    }
}
