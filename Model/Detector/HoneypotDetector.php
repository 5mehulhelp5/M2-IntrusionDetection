<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Merlin\IntrusionDetection\Api\DetectorInterface;
use Magento\Framework\App\RequestInterface;
use Merlin\IntrusionDetection\Model\Config;

class HoneypotDetector implements DetectorInterface {
    private $config;
    public function __construct(Config $config){ $this->config=$config; }
    public function getName(): string { return 'HoneypotDetector'; }
    public function inspect(RequestInterface $request): array {
        if (!$this->config->hpEnabled()) return [false,'low',null];
        $hp = rtrim($this->config->hpUrl(), '/');
        if ($hp === '') return [false,'low',null];
        $path = (string)($request->getRequestUri() ?? $request->getPathInfo() ?? '');
        if ($path === '') return [false,'low',null];
        $pathNorm = rtrim($path, '/');
        if ($pathNorm === $hp) { return [true, 'critical', 'Honeypot touched']; }
        return [false, 'low', null];
    }
}
