<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Merlin\IntrusionDetection\Api\DetectorInterface;
use Magento\Framework\App\RequestInterface;

class PathAnomalyDetector implements DetectorInterface {
    public function getName(): string { return 'PathAnomalyDetector'; }
    public function inspect(RequestInterface $request): array {
        $path = strtolower((string)($request->getRequestUri() ?? $request->getPathInfo() ?? ''));
        if ($path === '') return [false,'low',null];
        if (strlen($path) > 2048) return [true,'high','Excessive path length'];
        $needles = ['..','%2e%2e','/./','//','%2f%2f','%00','.env','/.git','/wp-admin','/wp-login'];
        foreach ($needles as $n) { if (strpos($path, $n) !== false) { return [true,'medium','Path anomaly: ' . $n]; } }
        return [false,'low',null];
    }
}
