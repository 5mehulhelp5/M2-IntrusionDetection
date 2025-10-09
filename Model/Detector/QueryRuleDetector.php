<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Merlin\IntrusionDetection\Api\DetectorInterface;
use Magento\Framework\App\RequestInterface;

class QueryRuleDetector implements DetectorInterface {
    public function getName(): string { return 'QueryRuleDetector'; }
    public function inspect(RequestInterface $request): array {
        $params = $request->getParams() ?: [];
        $blob = strtolower(implode(' ', array_map('strval', $params)));
        if ($blob === '') return [false,'low',null];
        $bad = [' or 1=1',' union select ',' sleep(',' benchmark(','@@version',' load_file(',' into outfile ','<script',' onerror=',' onload=',' javascript:',' data:text/html','../etc/passwd','%3cscript','%27%20or%20%271%27%3D%271'];
        foreach ($bad as $needle) { if (strpos($blob, $needle) !== false) { return [true, 'high', 'Matched: ' . $needle]; } }
        return [false,'low',null];
    }
}
