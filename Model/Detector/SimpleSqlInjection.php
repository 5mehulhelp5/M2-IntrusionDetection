<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Merlin\IntrusionDetection\Api\DetectorInterface;
use Magento\Framework\App\RequestInterface;

class SimpleSqlInjection implements DetectorInterface {
    public function getName(): string { return 'SimpleSQLi'; }
    public function inspect(RequestInterface $request): array {
        $q = implode(' ', array_map('strval', $request->getParams() ?: []));
        $needles = [' union ', ' select ', ' sleep(', ' benchmark(', "' or '1'='1", '" or \"1\"=\"1\"'];
        $lq = strtolower($q);
        foreach ($needles as $n) {
            if (strpos($lq, strtolower($n)) !== false) { return [true, 'high', 'Matched pattern: ' . $n]; }
        }
        return [false, 'low', null];
    }
}
