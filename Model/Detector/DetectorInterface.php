<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Magento\Framework\App\RequestInterface;

interface DetectorInterface
{
    /**
     * A short identifier for the detector (used in logs/UI).
     */
    public function getName(): string;

    /**
     * Inspect the request and return:
     *  - [0] bool   hit? (true if suspicious)
     *  - [1] string severity ('low'|'medium'|'high'|'critical')
     *  - [2] ?string optional details/message
     *
     * @return array{0:bool,1:string,2?:string}
     */
    public function inspect(RequestInterface $request): array;
}
