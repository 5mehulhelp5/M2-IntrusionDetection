<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Api;

use Magento\Framework\App\RequestInterface;

interface DetectorInterface {
    /** Return array: [bool $isHit, string $severity, ?string $details] */
    public function inspect(RequestInterface $request): array;
    public function getName(): string;
}
