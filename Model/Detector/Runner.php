<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Magento\Framework\App\RequestInterface;

class Runner
{
    /**
     * @param DetectorInterface[] $detectors
     */
    public function __construct(private readonly array $detectors = []) {}

    /**
     * Run all detectors against the given request.
     *
     * @return array<int, array{name:string,hit:bool,severity:string,details:?string}>
     */
    public function run(RequestInterface $request): array
    {
        $out = [];
        foreach ($this->detectors as $detector) {
            try {
                [$hit, $sev, $details] = $detector->inspect($request);
                $out[] = [
                    'name'     => $detector->getName(),
                    'hit'      => (bool)$hit,
                    'severity' => (string)$sev,
                    'details'  => $details !== null ? (string)$details : null,
                ];
            } catch (\Throwable $e) {
                $out[] = [
                    'name'     => (method_exists($detector, 'getName') ? $detector->getName() : get_class($detector)),
                    'hit'      => false,
                    'severity' => 'low',
                    'details'  => 'ERROR: ' . $e->getMessage(),
                ];
            }
        }
        return $out;
    }
}
