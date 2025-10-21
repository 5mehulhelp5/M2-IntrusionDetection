<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Geo;

use GeoIp2\Database\Reader;
use Magento\Framework\App\Filesystem\DirectoryList;
use Psr\Log\LoggerInterface;

class Resolver
{
    private ?Reader $reader = null;
    private string $dbPath;

    public function __construct(
        private readonly \Merlin\IntrusionDetection\Model\Config $config,
        private readonly DirectoryList $dirs,
        private readonly LoggerInterface $log
    ) {
        $this->dbPath = $this->config->geoDbPath() ?: '';
    }

    private function getReader(): ?Reader
    {
        if ($this->reader !== null) return $this->reader;

        $path = $this->dbPath;
        if ($path === '') {
            // default: var/geo/GeoLite2-City.mmdb
            $path = $this->dirs->getPath(DirectoryList::VAR_DIR) . '/geo/GeoLite2-City.mmdb';
        }
        try {
            if (is_readable($path)) {
                $this->reader = new Reader($path);
                return $this->reader;
            }
        } catch (\Throwable $e) {
            $this->log->warning('[Merlin_IDS] Geo resolver init failed: ' . $e->getMessage());
        }
        return null;
    }

    /**
     * @return array{country?:string, iso?:string, lat?:float, lon?:float}  (empty on failure)
     */
    public function ipInfo(string $ip): array
    {
        $reader = $this->getReader();
        if (!$reader) return [];

        try {
            $rec = $reader->city($ip);
            return [
                'country' => (string)($rec->country->name ?? ''),
                'iso'     => (string)($rec->country->isoCode ?? ''),
                'lat'     => (float)($rec->location->latitude ?? 0.0),
                'lon'     => (float)($rec->location->longitude ?? 0.0),
            ];
        } catch (\Throwable $e) {
            // likely private IP or unmapped just return empty
            return [];
        }
    }
}
