<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Magento\Framework\App\RequestInterface;
use Magento\Framework\App\CacheInterface;
use Magento\Framework\Session\SessionManagerInterface;
use Merlin\IntrusionDetection\Model\Config;
use Merlin\IntrusionDetection\Model\Geo\Resolver;

class GeoVelocityDetector implements DetectorInterface
{
    private const CACHE_PREFIX = 'merlin_ids_geo_';

    public function __construct(
        private readonly Resolver $geo,
        private readonly Config $config,
        private readonly CacheInterface $cache,
        private readonly SessionManagerInterface $session
    ) {}

    public function getName(): string
    {
        return 'GeoVelocity';
    }

    /**
     * @return array{0:bool,1:string,2?:string}
     */
    public function inspect(RequestInterface $request): array
    {
        if (!$this->config->geoEnabled()) {
            return [false, 'low', null];
        }

        $ip = $this->extractIp($request);
        if ($ip === '' || $this->shouldIgnoreIp($ip)) {
            return [false, 'low', null];
        }

        $now = time();
        $info = $this->geo->ipInfo($ip);
        $iso = strtoupper((string)($info['iso'] ?? ''));
        $lat = (float)($info['lat'] ?? 0.0);
        $lon = (float)($info['lon'] ?? 0.0);
        if ($iso === '') {
            return [false, 'low', null]; // no geo ? no signal
        }

        // --- Session-level check
        $sessKey = 'merlin_ids_geo_last';
        $sess = (array)($this->session->getData($sessKey) ?: []);
        $hit = $this->jumpDetected($sess, $iso, $lat, $lon, $now, (int)$this->config->geoWindowMinutes(), (int)$this->config->geoMinDistanceKm());
        if ($hit) {
            return [true, $this->config->geoSeverity(), sprintf('Session country jump: %s ? %s', $sess['iso'] ?? '??', $iso)];
        }
        // update session
        $this->session->setData($sessKey, ['iso'=>$iso,'ts'=>$now,'lat'=>$lat,'lon'=>$lon]);

        // --- IP-level check (shared devices)
        $cacheKey = self::CACHE_PREFIX . sha1($ip);
        $cached = $this->loadCache($cacheKey);
        $hitIp = $this->jumpDetected($cached, $iso, $lat, $lon, $now, (int)$this->config->geoIpWindowMinutes(), (int)$this->config->geoMinDistanceKm());
        // update cache
        $this->saveCache($cacheKey, ['iso'=>$iso,'ts'=>$now,'lat'=>$lat,'lon'=>$lon], (int)$this->config->geoCacheTtl());

        if ($hitIp) {
            return [true, $this->config->geoSeverity(), sprintf('IP country jump: %s ? %s', $cached['iso'] ?? '??', $iso)];
        }

        return [false, 'low', null];
    }

    private function shouldIgnoreIp(string $ip): bool
    {
        if ($this->isPrivate($ip)) return true;
        foreach ($this->config->geoIgnoreCidrs() as $cidr) {
            if ($this->config->isWhitelisted($ip)) return true; // reuse CIDR logic
        }
        return false;
    }

    private function extractIp(RequestInterface $request): string
    {
        $candidates = [
            (string)$request->getServer('HTTP_CF_CONNECTING_IP'),
            (string)$request->getServer('HTTP_X_REAL_IP'),
        ];
        $xff = (string)($request->getServer('HTTP_X_FORWARDED_FOR') ?? '');
        if ($xff !== '') {
            foreach (explode(',', $xff) as $p) {
                $candidates[] = trim($p);
            }
        }
        $candidates[] = (string)$request->getServer('REMOTE_ADDR');

        foreach ($candidates as $ip) {
            $ip = trim((string)$ip);
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        return '';
    }

    private function isPrivate(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            // ip is private/reserved
            return true;
        }
        return false;
    }

    /**
     * @param array{iso?:string,ts?:int,lat?:float,lon?:float}|null $prev
     */
    private function jumpDetected(?array $prev, string $iso, float $lat, float $lon, int $now, int $windowMin, int $minKm): bool
    {
        if (!$prev || empty($prev['iso']) || empty($prev['ts'])) {
            return false;
        }
        if (strtoupper((string)$prev['iso']) === $iso) {
            return false;
        }
        $elapsed = $now - (int)$prev['ts'];
        if ($elapsed > max(60, $windowMin) * 60) {
            return false; // outside time window
        }
        if ($minKm > 0 && $prev['lat'] && $prev['lon'] && $lat && $lon) {
            $dist = $this->haversine((float)$prev['lat'], (float)$prev['lon'], $lat, $lon);
            if ($dist < $minKm) {
                return false; // small border movement; ignore
            }
        }
        return true;
    }

    private function haversine(float $lat1, float $lon1, float $lat2, float $lon2): float
    {
        $R = 6371.0; // km
        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);
        $a = sin($dLat/2)**2 + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon/2)**2;
        return 2 * $R * asin(min(1, sqrt($a)));
    }

    private function loadCache(string $key): ?array
    {
        $raw = $this->cache->load($key);
        if (!$raw) return null;
        $data = @json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    private function saveCache(string $key, array $data, int $ttl): void
    {
        $this->cache->save(json_encode($data), $key, ['MERLIN_IDS_GEO'], max(60, $ttl));
    }
}
