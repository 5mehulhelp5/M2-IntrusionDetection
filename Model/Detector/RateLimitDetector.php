<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Merlin\IntrusionDetection\Api\DetectorInterface;
use Magento\Framework\App\CacheInterface;
use Magento\Framework\App\RequestInterface;
use Merlin\IntrusionDetection\Model\Config;

class RateLimitDetector implements DetectorInterface {
    private $cache; private $config;
    public function __construct(CacheInterface $cache, Config $config){ $this->cache=$cache; $this->config=$config; }
    public function getName(): string { return 'RateLimitDetector'; }
    public function inspect(RequestInterface $request): array {
        if (!$this->config->rlEnabled()) return [false,'low',null];
        $ip = (string)($request->getServer('REMOTE_ADDR') ?? '');
        if ($ip === '') return [false,'low',null];
        $win = max(5, $this->config->rlWindow());
        $max = max(1, $this->config->rlMax());
        $key = 'merlin_ids_rl_' . md5($ip);
        $now = time();
        $payload = $this->cache->load($key);
        $data = $payload ? json_decode($payload, true) : ['c'=>0,'t'=>$now];
        if (!is_array($data) || !isset($data['c'], $data['t'])) { $data = ['c'=>0,'t'=>$now]; }
        if (($now - (int)$data['t']) >= $win) { $data['c']=0; $data['t']=$now; }
        $data['c'] = (int)$data['c'] + 1;
        $this->cache->save(json_encode($data), $key, [], $win);
        if ($data['c'] > $max) { return [true,'high',sprintf('Rate limit exceeded: %d>%d in %ds', $data['c'], $max, $win)]; }
        return [false,'low',null];
    }
}
