<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Helper;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\RequestInterface;

class Bypass
{
    /** @var string[] */
    private array $paths;

    public function __construct(
        private readonly ScopeConfigInterface $cfg
    ) {
        // Optional admin config: stores -> config -> merlin_id/general/excluded_paths (comma-separated)
        $raw = (string)$this->cfg->getValue('merlin_id/general/excluded_paths') ?: '';
        $cfgPaths = array_filter(array_map('trim', explode(',', $raw)));

        // Hard-coded safe defaults for 3DS challenge endpoints
        $defaults = [
            '/elavon/pi/challengeLoader',
            '/opayo/pi/challengeLoader',
            '/sagepay/pi/challengeLoader',
        ];

        $this->paths = array_values(array_unique(array_merge($defaults, $cfgPaths)));
    }

    public function isExcluded(RequestInterface $req): bool
    {
        $path = strtolower($req->getPathInfo());
        foreach ($this->paths as $p) {
            $p = strtolower($p);
            if ($p !== '' && str_starts_with($path, $p)) {
                return true;
            }
        }
        return false;
    }

    public function looksLike3ds(RequestInterface $req): bool
    {
        // 3DS v2 params commonly present on challenge/redirects
        $params = array_change_key_case($req->getParams(), CASE_LOWER);
        $threeDsParams = ['challenge-creq','creq','threedsservertransid','acstransid','messagetype','messageversion'];

        foreach ($threeDsParams as $k) {
            if (array_key_exists($k, $params)) {
                return true;
            }
        }

        $ref = (string)($req->getServer('HTTP_REFERER') ?? '');
        if ($ref !== '' && preg_match('#(?:^|//)[^/]*\.(sagepay\.com|opayo\.eu(?:\.elavon\.com)?|arcot\.com|cardinalcommerce\.com)(/|$)#i', $ref)) {
            return true;
        }

        return false;
    }
}
