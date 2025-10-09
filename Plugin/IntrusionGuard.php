<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Plugin;

use Magento\Backend\Helper\Data as BackendHelper;
use Magento\Framework\App\FrontControllerInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\App\ResponseInterface;
use Magento\Framework\App\State;
use Merlin\IntrusionDetection\Api\BlockServiceInterface;
use Merlin\IntrusionDetection\Model\Config;
use Merlin\IntrusionDetection\Model\EventLogger;

class IntrusionGuard
{
    public function __construct(
        private readonly Config $config,
        private readonly EventLogger $logger,
        private readonly BlockServiceInterface $blockService,
        private readonly State $appState,
        private readonly BackendHelper $backendHelper,
        private readonly ResponseInterface $response,
        private readonly array $detectors = []
    ) {}

    public function aroundDispatch(
        FrontControllerInterface $subject,
        callable $proceed,
        RequestInterface $request
    ) {
        if (!$this->config->isEnabled()) {
            return $proceed($request);
        }

        // Never touch admin
        try { if ($this->appState->getAreaCode() === 'adminhtml') { return $proceed($request); } } catch (\Throwable $e) {}
        $adminFront = trim((string)$this->backendHelper->getAreaFrontName(), '/');
        $uri = '/' . ltrim((string)($request->getRequestUri() ?? $request->getPathInfo() ?? ''), '/');
        if ($adminFront !== '' && str_starts_with(ltrim($uri, '/'), $adminFront)) {
            return $proceed($request);
        }

        // --- proxy-aware client IPs ---
        $ips = $this->getClientIpCandidates($request); // ordered by trust/likelihood
        $path = (string)($request->getRequestUri() ?? $request->getPathInfo());
        $ua   = (string)($request->getServer('HTTP_USER_AGENT') ?? '');

        // Whitelist check (any candidate)
        $wl = $this->config->whitelist();
        if ($wl !== '') {
            $list = preg_split('/[\s,]+/', $wl, -1, PREG_SPLIT_NO_EMPTY) ?: [];
            foreach ($ips as $ip) {
                if (in_array($ip, $list, true)) {
                    return $proceed($request);
                }
            }
        }

// Logging
$this->logger->log('Debug', 'low', ($ips[0] ?? ''), $path, $ua,
    sprintf('Candidates=%s; WL=%s',
        implode(',', $ips),
        $this->config->whitelist()
    )
);

foreach ($ips as $ipCandidate) {
    $blocked = $this->blockService->isBlocked($ipCandidate);
    // log each candidate’s decision
    $this->logger->log('Debug', 'low', $ipCandidate, $path, $ua,
        'isBlocked=' . ($blocked ? '1' : '0')
    );
    if ($blocked) {
        $this->logger->log('IpBlockDetector', 'high', $ipCandidate, $path, $ua, 'Blocked IP');
        $this->response->setHttpResponseCode(403);
        if (method_exists($this->response, 'setBody')) {
            $this->response->setBody('Forbidden');
        } elseif (method_exists($this->response, 'setContent')) {
            $this->response->setContent('Forbidden');
        }
        return $this->response;
    }
}

        // Hard block (any candidate that is blocked)
        foreach ($ips as $ip) {
            if ($this->blockService->isBlocked($ip)) {
                // Log once using the first blocked match
                $this->logger->log('IpBlockDetector', 'high', $ip, $path, $ua, 'Blocked IP');
                $this->response->setHttpResponseCode(403);
                if (method_exists($this->response, 'setBody')) { $this->response->setBody('Forbidden'); }
                elseif (method_exists($this->response, 'setContent')) { $this->response->setContent('Forbidden'); }
                return $this->response;
            }
        }

        // Detectors (unchanged)
        $hits = [];
        foreach ($this->detectors as $detector) {
            try {
                $res  = $detector->inspect($request);
                $hit  = (bool)($res[0] ?? false);
                $sev  = (string)($res[1] ?? 'low');
                $det  = $res[2] ?? null;
                if ($hit) {
                    $this->logger->log($detector->getName(), $sev, $ips[0] ?? '', $path, $ua, is_string($det) ? $det : null);
                    $hits[] = [$detector->getName(), $sev];
                }
            } catch (\Throwable $e) {}
        }

        if ($hits && $this->config->mode() !== 'detect') {
            // auto-block on high/critical using the first candidate ip
            $ip = $ips[0] ?? '';
            foreach ($hits as [$detName, $sev]) {
                if (in_array($sev, ['high', 'critical'], true)) {
                    if ($ip !== '') { $this->blockService->block($ip, 'Auto block by ' . $detName, 60); }
                    break;
                }
            }
            $this->response->setHttpResponseCode(403);
            if (method_exists($this->response, 'setBody')) { $this->response->setBody('Forbidden'); }
            elseif (method_exists($this->response, 'setContent')) { $this->response->setContent('Forbidden'); }
            return $this->response;
        }

        return $proceed($request);
    }

    /**
     * Returns client IP candidates considering common proxy/CDN headers.
     * Order: CF-Connecting-IP, X-Real-IP, left-most X-Forwarded-For, REMOTE_ADDR.
     */
    private function getClientIpCandidates(RequestInterface $request): array
    {
        $candidates = [];

        $add = function (?string $ip) use (&$candidates) {
            $ip = trim((string)$ip);
            if ($ip === '') { return; }
            // strip ports if any (IPv4:port)
            $ip = preg_replace('/:\d+$/', '', $ip);
            // normalize IPv6 zone if present
            $ip = preg_replace('/%\w+$/', '', $ip);
            if (!in_array($ip, $candidates, true)) {
                $candidates[] = $ip;
            }
        };

        $add($request->getServer('HTTP_CF_CONNECTING_IP')); // Cloudflare
        $add($request->getServer('HTTP_X_REAL_IP'));        // NGINX/Proxy
        $xff = (string)($request->getServer('HTTP_X_FORWARDED_FOR') ?? '');
        if ($xff !== '') {
            foreach (explode(',', $xff) as $p) {
                $add($p);
            }
        }
        $add($request->getServer('REMOTE_ADDR'));

        return $candidates;
    }
}
