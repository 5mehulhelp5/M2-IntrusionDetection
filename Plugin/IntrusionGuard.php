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

        // --- Always allow our own route + static/media assets to pass ---
        $route    = (string)$request->getRouteName();
        $front    = method_exists($request, 'getFrontName') ? (string)$request->getFrontName() : '';
        $pathInfo = '/' . ltrim((string)($request->getPathInfo() ?? ''), '/');
        $script   = (string)($request->getServer('SCRIPT_NAME') ?? ''); // e.g. /static.php

        if (
            $route === 'merlin_ids' ||
            $front === 'merlin-ids' ||
            preg_match('#^(?:/)?(static|media)/#i', ltrim($pathInfo, '/')) ||
            $pathInfo === '/static.php' ||
            str_ends_with($script, '/static.php')
        ) {
            return $proceed($request);
        }

        // Never touch admin
        try {
            if ($this->appState->getAreaCode() === 'adminhtml') {
                return $proceed($request);
            }
        } catch (\Throwable $e) {}

        $adminFront = trim((string)$this->backendHelper->getAreaFrontName(), '/');
        $uri = '/' . ltrim((string)($request->getRequestUri() ?? $request->getPathInfo() ?? ''), '/');
        if ($adminFront !== '' && str_starts_with(ltrim($uri, '/'), $adminFront)) {
            return $proceed($request);
        }

        // --- 3DS / challenge bypass ---
        // If this looks like a 3DS challenge (path or params or referrer), skip IDS
        if ($this->isExcludedPath($request) || $this->looksLike3ds($request)) {
            // use existing logger shape: (name, severity, ip, path, ua, message)
            $ua = (string)($request->getServer('HTTP_USER_AGENT') ?? '');
            $this->logger->log('IntrusionGuard', 'low', '', $pathInfo, $ua, 'Bypassing IDS for 3DS/challenge path');
            return $proceed($request);
        }

        // proxy-aware candidates
        $ips  = $this->getClientIpCandidates($request);
        $path = (string)($request->getRequestUri() ?? $request->getPathInfo());
        $ua   = (string)($request->getServer('HTTP_USER_AGENT') ?? '');

        // whitelist (simple list)
        $wl = $this->config->whitelist();
        if ($wl !== '') {
            $list = preg_split('/[\s,]+/', $wl, -1, PREG_SPLIT_NO_EMPTY) ?: [];
            foreach ($ips as $ip) {
                if (in_array($ip, $list, true)) {
                    return $proceed($request);
                }
            }
        }

        // debug candidates
        $this->logger->log(
            'Debug',
            'low',
            ($ips[0] ?? ''),
            $path,
            $ua,
            sprintf('Candidates=%s; WL=%s', implode(',', $ips), $wl)
        );

        // Hard block: return pre-rendered 403 HTML (no layout/blocks)
        foreach ($ips as $ipCandidate) {
            $blocked = $this->blockService->isBlocked($ipCandidate);
            $this->logger->log('Debug', 'low', $ipCandidate, $path, $ua, 'isBlocked=' . ($blocked ? '1' : '0'));
            if ($blocked) {
                $this->logger->log('IpBlockDetector', 'high', $ipCandidate, $path, $ua, 'Blocked IP');
                return $this->renderBlockedResponse();
            }
        }

        // detectors
        $hits = [];
        foreach ($this->detectors as $detector) {
            try {
                $res = $detector->inspect($request);
                $hit = (bool)($res[0] ?? false);
                $sev = (string)($res[1] ?? 'low');
                $det = $res[2] ?? null;
                if ($hit) {
                    $this->logger->log(
                        $detector->getName(),
                        $sev,
                        $ips[0] ?? '',
                        $path,
                        $ua,
                        is_string($det) ? $det : null
                    );
                    $hits[] = [$detector->getName(), $sev];
                }
            } catch (\Throwable $e) {}
        }

        if ($hits && $this->config->mode() !== 'detect') {
            $ip = $ips[0] ?? '';
            foreach ($hits as [$detName, $sev]) {
                if (in_array($sev, ['high', 'critical'], true)) {
                    if ($ip !== '') {
                        $this->blockService->block($ip, 'Auto block by ' . $detName, 60);
                    }
                    break;
                }
            }
            return $this->renderBlockedResponse();
        }

        return $proceed($request);
    }

    /**
     * Build a minimal branded HTML and write it to the Response with HTTP 403.
     * No layout/blocks used -> avoids rendering crashes from within the plugin.
     */
    private function renderBlockedResponse(): ResponseInterface
    {
        $title   = htmlspecialchars($this->config->blockedTitle() ?: 'Access blocked', ENT_QUOTES, 'UTF-8');
        // blockedMessage allows HTML on purpose
        $message = $this->config->blockedMessage();
        $email   = htmlspecialchars($this->config->contactEmail() ?: '', ENT_QUOTES, 'UTF-8');
        $phone   = htmlspecialchars($this->config->contactPhone() ?: '', ENT_QUOTES, 'UTF-8');

        $contactHtml = '';
        if ($email || $phone) {
            $contactHtml .= '<div style="opacity:.85"><strong>Need help?</strong><br/>';
            if ($email) { $contactHtml .= 'Email: <a href="mailto:' . $email . '">' . $email . '</a><br/>'; }
            if ($phone) { $contactHtml .= 'Phone: ' . $phone . '<br/>'; }
            $contactHtml .= '</div>';
        }

        $html = <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{$title}</title>
  <meta name="robots" content="noindex,nofollow"/>
</head>
<body>
  <div style="max-width:760px;margin:40px auto;padding:24px;border:1px solid #eee;border-radius:8px;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;">
    <h1 style="margin-top:0;">{$title}</h1>
    <div style="margin:12px 0 18px;">{$message}</div>
    {$contactHtml}
    <p style="margin-top:18px;color:#888;font-size:12px;">If you believe this is an error, please contact us.</p>
  </div>
</body>
</html>
HTML;

        // Headers FPC expects + no-cache
        $this->response->setHttpResponseCode(403);
        $this->response->setHeader('Content-Type', 'text/html; charset=UTF-8', true);
        $this->response->setHeader('X-Magento-Tags', 'merlin_ids_blocked', true);
        $this->response->setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0', true);
        $this->response->setHeader('Pragma', 'no-cache', true);
        $this->response->setHeader('Expires', 'Thu, 01 Jan 1970 00:00:00 GMT', true);

        if (method_exists($this->response, 'setBody')) {
            $this->response->setBody($html);
        } elseif (method_exists($this->response, 'setContent')) {
            $this->response->setContent($html);
        }

        return $this->response;
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
            $ip = preg_replace('/:\d+$/', '', $ip); // strip :port
            $ip = preg_replace('/%\w+$/', '', $ip); // strip IPv6 zone
            if (!in_array($ip, $candidates, true)) { $candidates[] = $ip; }
        };

        $add($request->getServer('HTTP_CF_CONNECTING_IP'));
        $add($request->getServer('HTTP_X_REAL_IP'));
        $xff = (string)($request->getServer('HTTP_X_FORWARDED_FOR') ?? '');
        if ($xff !== '') { foreach (explode(',', $xff) as $p) { $add($p); } }
        $add($request->getServer('REMOTE_ADDR'));

        return $candidates;
    }

    /**
     * Quick path-level exclusions for challenge endpoints.
     */
    private function isExcludedPath(RequestInterface $request): bool
    {
        $pathInfo = '/' . ltrim((string)($request->getPathInfo() ?? ''), '/');
        $exclusions = [
            '/elavon/pi/challengeLoader',
            '/opayo/pi/challengeLoader',
            '/sagepay/pi/challengeLoader',
        ];
        foreach ($exclusions as $p) {
            if (str_starts_with(strtolower($pathInfo), strtolower($p))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Heuristic that detects 3DS challenge requests by parameter names or referrer.
     */
    private function looksLike3ds(RequestInterface $request): bool
    {
        // check params commonly present for 3DS v2 challenges
        $params = array_change_key_case($request->getParams(), CASE_LOWER);
        $threeDsParams = ['challenge-creq','creq','threedsservertransid','acstransid','messagetype','messageversion'];

        foreach ($threeDsParams as $k) {
            if (array_key_exists(strtolower($k), $params)) {
                return true;
            }
        }

        // check referrer for known ACS / payment vendor hosts
        $ref = (string)($request->getServer('HTTP_REFERER') ?? '');
        if ($ref !== '' && preg_match('#(?:^|//)[^/]*\.(sagepay\.com|opayo\.eu|opayo\.co\.uk|elavon\.com|arcot\.com|cardinalcommerce\.com)(/|$)#i', $ref)) {
            return true;
        }

        return false;
    }
}
