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

/**
 * Front controller plugin that runs Merlin IDS detectors on every frontend request.
 *
 * Notes:
 * - Skips when module disabled.
 * - Skips adminhtml area / admin frontName routes.
 * - Skips whitelisted IPs (single IP or CIDR ranges) via Config::isWhitelisted().
 * - Runs configured detectors and logs hits.
 * - If mode != "detect" (i.e., "block") and any hit is high/critical, blocks IP and returns 403.
 * - Handles optional Honeypot URL if enabled in config.
 */
class IntrusionGuard
{
    /** @var Config */
    private $config;
    /** @var EventLogger */
    private $logger;
    /** @var BlockServiceInterface */
    private $blockService;
    /** @var State */
    private $appState;
    /** @var BackendHelper */
    private $backendHelper;
    /** @var ResponseInterface */
    private $response;
    /**
     * @var array Detectors; each must implement:
     *            - inspect(RequestInterface $request): array [bool $isHit, string $severity('low'..'critical'), string|null $details]
     *            - getName(): string
     */
    private $detectors;

    public function __construct(
        Config $config,
        EventLogger $logger,
        BlockServiceInterface $blockService,
        State $appState,
        BackendHelper $backendHelper,
        ResponseInterface $response,
        array $detectors = []
    ) {
        $this->config        = $config;
        $this->logger        = $logger;
        $this->blockService  = $blockService;
        $this->appState      = $appState;
        $this->backendHelper = $backendHelper;
        $this->response      = $response;
        $this->detectors     = $detectors;
    }

    /**
     * aroundDispatch: run before the FrontController processes the request.
     */
    public function aroundDispatch(
        FrontControllerInterface $subject,
        callable $proceed,
        RequestInterface $request
    ) {
        // 0) Feature switch
        if (!$this->config->isEnabled()) {
            return $proceed($request);
        }

        // 1) Skip adminhtml area (compile-safe; area may not be set yet)
        try {
            if ($this->appState->getAreaCode() === 'adminhtml') {
                return $proceed($request);
            }
        } catch (\Throwable $e) {
            // ignore; area not set at this point on some entry paths
        }

        // 2) Skip admin route by frontName (e.g., /admin_abcdef/...)
        $adminFrontName = trim((string) $this->backendHelper->getAreaFrontName(), '/');
        $uri = '/' . ltrim((string)($request->getRequestUri() ?: $request->getPathInfo() ?: ''), '/');
        if ($adminFrontName !== '' && strpos(ltrim($uri, '/'), $adminFrontName) === 0) {
            return $proceed($request);
        }

        // 3) Gather request context
        $ip   = (string)($request->getServer('REMOTE_ADDR') ?? '');
        $path = (string)($request->getRequestUri() ?? $request->getPathInfo() ?? '/');
        $ua   = (string)($request->getServer('HTTP_USER_AGENT') ?? '');

        // 4) Whitelist: short-circuit entirely if IP should be ignored
        if ($ip !== '' && $this->config->isWhitelisted($ip)) {
            return $proceed($request);
        }

        $hits = [];

        // 5) Honeypot (optional, quick win)
        if ($this->config->hpEnabled()) {
            $honeypot = rtrim($this->config->hpUrl() ?: '/_hp', '/');
            $reqPath  = rtrim(parse_url($path, PHP_URL_PATH) ?: '', '/');
            if ($honeypot !== '' && $reqPath === $honeypot) {
                $this->logger->log('HoneypotDetector', 'high', $ip, $path, $ua, 'Honeypot tripped');
                $hits[] = ['HoneypotDetector', 'high'];
            }
        }

        // 6) Run detectors (duck-typed; see class phpdoc)
        foreach ($this->detectors as $detector) {
            // support either inspect(RequestInterface) or inspect($request)
            try {
                $res = $detector->inspect($request);
            } catch (\ArgumentCountError $e) {
                $res = $detector->inspect();
            } catch (\Throwable $e) {
                // detector failure should never take down the request; log and continue
                $this->logger->log(
                    method_exists($detector, 'getName') ? $detector->getName() : get_class($detector),
                    'low',
                    $ip,
                    $path,
                    $ua,
                    'Detector error: ' . $e->getMessage()
                );
                continue;
            }

            $isHit = (bool)($res[0] ?? false);
            $sev   = (string)($res[1] ?? 'low');
            $det   = $res[2] ?? null;

            if ($isHit) {
                $detName = method_exists($detector, 'getName') ? (string)$detector->getName() : (new \ReflectionClass($detector))->getShortName();
                $this->logger->log($detName, $sev, $ip, $path, $ua, is_string($det) ? $det : null);
                $hits[] = [$detName, $sev];
            }
        }

        // 7) Enforcement: if not just "detect", block on high/critical and stop
        if ($hits && $this->config->mode() !== 'detect') {
            foreach ($hits as [$detName, $severity]) {
                if (in_array($severity, ['high', 'critical'], true)) {
                    if ($ip !== '') {
                        // default 60 minutes block; adjust if you have config-driven duration
                        $this->blockService->block($ip, 'Auto by ' . $detName, 60);
                    }
                    break;
                }
            }

            // Return a 403 immediately
            $this->response->setHttpResponseCode(403);

            // Write a small body safely (method varies by implementation)
            if (method_exists($this->response, 'setBody')) {
                $this->response->setBody('Forbidden');
            } elseif (method_exists($this->response, 'setContent')) {
                $this->response->setContent('Forbidden');
            }

            return $this->response;
        }

        // 8) No enforcement or no hits => proceed
        return $proceed($request);
    }
}
