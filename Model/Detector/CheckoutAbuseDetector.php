<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Magento\Framework\App\RequestInterface;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\App\CacheInterface;
use Merlin\IntrusionDetection\Model\Config;

class CheckoutAbuseDetector implements DetectorInterface
{
    public function __construct(
        private readonly Config $config,
        private readonly ResourceConnection $res,
        private readonly CacheInterface $cache
    ) {}

    public function getName(): string { return 'CheckoutAbuse'; }

    public function inspect(RequestInterface $request): array
    {
        if (!$this->config->chkEnabled()) {
            return [false, 'low', null];
        }

        // Only watch checkout-ish routes to reduce load
        $uri = (string)($request->getRequestUri() ?? $request->getPathInfo() ?? '');
        if (!preg_match('#/(checkout|rest/.+/carts/.+/payment-information|opayo|sagepay|payment)#i', $uri)) {
            return [false, 'low', null];
        }

        $now = time();
        $windowMin = $this->config->chkWindowMinutes();
        $since = date('Y-m-d H:i:s', $now - ($windowMin * 60));
        $conn  = $this->res->getConnection();
        $tbl   = $this->res->getTableName('merlin_payment_attempt');

        $ip = (string)$request->getServer('REMOTE_ADDR');

        // 1) IP failure velocity
        $ipFail = 0;
        if ($ip !== '') {
            $ipFail = (int)$conn->fetchOne(
                "SELECT COUNT(*) FROM {$tbl} WHERE status='failed' AND ip = :ip AND created_at >= :since",
                ['ip' => $ip, 'since' => $since]
            );
            if ($ipFail >= $this->config->chkIpFailThreshold()) {
                return [true, $this->config->chkSeverity(), "IP failures in {$windowMin}m: {$ipFail}"];
            }
        }

        // 2) BIN velocity (all statuses) – detect testing of specific BINs
        // We can’t read BIN from raw request; rely on logged attempts in window
        $binHot = (int)$conn->fetchOne(
            "SELECT MAX(cnt) FROM (SELECT bin6, COUNT(*) AS cnt FROM {$tbl} WHERE created_at >= :since AND bin6 IS NOT NULL GROUP BY bin6) t",
            ['since' => $since]
        );
        if ($binHot >= $this->config->chkBinThreshold()) {
            return [true, $this->config->chkSeverity(), "BIN velocity in {$windowMin}m: {$binHot} attempts on a single BIN"];
        }

        // 3) AVS/CVV failure spikes across site
        $avsBad = 0; $cvvBad = 0;
        if ($this->config->chkAvsFailThreshold() > 0) {
            $avsBad = (int)$conn->fetchOne(
                "SELECT COUNT(*) FROM {$tbl} WHERE created_at >= :since AND (LOWER(avs_result) IN ('n','no','nomatch','mismatch','fail'))",
                ['since' => $since]
            );
            if ($avsBad >= $this->config->chkAvsFailThreshold()) {
                return [true, $this->config->chkSeverity(), "AVS failures in {$windowMin}m: {$avsBad}"];
            }
        }
        if ($this->config->chkCvvFailThreshold() > 0) {
            $cvvBad = (int)$conn->fetchOne(
                "SELECT COUNT(*) FROM {$tbl} WHERE created_at >= :since AND (LOWER(cvv_result) IN ('n','no','nomatch','mismatch','fail'))",
                ['since' => $since]
            );
            if ($cvvBad >= $this->config->chkCvvFailThreshold()) {
                return [true, $this->config->chkSeverity(), "CVV failures in {$windowMin}m: {$cvvBad}"];
            }
        }

        return [false, 'low', null];
    }
}
