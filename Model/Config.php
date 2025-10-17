<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Store\Model\ScopeInterface;

class Config
{
    /** Base config section path */
    private const BASE_PATH = 'merlin_intrusion/';

    /** Paths */
    private const PATH_ENABLED      = 'general/enabled';
    private const PATH_MODE         = 'general/mode';
    private const PATH_WHITELIST    = 'general/whitelist';        // textarea: IPs/CIDRs (comma/newline)
    private const PATH_EXCLUDED     = 'general/excluded_paths';    // textarea: URL path prefixes (comma/newline)

    private const PATH_RL_ENABLED   = 'ratelimit/enabled';
    private const PATH_RL_WINDOW    = 'ratelimit/window_seconds';
    private const PATH_RL_MAX       = 'ratelimit/max_requests';

    private const PATH_HP_ENABLED   = 'honeypot/enabled';
    private const PATH_HP_URL       = 'honeypot/url';

    public function __construct(
        private readonly ScopeConfigInterface $scopeConfig
    ) {}

    /* ------------------------------
     * Internal helpers
     * ------------------------------ */

    private function get(string $path): mixed
    {
        return $this->scopeConfig->getValue(
            self::BASE_PATH . $path,
            ScopeInterface::SCOPE_STORE
        );
    }

    /** Return trimmed, non-empty lines from a textarea config */
    private function getLines(string $path): array
    {
        $raw = (string)($this->get($path) ?? '');
        if ($raw === '') {
            return [];
        }
        $lines = preg_split('/\r\n|\r|\n/', $raw);
        if (!$lines) {
            return [];
        }
        $out = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '') {
                $out[] = $line;
            }
        }
        return $out;
    }

    /* ------------------------------
     * Public getters (existing)
     * ------------------------------ */

    public function isEnabled(): bool
    {
        return (bool)$this->get(self::PATH_ENABLED);
    }

    public function mode(): string
    {
        return (string)($this->get(self::PATH_MODE) ?: 'detect');
    }

    public function rlEnabled(): bool
    {
        return (bool)$this->get(self::PATH_RL_ENABLED);
    }

    public function rlWindow(): int
    {
        return (int)($this->get(self::PATH_RL_WINDOW) ?: 60);
    }

    public function rlMax(): int
    {
        return (int)($this->get(self::PATH_RL_MAX) ?: 120);
    }

    public function hpEnabled(): bool
    {
        return (bool)$this->get(self::PATH_HP_ENABLED);
    }

    public function hpUrl(): string
    {
        return (string)($this->get(self::PATH_HP_URL) ?: '/_hp');
    }

    public function blockedTitle(): string
    {
        return (string)($this->get('general/blocked_title') ?: __('Access blocked'));
    }

    public function blockedMessage(): string
    {
        return (string)($this->get('general/blocked_message') ?: __('Your request was blocked by our security system.'));
    }

    public function contactEmail(): string
    {
        return (string)($this->get('general/contact_email') ?: '');
    }

    public function contactPhone(): string
    {
        return (string)($this->get('general/contact_phone') ?: '');
    }

    /* ------------------------------
     * Whitelist / Ignore IPs
     * ------------------------------ */

    /**
     * Raw whitelist string (textarea) used by IntrusionGuard.
     * Returns the unprocessed value; entries are expected to be comma/newline separated.
     */
    public function whitelist(): string
    {
        return (string)($this->get(self::PATH_WHITELIST) ?? '');
    }

    /**
     * Raw whitelist entries (each entry is either a single IP or CIDR).
     * @return string[]
     */
    public function whitelistRaw(): array
    {
        // Accept both newline and comma separation
        $raw = (string)($this->get(self::PATH_WHITELIST) ?? '');
        if ($raw === '') {
            return [];
        }
        $parts = preg_split('/[\r\n,]+/', $raw) ?: [];
        $out = [];
        foreach ($parts as $p) {
            $p = trim($p);
            if ($p !== '') {
                $out[] = $p;
            }
        }
        return $out;
    }

    /**
     * Returns true if the given IP is explicitly whitelisted.
     * Supports IPv4/IPv6 and CIDR ranges (e.g., "192.0.2.0/24", "2001:db8::/32").
     */
    public function isWhitelisted(string $ip): bool
    {
        if ($ip === '') {
            return false;
        }

        $isV6 = (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $isV4 = (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        if (!$isV4 && !$isV6) {
            return false; // Not a valid IP
        }

        foreach ($this->whitelistRaw() as $entry) {
            // Exact IP match (fast path)
            if (strpos($entry, '/') === false) {
                if ($ip === $entry) {
                    return true;
                }
                continue;
            }

            // CIDR match
            if ($this->ipInCidr($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if $ip is inside the $cidr network.
     * Handles IPv4 and IPv6.
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }
        [$subnet, $maskStr] = $parts;
        if ($subnet === '' || $maskStr === '') {
            return false;
        }
        $mask = (int)$maskStr;

        // Detect IP versions
        $isV6 = (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $isSubnetV6 = (bool)filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);

        // IPv6 case
        if ($isV6 || $isSubnetV6) {
            $ipBin = @inet_pton($ip);
            $subnetBin = @inet_pton($subnet);
            if ($ipBin === false || $subnetBin === false) {
                return false;
            }
            if ($mask < 0 || $mask > 128) {
                return false;
            }

            $bytes = intdiv($mask, 8);
            $bits  = $mask % 8;

            // Compare full bytes
            if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
                return false;
            }

            if ($bits === 0) {
                return true;
            }

            // Compare remaining bits
            $maskByte = chr(0xFF << (8 - $bits) & 0xFF);
            return ((ord($ipBin[$bytes]) & ord($maskByte)) === (ord($subnetBin[$bytes]) & ord($maskByte)));
        }

        // IPv4 case
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        if ($mask < 0 || $mask > 32) {
            return false;
        }

        // Build mask and compare
        $maskDec = $mask === 0 ? 0 : (~((1 << (32 - $mask)) - 1) & 0xFFFFFFFF);
        return (($ipLong & $maskDec) === ($subnetLong & $maskDec));
    }

    /* ------------------------------
     * Excluded path prefixes (NEW)
     * ------------------------------ */

    /**
     * Returns normalized, de-duplicated list of path prefixes that should skip IDS.
     * - Split by commas or newlines
     * - Trim whitespace
     * - Ensure a leading '/'
     * - Lowercase
     * - Remove empties and duplicates
     *
     * @return string[] e.g. ['/elavon/pi/challengeLoader', '/amgdprcookie/cookie/allow']
     */
    public function excludedPaths(): array
    {
        $raw = (string)($this->get(self::PATH_EXCLUDED) ?? '');
        if ($raw === '') {
            return [];
        }

        $parts = preg_split('/[\r\n,]+/', $raw) ?: [];
        $norm  = [];

        foreach ($parts as $p) {
            $p = trim($p);
            if ($p === '') {
                continue;
            }
            // ensure leading slash and normalize to lowercase
            $p = '/' . ltrim($p, '/');
            $p = strtolower($p);

            $norm[$p] = true; // use assoc keys to dedupe
        }

        return array_keys($norm);
    }
}
