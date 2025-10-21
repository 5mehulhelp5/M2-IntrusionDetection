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
    private const PATH_GEO_ENABLED        = 'geo/enabled';
    private const PATH_GEO_DB_PATH        = 'geo/db_path';
    private const PATH_GEO_WIN_MIN        = 'geo/window_minutes';
    private const PATH_GEO_IP_WIN_MIN     = 'geo/ip_window_minutes';
    private const PATH_GEO_MIN_DIST       = 'geo/min_distance_km';
    private const PATH_GEO_CACHE_TTL      = 'geo/cache_ttl';
    private const PATH_GEO_SEVERITY       = 'geo/severity';
    private const PATH_GEO_IGNORE_CIDRS   = 'geo/ignore_cidrs';

    private const PATH_HEADERS_ENABLED                 = 'headers/enabled';
    private const PATH_HEADERS_SEVERITY                = 'headers/severity';
    private const PATH_HEADERS_ALLOWED_HOSTS           = 'headers/allowed_hosts';
    private const PATH_HEADERS_FORBID_IP_HOST          = 'headers/forbid_ip_host';
    private const PATH_HEADERS_TRUSTED_PROXY_CIDRS     = 'headers/trusted_proxy_cidrs';
    private const PATH_HEADERS_DISALLOW_PRIVATE_CLIENT = 'headers/disallow_private_client_ip';
    private const PATH_HEADERS_REQUIRE_ACCEPT          = 'headers/require_accept';
    private const PATH_HEADERS_REQUIRED_ACCEPT_TOKENS  = 'headers/required_accept_tokens';

    private const PATH_CHK_ENABLED         = 'checkout_abuse/enabled';
    private const PATH_CHK_SEVERITY        = 'checkout_abuse/severity';
    private const PATH_CHK_WINDOW_MIN      = 'checkout_abuse/window_minutes';
    private const PATH_CHK_IP_FAIL_TH      = 'checkout_abuse/ip_fail_threshold';
    private const PATH_CHK_BIN_TH          = 'checkout_abuse/bin_threshold';
    private const PATH_CHK_AVS_FAIL_TH     = 'checkout_abuse/avs_fail_threshold';
    private const PATH_CHK_CVV_FAIL_TH     = 'checkout_abuse/cvv_fail_threshold';

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
private function splitList(string $path): array
{
    $raw = (string)($this->get($path) ?? '');
    if ($raw === '') return [];
    $parts = preg_split('/[\r\n,]+/', $raw) ?: [];
    $out = [];
    foreach ($parts as $p) {
        $p = trim($p);
        if ($p !== '') $out[] = $p;
    }
    return $out;
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
     public function geoEnabled(): bool { return (bool)$this->get(self::PATH_GEO_ENABLED); }
     public function geoDbPath(): string { return (string)($this->get(self::PATH_GEO_DB_PATH) ?: ''); }
     public function geoWindowMinutes(): int { return max(1, (int)($this->get(self::PATH_GEO_WIN_MIN) ?: 15)); }
     public function geoIpWindowMinutes(): int { return max(1, (int)($this->get(self::PATH_GEO_IP_WIN_MIN) ?: 30)); }
     public function geoMinDistanceKm(): int { return max(0, (int)($this->get(self::PATH_GEO_MIN_DIST) ?: 500)); }
     public function geoCacheTtl(): int { return max(60, (int)($this->get(self::PATH_GEO_CACHE_TTL) ?: 3600)); }
     public function geoSeverity(): string { return (string)($this->get(self::PATH_GEO_SEVERITY) ?: 'high'); }
     public function geoIgnoreCidrs(): array {
    $raw = (string)($this->get(self::PATH_GEO_IGNORE_CIDRS) ?? '');
    if ($raw === '') return [];
    $parts = preg_split('/[\r\n,]+/', $raw) ?: [];
    $out = [];
    foreach ($parts as $p) {
        $p = trim($p);
        if ($p !== '') $out[] = $p;
    }
    return $out;
}

    public function headersEnabled(): bool
{
    return (bool)$this->get(self::PATH_HEADERS_ENABLED);
}

public function headersSeverity(): string
{
    return (string)($this->get(self::PATH_HEADERS_SEVERITY) ?: 'high');
}

public function headersAllowedHosts(): array
{
    $list = $this->splitList(self::PATH_HEADERS_ALLOWED_HOSTS);
    // normalize to lowercase and strip ports if present
    $norm = [];
    foreach ($list as $h) {
        $h = strtolower($h);
        // remove :port if present
        $h = preg_replace('/:\d+$/', '', $h);
        if ($h !== '') $norm[$h] = true;
    }
    return array_keys($norm);
}

public function headersForbidIpHost(): bool
{
    return (bool)$this->get(self::PATH_HEADERS_FORBID_IP_HOST);
}

public function headersTrustedProxyCidrs(): array
{
    return $this->splitList(self::PATH_HEADERS_TRUSTED_PROXY_CIDRS);
}

public function headersDisallowPrivateClientIp(): bool
{
    return (bool)$this->get(self::PATH_HEADERS_DISALLOW_PRIVATE_CLIENT);
}

public function headersRequireAccept(): bool
{
    return (bool)$this->get(self::PATH_HEADERS_REQUIRE_ACCEPT);
}

public function headersRequiredAcceptSubstrings(): array
{
    // keep in lowercase for case-insensitive contains checks
    return array_map('strtolower', $this->splitList(self::PATH_HEADERS_REQUIRED_ACCEPT_TOKENS));
}

    public function chkEnabled(): bool { return (bool)$this->get(self::PATH_CHK_ENABLED); }
    public function chkSeverity(): string { return (string)($this->get(self::PATH_CHK_SEVERITY) ?: 'high'); }
    public function chkWindowMinutes(): int { return max(1, (int)($this->get(self::PATH_CHK_WINDOW_MIN) ?: 15)); }
    public function chkIpFailThreshold(): int { return max(1, (int)($this->get(self::PATH_CHK_IP_FAIL_TH) ?: 8)); }
    public function chkBinThreshold(): int { return max(1, (int)($this->get(self::PATH_CHK_BIN_TH) ?: 12)); }
    public function chkAvsFailThreshold(): int { return max(0, (int)($this->get(self::PATH_CHK_AVS_FAIL_TH) ?: 15)); }
    public function chkCvvFailThreshold(): int { return max(0, (int)($this->get(self::PATH_CHK_CVV_FAIL_TH) ?: 10)); }
    
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
