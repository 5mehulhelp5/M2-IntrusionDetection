<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Magento\Framework\App\RequestInterface;
use Merlin\IntrusionDetection\Model\Config;

class HeaderSanityDetector implements DetectorInterface
{
    public function __construct(private readonly Config $config) {}

    public function getName(): string
    {
        return 'HeaderSanity';
    }

    /**
     * @return array{0:bool,1:string,2?:string}
     */
    public function inspect(RequestInterface $request): array
    {
        if (!$this->config->headersEnabled()) {
            return [false, 'low', null];
        }

        $issues = [];

        // 1) Host sanity
        $host = (string)($request->getServer('HTTP_HOST') ?? '');
        if ($host === '') {
            $issues[] = 'Missing Host';
        } else {
            $allowed = $this->headersAllowedHostsNormalized();
            if ($allowed) {
                $hostLc = strtolower($host);
                // strip :port for comparison
                $hostLc = (string)preg_replace('/:\d+$/', '', $hostLc);
                if (!in_array($hostLc, $allowed, true)) {
                    $issues[] = 'Invalid Host: ' . $host;
                }
            }
            if ($this->config->headersForbidIpHost() && filter_var($host, FILTER_VALIDATE_IP)) {
                $issues[] = 'IP Host forbidden: ' . $host;
            }
        }

        // 2) X-Forwarded-For sanity (if present)
        $xff = trim((string)($request->getServer('HTTP_X_FORWARDED_FOR') ?? ''));
        if ($xff !== '') {
            $chain = array_values(array_filter(array_map('trim', explode(',', $xff)), static fn($v) => $v !== ''));
            if (!$this->validXffChain($chain)) {
                $issues[] = 'Malformed X-Forwarded-For chain';
            } else {
                $trustedCidrs = $this->config->headersTrustedProxyCidrs();
                if ($trustedCidrs) {
                    $lastHop = end($chain) ?: '';
                    if ($lastHop !== '' && !$this->ipInAnyCidr($lastHop, $trustedCidrs)) {
                        $issues[] = 'XFF last hop not trusted: ' . $lastHop;
                    }
                }
                if ($this->config->headersDisallowPrivateClientIp()) {
                    $client = $chain[0] ?? '';
                    if ($client !== '' && $this->isPrivateOrReserved($client)) {
                        $issues[] = 'XFF client is private/reserved: ' . $client;
                    }
                }
            }
        }

        // 3) Accept header sanity (for GET/HEAD)
        $method = strtoupper((string)($request->getServer('REQUEST_METHOD') ?? 'GET'));
        $accept = trim((string)($request->getServer('HTTP_ACCEPT') ?? ''));
        if (in_array($method, ['GET', 'HEAD'], true)) {
            if ($this->config->headersRequireAccept() && $accept === '') {
                $issues[] = 'Missing Accept';
            } else {
                $required = $this->config->headersRequiredAcceptSubstrings();
                if ($required && $accept !== '') {
                    $acceptLc = strtolower($accept);
                    $hasAny = false;
                    foreach ($required as $needle) {
                        if ($needle !== '' && strpos($acceptLc, $needle) !== false) {
                            $hasAny = true;
                            break;
                        }
                    }
                    if (!$hasAny) {
                        $issues[] = 'Accept missing expected tokens';
                    }
                }
            }
        }

        if ($issues) {
            return [true, $this->config->headersSeverity(), implode('; ', $issues)];
        }

        return [false, 'low', null];
    }

    /** Normalize allowed hosts to lowercase without :port */
    private function headersAllowedHostsNormalized(): array
    {
        $list = $this->config->headersAllowedHosts();
        if (!$list) {
            return [];
        }
        $norm = [];
        foreach ($list as $h) {
            $h = strtolower((string)$h);
            $h = (string)preg_replace('/:\d+$/', '', $h);
            if ($h !== '') {
                $norm[$h] = true;
            }
        }
        return array_keys($norm);
    }

    private function validXffChain(array $ips): bool
    {
        if (!$ips) {
            return false;
        }
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return false;
            }
        }
        return true;
    }

    private function ipInAnyCidr(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if ($this->ipInCidr($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }
        [$subnet, $maskStr] = $parts;
        $mask = (int)$maskStr;

        $isV6 = (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $isSubnetV6 = (bool)filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);

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

            if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
                return false;
            }
            if ($bits === 0) {
                return true;
            }

            $maskByte = chr(0xFF << (8 - $bits) & 0xFF);
            return ((ord($ipBin[$bytes]) & ord($maskByte)) === (ord($subnetBin[$bytes]) & ord($maskByte)));
        }

        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        if ($mask < 0 || $mask > 32) {
            return false;
        }

        $maskDec = $mask === 0 ? 0 : (~((1 << (32 - $mask)) - 1) & 0xFFFFFFFF);
        return (($ipLong & $maskDec) === ($subnetLong & $maskDec));
    }

    private function isPrivateOrReserved(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }
}
