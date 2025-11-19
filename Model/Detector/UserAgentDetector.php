<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Detector;

use Merlin\IntrusionDetection\Api\DetectorInterface;
use Magento\Framework\App\RequestInterface;

class UserAgentDetector implements DetectorInterface {
    public function getName(): string { return 'UserAgentDetector'; }
    public function inspect(RequestInterface $request): array {
        $ua = strtolower((string)($request->getServer('HTTP_USER_AGENT') ?? ''));
        if ($ua === '') return [false, 'low', null];
        $signatures = ['sqlmap','nikto','acunetix','wpscan','nmap','dirbuster','masscan','curl/','python-requests','libwww-perl','fuzz'];
        foreach ($signatures as $s) { if (strpos($ua, $s) !== false) { return [true,'medium','Bad UA: '.$s]; } }
        return [false,'low',null];
    }
}
