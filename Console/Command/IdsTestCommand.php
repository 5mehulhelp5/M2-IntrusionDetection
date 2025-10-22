<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Console\Command;

use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\Console\Cli;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Output\OutputInterface;
use Merlin\IntrusionDetection\Model\Detector\Runner;
use Laminas\Stdlib\Parameters;

/**
 * Run Merlin IDS detectors against a synthetic request.
 *
 * You can provide raw parameters (--uri, --host, --ip, --xff, --accept, --ua),
 * OR choose a --scenario that pre-fills sensible values to trigger a specific detector.
 */
class IdsTestCommand extends Command
{
    private const OPT_SCENARIO = 'scenario';
    private const OPT_URI      = 'uri';
    private const OPT_METHOD   = 'method';
    private const OPT_HOST     = 'host';
    private const OPT_IP       = 'ip';
    private const OPT_XFF      = 'xff';
    private const OPT_ACCEPT   = 'accept';
    private const OPT_UA       = 'ua';
    private const OPT_REPEAT   = 'repeat';
    private const OPT_SLEEP    = 'sleep';
    private const OPT_GEO_SEED = 'geo-seed-country';
    private const OPT_GEO_NOW  = 'geo-now-country';

    public function __construct(
        private readonly Runner $runner,
        private readonly HttpRequest $request
    ) { parent::__construct(); }

    protected function configure(): void
    {
        $this->setName('merlin:ids:test')
            ->setDescription('Run Merlin IDS detectors against a synthetic request')
            ->addOption(self::OPT_SCENARIO, null, InputOption::VALUE_OPTIONAL, 'Preset scenario (headers|ipblock|honeypot|path-sqli|path-anomaly|geo-jump|rate-limit|useragent-bot|checkout-abuse)')
            // raw overrides
            ->addOption(self::OPT_URI,    null, InputOption::VALUE_OPTIONAL, 'Request URI/path', '/')
            ->addOption(self::OPT_METHOD, null, InputOption::VALUE_OPTIONAL, 'HTTP method', 'GET')
            ->addOption(self::OPT_HOST,   null, InputOption::VALUE_OPTIONAL, 'Host header')
            ->addOption(self::OPT_IP,     null, InputOption::VALUE_OPTIONAL, 'REMOTE_ADDR')
            ->addOption(self::OPT_XFF,    null, InputOption::VALUE_OPTIONAL, 'X-Forwarded-For (comma-separated)')
            ->addOption(self::OPT_ACCEPT, null, InputOption::VALUE_OPTIONAL, 'Accept header')
            ->addOption(self::OPT_UA,     null, InputOption::VALUE_OPTIONAL, 'User-Agent header')
            // iteration helpers (for RateLimit, Geo velocity, etc.)
            ->addOption(self::OPT_REPEAT, null, InputOption::VALUE_OPTIONAL, 'Repeat N times (for rate-limit)', '1')
            ->addOption(self::OPT_SLEEP,  null, InputOption::VALUE_OPTIONAL, 'Sleep seconds between repeats (float)', '0')
            // geo helper tokens (if your GeoVelocityDetector supports header/country hints)
            ->addOption(self::OPT_GEO_SEED, null, InputOption::VALUE_OPTIONAL, 'Seed previous country code (e.g. GB)')
            ->addOption(self::OPT_GEO_NOW,  null, InputOption::VALUE_OPTIONAL, 'Current country code (e.g. US)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        // Start from defaults, then apply scenario, then apply explicit overrides
        $server = [
            'REQUEST_URI'    => '/',
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST'      => 'www.theappliancedepot.co.uk',
            'REMOTE_ADDR'    => '203.0.113.10',
            'HTTP_ACCEPT'    => 'text/html,application/xhtml+xml',
            'HTTP_USER_AGENT'=> 'Mozilla/5.0 (Testing Merlin IDS)',
        ];

        $scenario = (string)($input->getOption(self::OPT_SCENARIO) ?? '');
        switch ($scenario) {
            case 'headers':
                // Trip HeaderSanity: bad host + missing Accept
                $server['HTTP_HOST'] = 'attacker.invalid';
                $server['HTTP_ACCEPT'] = '';
                break;

            case 'ipblock':
                // Exercise IpBlockDetector (ensure this IP is blocked in your table first)
                $server['REMOTE_ADDR'] = '198.51.100.66';
                $server['REQUEST_URI'] = '/';
                break;

            case 'honeypot':
                // Hit your configured honeypot path (adjust if you changed it)
                $server['REQUEST_URI'] = '/merlin/honeypot';
                break;

            case 'path-sqli':
                // Classic SQLi probe in query string
                $server['REQUEST_URI'] = '/catalogsearch/result/?q=%27%20OR%201%3D1--';
                break;

            case 'path-anomaly':
                // Suspicious path fragments
                $server['REQUEST_URI'] = '/wp-admin/.env';
                break;

            case 'geo-jump':
                // Simulate country jump in a session/IP:
                // If your GeoVelocityDetector reads CF-IPCountry or similar, set both seed and now codes.
                $server['REMOTE_ADDR'] = '203.0.113.50';
                // "seed" previous country via a header your detector trusts for country resolution (if applicable)
                if ($seed = $input->getOption(self::OPT_GEO_SEED)) {
                    $server['HTTP_X_MERLIN_GEOSEED'] = (string)$seed;
                } else {
                    $server['HTTP_X_MERLIN_GEOSEED'] = 'GB';
                }
                $server['HTTP_CF_IPCOUNTRY'] = (string)($input->getOption(self::OPT_GEO_NOW) ?: 'US');
                $server['REQUEST_URI'] = '/customer/account/login';
                break;

            case 'rate-limit':
                // Same IP hammering a simple endpoint
                $server['REMOTE_ADDR'] = '203.0.113.77';
                $server['REQUEST_URI'] = '/customer/account/login';
                break;

            case 'useragent-bot':
                // Bot-like UA and no Accept
                $server['HTTP_USER_AGENT'] = 'curl/7.88 (bot test)';
                $server['HTTP_ACCEPT'] = '';
                $server['REQUEST_METHOD'] = 'GET';
                $server['REQUEST_URI'] = '/';
                break;

            case 'checkout-abuse':
                // Payment-ish route to exercise the CheckoutAbuseDetector lookbacks
                $server['REQUEST_URI'] = '/rest/V1/carts/123/payment-information';
                $server['HTTP_ACCEPT'] = 'application/json';
                break;

            case '':
                // no preset; use raw overrides
                break;

            default:
                $io->warning('Unknown scenario: ' . $scenario);
                break;
        }

        // Apply explicit overrides last
        $this->applyOverride($server, 'REQUEST_URI',    (string)$input->getOption(self::OPT_URI));
        $this->applyOverride($server, 'REQUEST_METHOD', strtoupper((string)$input->getOption(self::OPT_METHOD)));
        $this->applyOverride($server, 'HTTP_HOST',      (string)($input->getOption(self::OPT_HOST)   ?? ''));
        $this->applyOverride($server, 'REMOTE_ADDR',    (string)($input->getOption(self::OPT_IP)     ?? ''));
        $this->applyOverride($server, 'HTTP_X_FORWARDED_FOR', (string)($input->getOption(self::OPT_XFF) ?? ''));
        $this->applyOverride($server, 'HTTP_ACCEPT',    (string)($input->getOption(self::OPT_ACCEPT) ?? ''));
        $this->applyOverride($server, 'HTTP_USER_AGENT',(string)($input->getOption(self::OPT_UA)     ?? ''));

        $repeat = max(1, (int)$input->getOption(self::OPT_REPEAT));
        $sleep  = (float)$input->getOption(self::OPT_SLEEP);

        $rows = [];
        for ($i = 1; $i <= $repeat; $i++) {
		$serverParams = new Parameters($server);
		$this->request->setServer($serverParams);
		$this->request->setMethod($serverParams->get('REQUEST_METHOD', 'GET'));
		$this->request->setRequestUri($serverParams->get('REQUEST_URI', '/'));
            $results = $this->runner->run($this->request);
            foreach ($results as $r) {
                $rows[] = [
                    '#'.$i,
                    $r['name'],
                    $r['hit'] ? 'YES' : 'no',
                    $r['severity'],
                    $r['details'] ?? '',
                ];
            }

            if ($sleep > 0 && $i < $repeat) {
                usleep((int)round($sleep * 1_000_000));
            }
        }

        $io->title('Merlin IDS Detector Results');
        $io->text('Method: ' . $server['REQUEST_METHOD'] . '  URI: ' . $server['REQUEST_URI']);
        $io->text('Host: ' . ($server['HTTP_HOST'] ?? '(none)') . '  IP: ' . ($server['REMOTE_ADDR'] ?? '(none)'));
        if (!empty($server['HTTP_X_FORWARDED_FOR'])) {
            $io->text('XFF: ' . $server['HTTP_X_FORWARDED_FOR']);
        }
        $io->newLine();
        $io->table(['Iter', 'Detector', 'Hit', 'Severity', 'Details'], $rows);

        return Cli::RETURN_SUCCESS;
    }

    private function applyOverride(array &$server, string $key, string $value): void
    {
        if ($value !== '') {
            $server[$key] = $value;
        }
    }
}
