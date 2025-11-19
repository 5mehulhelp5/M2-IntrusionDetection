<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Diag;

use Magento\Framework\App\Action\Action;
use Magento\Framework\App\Action\Context;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\Controller\Result\JsonFactory;
use Merlin\IntrusionDetection\Model\Config;
use Merlin\IntrusionDetection\Model\Detector\Runner;

class Index extends Action
{
    public function __construct(
        Context $context,
        private readonly Config $config,
        private readonly Runner $runner,
        private readonly HttpRequest $request,
        private readonly JsonFactory $jsonFactory
    ) {
        parent::__construct($context);
    }

    public function execute()
    {
        $result = $this->jsonFactory->create();

        if (!$this->config->diagEnabled()) {
            return $result->setHttpResponseCode(403)->setData(['error' => 'Diagnostics disabled']);
        }

        $secret = (string)$this->request->getParam('secret', '');
        if ($secret === '' || $secret !== $this->config->diagSecret()) {
            return $result->setHttpResponseCode(403)->setData(['error' => 'Forbidden']);
        }

        // Optional: allow overriding basic headers via query for testing
        $host   = (string)$this->request->getParam('host', '');
        $ip     = (string)$this->request->getParam('ip', '');
        $xff    = (string)$this->request->getParam('xff', '');
        $accept = (string)$this->request->getParam('accept', '');
        $method = strtoupper((string)$this->request->getParam('method', 'GET'));
        $uri    = (string)$this->request->getParam('uri', $this->request->getRequestUri());

        $server = $this->request->getServer();
        $server['REQUEST_METHOD'] = $method;
        $server['REQUEST_URI']    = $uri;
        if ($host !== '')   { $server['HTTP_HOST'] = $host; }
        if ($ip !== '')     { $server['REMOTE_ADDR'] = $ip; }
        if ($xff !== '')    { $server['HTTP_X_FORWARDED_FOR'] = $xff; }
        if ($accept !== '') { $server['HTTP_ACCEPT'] = $accept; }

        $this->request->setServer($server);
        $this->request->setMethod($method);
        $this->request->setRequestUri($uri);

        $results = $this->runner->run($this->request);

        return $result->setData([
            'ok'      => true,
            'request' => [
                'method' => $method,
                'uri'    => $uri,
                'host'   => $server['HTTP_HOST'] ?? null,
                'ip'     => $server['REMOTE_ADDR'] ?? null,
                'xff'    => $server['HTTP_X_FORWARDED_FOR'] ?? null,
                'accept' => $server['HTTP_ACCEPT'] ?? null,
            ],
            'results' => $results,
        ]);
    }
}
