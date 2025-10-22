<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Diag;

use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\App\Request\HttpFactory;
use Laminas\Stdlib\Parameters;
use Magento\Framework\Controller\ResultFactory;
use Merlin\IntrusionDetection\Model\Detector\Runner;
use Magento\Framework\Data\Form\FormKey\Validator as FormKeyValidator;


class Index extends Action
{
    public const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::diagnostics';

    public function __construct(
        Context $context,
        private readonly Runner $runner,
        private readonly HttpFactory $httpFactory
        private readonly FormKeyValidator $formKeyValidator
    ) {
        parent::__construct($context);
    }

    public function execute()
    {
        // If POST, build a synthetic request and stash results in registry for the block/template
        if ($this->getRequest()->isPost()) {
            $p = $this->getRequest()->getPostValue();
        
            if (!$this->formKeyValidator->validate($this->getRequest())) {
                $this->messageManager->addErrorMessage(__('Invalid form key. Please refresh and try again.'));
                return $this->_redirect('*/*/index');
      }
            // Build synthetic server array
            $server = [
                'REQUEST_URI'          => (string)($p['uri'] ?? '/'),
                'REQUEST_METHOD'       => strtoupper((string)($p['method'] ?? 'GET')),
                'HTTP_HOST'            => (string)($p['host'] ?? 'www.theappliancedepot.co.uk'),
                'REMOTE_ADDR'          => (string)($p['ip'] ?? '203.0.113.10'),
                'HTTP_X_FORWARDED_FOR' => (string)($p['xff'] ?? ''),
                'HTTP_ACCEPT'          => (string)($p['accept'] ?? 'text/html,application/xhtml+xml'),
                'HTTP_USER_AGENT'      => (string)($p['ua'] ?? 'Mozilla/5.0 (Merlin IDS Admin)'),
            ];

            // Optionally pre-fill for scenario shortcuts
            $scenario = (string)($p['scenario'] ?? '');
            switch ($scenario) {
                case 'headers':
                    $server['HTTP_HOST'] = 'attacker.invalid';
                    $server['HTTP_ACCEPT'] = '';
                    break;
                case 'honeypot':
                    $server['REQUEST_URI'] = '/merlin/honeypot';
                    break;
                case 'path-sqli':
                    $server['REQUEST_URI'] = '/catalogsearch/result/?q=%27%20OR%201%3D1--';
                    break;
                case 'path-anomaly':
                    $server['REQUEST_URI'] = '/wp-admin/.env';
                    break;
                case 'useragent-bot':
                    $server['HTTP_USER_AGENT'] = 'curl/7.88 (bot test)';
                    $server['HTTP_ACCEPT'] = '';
                    break;
                case 'checkout-abuse':
                    $server['REQUEST_URI'] = '/rest/V1/carts/123/payment-information';
                    $server['HTTP_ACCEPT'] = 'application/json';
                    break;
                case 'rate-limit':
                case 'geo-jump':
                case '':
                default:
                    // leave as provided
                    break;
            }

            // Create a fresh Http request so we don't mutate the admin request object
            $synthetic = $this->httpFactory->create();
            $synthetic->setServer(new Parameters($server));
            $synthetic->setMethod($server['REQUEST_METHOD']);
            $synthetic->setRequestUri($server['REQUEST_URI']);

            $results = $this->runner->run($synthetic);

            // Hand off to block via registry (or session)
            $this->_objectManager->get(\Magento\Framework\Registry::class)
                ->register('merlin_ids_diag_results', [
                    'server'  => $server,
                    'results' => $results,
                ], true);
        }

        return $this->resultFactory->create(ResultFactory::TYPE_PAGE)
            ->setActiveMenu('Merlin_IntrusionDetection::diagnostics')
            ->getConfig()->getTitle()->prepend(__('Merlin IDS Diagnostics'));
    }
}
