<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Blocked;

use Magento\Framework\App\Action\Action;
use Magento\Framework\App\Action\Context;
use Magento\Framework\View\Result\PageFactory;
use Merlin\IntrusionDetection\Model\Config;

class Index extends Action
{
    public function __construct(
        Context $context,
        private readonly PageFactory $pageFactory,
        private readonly Config $config
    ) {
        parent::__construct($context);
    }

    public function execute()
    {
        $page = $this->pageFactory->create();
        $page->getConfig()->getTitle()->set($this->config->blockedTitle());
        $this->getResponse()->setHttpResponseCode(403);
        return $page;
    }
}
