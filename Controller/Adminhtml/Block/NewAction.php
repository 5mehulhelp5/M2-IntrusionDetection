<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Block;

use Magento\Backend\App\Action;
use Magento\Framework\View\Result\PageFactory;

class NewAction extends Action
{
    public const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::blocks';

    public function __construct(
        Action\Context $context,
        private PageFactory $resultPageFactory
    ) {
        parent::__construct($context);
    }

    public function execute()
    {
        $resultPage = $this->resultPageFactory->create();
        $resultPage->setActiveMenu('Merlin_IntrusionDetection::blocks');
        $resultPage->getConfig()->getTitle()->prepend(__('New Blocked IP'));
        
        // DEBUG: Log what layout handles are being used
        $layout = $resultPage->getLayout();
        $handles = $layout->getUpdate()->getHandles();
        
        $writer = new \Zend_Log_Writer_Stream(BP . '/var/log/form_debug.log');
        $logger = new \Zend_Log();
        $logger->addWriter($writer);
        $logger->info('Layout handles: ' . print_r($handles, true));
        
        return $resultPage;
    }
}
