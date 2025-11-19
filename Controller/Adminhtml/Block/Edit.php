<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Block;

use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\View\Result\PageFactory;
use Magento\Framework\Registry;

class Edit extends Action
{
    public const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::blocks';

    protected $resultPageFactory;
    protected $registry;

    public function __construct(
        Context $context,
        PageFactory $resultPageFactory,
        Registry $registry
    ) {
        parent::__construct($context);
        $this->resultPageFactory = $resultPageFactory;
        $this->registry = $registry;
    }

    public function execute()
    {
        $id = (int)$this->getRequest()->getParam('block_id');
        $this->registry->register('current_blocked_ip_id', $id);
        
        $resultPage = $this->resultPageFactory->create();
        $resultPage->setActiveMenu('Merlin_IntrusionDetection::blocks');
        $resultPage->getConfig()->getTitle()->prepend(__('Edit Blocked IP'));
        
        return $resultPage;
    }
}
