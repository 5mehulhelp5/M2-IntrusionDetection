<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Block;

use Magento\Backend\App\Action;
use Magento\Framework\View\Result\PageFactory;

class Index extends Action
{
    public const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::blocks';

    /** @var PageFactory */
    private $pageFactory;

    public function __construct(
        Action\Context $context,
        PageFactory $pageFactory
    ) {
        parent::__construct($context);
        $this->pageFactory = $pageFactory;
    }

    public function execute()
    {
        $resultPage = $this->pageFactory->create();
        $resultPage->setActiveMenu('Merlin_IntrusionDetection::blocks');
        $resultPage->getConfig()->getTitle()->prepend(__('Blocked IPs'));
        return $resultPage;
    }
}
