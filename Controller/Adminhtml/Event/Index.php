<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Event;

use Magento\Backend\App\Action;
use Magento\Framework\View\Result\PageFactory;

class Index extends Action {
    const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::events';
    private $pageFactory;
    public function __construct(Action\Context $context, PageFactory $pageFactory){ parent::__construct($context); $this->pageFactory=$pageFactory; }
    public function execute(){ $p=$this->pageFactory->create(); $p->setActiveMenu('Merlin_IntrusionDetection::events'); $p->getConfig()->getTitle()->prepend(__('Intrusion Events')); return $p; }
}
