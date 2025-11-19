<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Event;

use Magento\Backend\App\Action;
use Magento\Ui\Component\MassAction\Filter;
use Merlin\IntrusionDetection\Model\ResourceModel\EventLog\CollectionFactory;

class MassDelete extends Action
{
    public const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::events';

    /** @var Filter */
    private $filter;
    /** @var CollectionFactory */
    private $collectionFactory;

    public function __construct(
        Action\Context $context,
        Filter $filter,
        CollectionFactory $collectionFactory
    ) {
        parent::__construct($context);
        $this->filter = $filter;
        $this->collectionFactory = $collectionFactory;
    }

    public function execute()
    {
        $resultRedirect = $this->resultRedirectFactory->create();

        $collection = $this->filter->getCollection($this->collectionFactory->create());
        $count = 0;
        foreach ($collection as $item) {
            $item->delete();
            $count++;
        }

        if ($count) {
            $this->messageManager->addSuccessMessage(__('Deleted %1 event(s).', $count));
        } else {
            $this->messageManager->addNoticeMessage(__('No records selected.'));
        }

        return $resultRedirect->setPath('*/*/');
    }
}
